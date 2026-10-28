import argparse
import bisect
from collections import Counter
import itertools
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

try:
    import tomllib
except ImportError:
    tomllib = None


VERSION = "1.0.0"
SCHEMA = "commonrig.doctor.bundle/1"
ROOT = Path(__file__).resolve().parent.parent
MASK = "[withheld secret excerpt]"
SKIP = {"node_modules", ".git", "library", "temp", "bin", "obj", "__pycache__"}
VALUE = r'''(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;)"',}]+)'''
ASSIGN = re.compile(r"(?i)\b(?:pgpassword|password|passwd|pwd|token|api_key|apikey|secret)[\"']?\s*[:=]\s*(" + VALUE + ")")
BEARER = re.compile(r'''(?i)\bBearer\s+([^\s"');]{20,})''')
PREFIX = re.compile(r"\b(?:sk-|ghp_|xox)[A-Za-z0-9_+-]+")
LONG = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
CHAIN = re.compile(r"[A-Za-z0-9]+(?:[-_]{1,2}[A-Za-z0-9]+)+")
LETTERS = re.compile(r"[A-Za-z]+")
NOT_PATH_CHAR = re.compile(r"[^\w./-]")
PATH_START = re.compile(r"[A-Za-z]:[\\/]|//|/|~/|\.\.?/")
BOUNDARY = " \t\r\n\"'()"
PID = re.compile(r"(?i)(?:-Id\s+\d+|/PID\s+\d+|kill\s+-9\s+\d+|findstr\s+\d{4,})\b")
LOCAL = re.compile(r"(?i)localhost:\d+|127\.0\.0\.1|https?://192\.168\.\d+\.\d+")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
MARKER = re.compile(r"(?<![A-Za-z0-9_])(?:SUPERSEDED|DEPRECATED|RETIRED)(?![A-Za-z0-9_])")
HOME = re.compile(r'''(?:[A-Za-z]:[\\/]Users[\\/][^\s/\\"'<>]+|/(?:home|Users)/[^\s/\\"'<>]+)''')
RATES = (("tokens", 1, 30), ("dates", 1, 10), ("markers", 2, 10),
         ("glyphs", 0.5, 5), ("duplicates", 1, 10), ("secrets", 10, 30),
         ("home_paths", 0.5, 5), ("hooks", 5, 15))


def word_chain(run):
    # Linear form of [A-Za-z]+(?:[-_]{1,2}[A-Za-z0-9]{1,6})*(?:[-_]{1,2}[A-Za-z]+)+, which backtracks quadratically on
    # long runs: letters first, a letters-only tail, segments of at most six between
    if not CHAIN.fullmatch(run):
        return False
    segments = re.split(r"[-_]{1,2}", run)
    if not LETTERS.fullmatch(segments[0]):
        return False
    last = len(segments) - 1
    while last >= 1 and LETTERS.fullmatch(segments[last]):
        last -= 1
    return last < len(segments) - 1 and all(len(segment) <= 6 for segment in segments[1:last + 1])


def ahead(find):
    # First index at or after a start that only moves forward, cached while still ahead, so a whole scan stays O(n)
    found = [-1]

    def lookup(start):
        if found[0] < start:
            index = find(start)
            found[0] = math.inf if index < 0 else index
        return found[0]
    return lookup


def secret_spans(text):
    spans = [match.span(1) for pattern in (ASSIGN, BEARER) for match in pattern.finditer(text)]
    spans.extend(match.span() for match in PREFIX.finditer(text))
    for command in re.finditer(r"(?i)\bmysql\b[^;\r\n]*", text):
        for match in re.finditer(r"(?:^|\s)-p(" + VALUE + ")", command.group()):
            spans.append((command.start() + match.start(1), command.start() + match.end(1)))
    # Long runs skip any span the patterns above found: sorted starts plus a running max end answer that by bisection
    prior = sorted(spans)
    starts, max_ends = [start for start, _ in prior], list(itertools.accumulate((end for _, end in prior), max))

    def touches(start, end):
        count = bisect.bisect_left(starts, end)
        return count > 0 and max_ends[count - 1] > start
    # Each run's token reaches back to the last boundary character; that start only moves forward, so the token
    # tests are index lookups rather than a rescan of the token per run
    backslash, mcp = ahead(lambda at: text.find("\\", at)), ahead(lambda at: text.find("mcp__", at))
    slash, double = ahead(lambda at: text.find("/", at)), ahead(lambda at: text.find("//", at))
    bad = ahead(lambda at: next((m.start() for m in [NOT_PATH_CHAR.search(text, at)] if m), -1))
    scan = token_start = 0
    for match in LONG.finditer(text):
        begin, end = match.span()
        if touches(begin, end):
            continue
        for scan in range(scan, begin):
            if text[scan] in BOUNDARY:
                token_start = scan + 1
        scan = max(scan, begin)
        run = match.group()
        # [\w.-]+/(?:[\w.-]+/)*[\w.-]+ over the whole run, made of word chars, dots, dashes and single slashes, none at either end
        chain = (bad(token_start) >= end and slash(token_start) < end and double(token_start) + 1 >= end
                 and text[token_start] != "/" and text[end - 1] != "/")
        is_path = PATH_START.match(text, token_start) or backslash(token_start) < end or chain
        is_name = (mcp(token_start) + 5 <= end or not re.search(r"\d", run) or not re.search(r"[A-Za-z]", run)
                   or word_chain(run))
        # Lowercase hex of git-sha or sha256 length is a content hash (generated-file footers), not a secret
        is_hash = re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", run)
        if not is_path and not is_name and not is_hash:
            spans.append(match.span())
    merged = []
    for start, end in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def safe(text, values=()):
    text = str(text)
    return MASK if secret_spans(text) or any(value in text for value in values) else text


def secret_values(text):
    return {text[start:end].strip("\"'") for start, end in secret_spans(text)} - {""}


def clean(value):
    if isinstance(value, str):
        return safe(value)
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, dict):
        return {safe(key): clean(item) for key, item in value.items()}
    return value


def units(text):
    return len(text.encode("utf-16-le", errors="surrogatepass")) // 2


def line_counts(line):
    return dict(dates=int(bool(DATE.search(line))), markers=len(MARKER.findall(line)),
                glyphs=line.count("\u2014") + line.count("\u2013"),
                secrets=len(secret_spans(line)), home_paths=len(HOME.findall(line)))


def file_record(role, name, text, seen, values=()):
    text = text.replace("\r\n", "\n").replace("\r", "\n").removeprefix("\ufeff")
    lines = text.split("\n")
    values = set(values) | secret_values(text)
    redactions = []
    for index, line in enumerate(lines):
        counts = line_counts(line)
        duplicate = int(bool(line.strip()) and units(line) > 40 and line in seen)
        if line.strip() and units(line) > 40:
            seen.add(line)
        if safe(line, values) == MASK:
            redactions.append(dict(line=index, duplicates=duplicate, **counts))
    return dict(role=role, name=safe(name, values), chars=units(text), est_tokens=math.ceil(units(text) / 4),
                lines=[safe(line, values) for line in lines], redactions=redactions)


def active_engines(bundle):
    return ("claude", "codex") if bundle["engine"] == "both" else (bundle["engine"],)


def hook_present(bundle, expected):
    name = re.split(r"[\\/]", expected["script"])[-1]
    return any(hook["event"] == expected["event"] and hook["script"] == name
               for hook in bundle["hooks"][expected["engine"]])


def score_bundle(bundle):
    validate_bundle(bundle)
    counts, tokens = Counter(), Counter()
    seen = {engine: set() for engine in active_engines(bundle)}
    for file in bundle["files"]:
        engine = file["role"].split("-", 1)[0]
        tokens[engine] += file["est_tokens"]
        redactions = {item["line"]: item for item in file.get("redactions", [])}
        for index, line in enumerate(file["lines"]):
            if index in redactions:
                counts.update({key: value for key, value in redactions[index].items() if key != "line"})
                continue
            counts.update(line_counts(line))
            if line.strip() and units(line) > 40:
                counts["duplicates"] += int(line in seen[engine])
                seen[engine].add(line)
    counts["tokens"] = sum(math.ceil(max(0, value - 3500) / 250) for value in tokens.values())
    counts["hooks"] = sum(not hook_present(bundle, item) for item in bundle["policy_expected"]
                          if item["engine"] in active_engines(bundle))
    deductions = [dict(code=code, count=counts[code], points=min(cap, counts[code] * rate), cap=cap)
                  for code, rate, cap in RATES if counts[code]]
    score = math.floor(max(0, 100 - sum(item["points"] for item in deductions)) + 0.5)
    grade = next(grade for minimum, grade in ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")) if score >= minimum)
    return dict(score=score, grade=grade, deductions=deductions, findings=[])


def validate_bundle(bundle):
    def integer(value):
        return type(value) is int and value >= 0

    if not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA or bundle.get("engine") not in ("claude", "codex", "both"):
        raise ValueError("invalid bundle header")
    if not isinstance(bundle.get("generator_version"), str):
        raise ValueError("missing generator version")
    if not all(integer(bundle.get(key)) for key in ("memory_files", "skills")):
        raise ValueError("invalid inventory counts")
    if not isinstance(bundle.get("files"), list):
        raise ValueError("invalid files")
    roles = {engine + suffix for engine in active_engines(bundle) for suffix in ("-global", "-workspace")}
    for file in bundle["files"]:
        if not isinstance(file, dict) or file.get("role") not in roles or not isinstance(file.get("name"), str):
            raise ValueError("invalid file")
        if not integer(file.get("chars")) or file.get("est_tokens") != math.ceil(file["chars"] / 4):
            raise ValueError("invalid token estimate")
        if not isinstance(file.get("lines"), list) or not all(isinstance(line, str) for line in file["lines"]):
            raise ValueError("invalid lines")
        redactions = file.get("redactions", [])
        if not isinstance(redactions, list):
            raise ValueError("invalid redactions")
        indices = set()
        for item in redactions:
            keys = ("line", "dates", "markers", "glyphs", "secrets", "home_paths", "duplicates")
            if not isinstance(item, dict) or set(item) != set(keys) or not all(integer(item[key]) for key in keys):
                raise ValueError("invalid redaction counts")
            index = item["line"]
            if index >= len(file["lines"]) or index in indices or file["lines"][index] != MASK or item["dates"] > 1 or item["duplicates"] > 1:
                raise ValueError("invalid redaction line")
            indices.add(index)
    hooks = bundle.get("hooks")
    if not isinstance(hooks, dict) or not isinstance(bundle.get("policy_expected"), list):
        raise ValueError("invalid hooks")
    for engine in ("claude", "codex"):
        if not isinstance(hooks.get(engine), list):
            raise ValueError("invalid hook inventory")
        for item in hooks[engine]:
            if not isinstance(item, dict) or not all(isinstance(item.get(key), str) for key in ("event", "script")):
                raise ValueError("invalid installed hook")
    for item in bundle["policy_expected"]:
        if not isinstance(item, dict) or item.get("engine") not in ("claude", "codex") or not all(isinstance(item.get(key), str) and item[key] for key in ("id", "event", "script")):
            raise ValueError("invalid expected hook")


class Doctor:
    def __init__(self, claude_home, codex_home, workspace, policy_path, config_path=None, config=None, budget=10):
        self.homes = {"claude": Path(claude_home), "codex": Path(codex_home)}
        self.workspace, self.policy_path = Path(workspace), Path(policy_path)
        self.config_path, self.config = config_path, config or {}
        self.findings, self.cache = [], {}
        self.hook_targets = {}
        self.deadline = time.monotonic() + budget
        self.expired = False

    def add(self, check, level, where, detail):
        self.findings.append(dict(check=check, level=level, where=safe(where), detail=safe(detail)))

    def available(self):
        if time.monotonic() < self.deadline:
            return True
        if not self.expired:
            self.add("budget", "WARN", "doctor", "time budget reached; remaining checks skipped")
            self.expired = True
        return False

    def label(self, path):
        path = Path(path)
        for name, base in list(self.homes.items()) + [("workspace", self.workspace)]:
            try:
                return name + "/" + path.relative_to(base).as_posix()
            except ValueError:
                pass
        return safe(path.name)

    def load(self, path):
        path = Path(path)
        if path not in self.cache:
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                if not isinstance(data, dict):
                    raise ValueError()
            except FileNotFoundError:
                data = {}
            except (OSError, ValueError, UnicodeError):
                self.add("config", "FAIL", self.label(path), "cannot read a JSON object")
                data = {}
            self.cache[path] = data
        return self.cache[path]

    def read(self, path):
        try:
            return path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError):
            self.add("read", "WARN", self.label(path), "cannot read text file")
            return None

    def walk(self, base, depth):
        stack = [(base, 0)]
        while stack and self.available():
            directory, level = stack.pop()
            if directory.is_symlink() or getattr(directory, "is_junction", lambda: False)():
                continue
            yield directory
            if level >= depth:
                continue
            try:
                for child in sorted(directory.iterdir(), reverse=True):
                    if not self.available():
                        return
                    if child.is_dir() and child.name.lower() not in SKIP and ".bak" not in child.name.lower():
                        stack.append((child, level + 1))
            except FileNotFoundError:
                pass
            except OSError:
                self.add("discovery", "WARN", self.label(directory), "cannot scan directory")

    def installed(self, config, engine):
        result = []
        hooks = config.get("hooks", {})
        for event, groups in hooks.items() if isinstance(hooks, dict) else []:
            for group in groups if isinstance(groups, list) else []:
                if not isinstance(group, dict):
                    continue
                nested = group.get("hooks", [group])
                for hook in nested if isinstance(nested, list) else []:
                    if not isinstance(hook, dict):
                        continue
                    command = hook.get("command", "")
                    args = hook.get("args", [])
                    parts = command if isinstance(command, list) else re.findall(r'''"[^"]*"|'[^']*'|[^\s]+''', str(command))
                    parts = parts + (args if isinstance(args, list) else [])
                    if secret_spans(" ".join(str(part) for part in parts)):
                        result.append(dict(event=safe(event), script=MASK))
                        continue
                    for part in parts:
                        if isinstance(part, str):
                            script = re.split(r"[\\/]", part.strip("\"'"))[-1]
                            literal = part.strip("\"'")
                            if re.match(r"^(?:[A-Za-z]:[\\/]|/)", literal):
                                self.hook_targets.setdefault((engine, event, script), []).append(Path(literal))
                            record = dict(event=safe(event), script=safe(script))
                            if record not in result:
                                result.append(record)
        return result

    def bundle(self):
        policy = self.load(self.policy_path)
        self.policy = policy
        block = policy.get("hooks", {})
        expected = block.get("expected", []) if isinstance(block, dict) else None
        if not isinstance(expected, list):
            self.add("hooks", "FAIL", "policy", "hooks.expected must be an array")
            expected = []
        valid_expected = []
        for item in expected:
            if isinstance(item, dict) and item.get("engine") in self.homes and all(isinstance(item.get(key), str) and item[key] for key in ("id", "event", "script")):
                valid_expected.append({key: safe(item[key]) for key in ("id", "engine", "event", "script")})
            else:
                self.add("hooks", "FAIL", "policy", "invalid expected hook")
        files, engines, hooks = [], [], {"claude": [], "codex": []}
        sources = []
        enabled = self.config.get("engines", {})
        for engine, home in self.homes.items():
            if not home.is_dir() or (isinstance(enabled, dict) and enabled.get(engine) is False):
                self.add("engine", "INFO", engine, "engine absent or disabled; skipped")
                continue
            engines.append(engine)
            filename = "CLAUDE.md" if engine == "claude" else "AGENTS.md"
            paths = [("global", home / filename), ("workspace", self.workspace / filename)]
            used = set()
            for role, path in paths:
                if path.resolve() in used or not self.available():
                    continue
                used.add(path.resolve())
                text = self.read(path)
                if text is not None:
                    sources.append((engine, role, filename, text))
            hooks[engine] = self.installed(self.load(home / ("settings.json" if engine == "claude" else "hooks.json")), engine)
            toml_path = home / "config.toml"
            if engine == "codex" and toml_path.is_file():
                if tomllib is None:
                    self.add("hooks", "INFO", "codex/config.toml", "TOML hook inspection needs Python 3.11; skipped")
                    valid_expected = [item for item in valid_expected if item["engine"] != "codex" or hook_present(dict(hooks=hooks), item)]
                else:
                    text = self.read(toml_path)
                    try:
                        hooks[engine].extend(self.installed(tomllib.loads(text or ""), engine))
                    except ValueError:
                        self.add("hooks", "FAIL", "codex/config.toml", "cannot read TOML configuration")
        values = set().union(*(secret_values(source[3]) for source in sources))
        seen = {engine: set() for engine in engines}
        for engine, role, filename, text in sources:
            files.append(file_record(engine + "-" + role, engine + "/" + role + "/" + filename,
                                     text, seen[engine], values))
        memory = self.memory_indices() if "claude" in engines else []
        skills = 0
        for engine in engines:
            for directory in self.walk(self.homes[engine] / "skills", 3):
                skills += int((directory / "SKILL.md").is_file())
        return dict(schema=SCHEMA, generator_version=VERSION,
                    engine=engines[0] if len(engines) == 1 else "both", files=files, hooks=hooks,
                    policy_expected=valid_expected if engines else [], memory_files=len(memory), skills=skills)

    def memory_directories(self):
        projects = self.homes["claude"] / "projects"
        return [directory / "memory" for directory in self.walk(projects, 1)
                if directory != projects and (directory / "memory").is_dir()]

    def memory_indices(self):
        return [directory / "MEMORY.md" for directory in self.memory_directories()
                if (directory / "MEMORY.md").is_file()]

    def settings_paths(self):
        yield self.homes["claude"] / "settings.json"
        yield self.homes["claude"] / "settings.local.json"
        for directory in self.walk(self.workspace, 3):
            yield directory / ".claude/settings.json"
            yield directory / ".claude/settings.local.json"

    def expanded_path(self, value, base):
        value = re.sub(r"^//([A-Za-z])/", lambda match: match[1].upper() + ":/", value)
        value = re.sub(r"[\\/]\*\*$", "", value)
        path = Path(os.path.expandvars(value)).expanduser()
        return path if path.is_absolute() else base / path

    def hygiene(self):
        for path in dict.fromkeys(self.settings_paths()):
            if not self.available():
                return
            if not path.is_file():
                continue
            config = self.load(path)
            raw = self.read(path)
            if raw and secret_spans(raw):
                self.add("settings-secrets", "FAIL", self.label(path), "secret-shaped value present; excerpt withheld")
            permissions = config.get("permissions", {})
            if not isinstance(permissions, dict):
                self.add("hygiene", "FAIL", self.label(path), "permissions must be an object")
                continue
            for kind in ("allow", "ask", "deny", "additionalDirectories"):
                entries = permissions.get(kind, [])
                if not isinstance(entries, list):
                    self.add("hygiene", "FAIL", self.label(path), kind + " must be an array")
                    continue
                for index, entry in enumerate(entries):
                    where = self.label(path) + " " + kind + "[" + str(index) + "]"
                    if not isinstance(entry, str):
                        self.add("hygiene", "FAIL", where, "entry must be a string")
                        continue
                    categories = []
                    if secret_spans(entry):
                        categories.append("secret")
                    if kind == "additionalDirectories":
                        if not self.expanded_path(entry, path.parent.parent).is_dir():
                            categories.append("missing-directory")
                    else:
                        if PID.search(entry):
                            categories.append("pinned-pid")
                        if "*" not in entry and LOCAL.search(entry):
                            categories.append("localhost-oneoff")
                        rule = re.fullmatch(r"(?:Read|Edit|Write)\((.*)\)", entry)
                        if rule:
                            target = self.expanded_path(rule[1], path.parent.parent)
                            if not any(char in str(target) for char in "*?[") and not target.exists():
                                categories.append("retired-path")
                        if entry.startswith("Bash(") and "*" not in entry and len(entry) > 60:
                            categories.append("one-off")
                    for category in categories:
                        self.add(category, "FAIL" if category == "secret" else "WARN", where, category)

    def memory(self):
        for directory in self.memory_directories():
            if not self.available():
                return
            index = directory / "MEMORY.md"
            text = self.read(index)
            if text is None:
                self.add("memory-index", "WARN", self.label(index), "memory index absent or unreadable")
                text = ""
            references = set()
            targets = re.findall(r"\[[^\]]*\]\(<?([^\s)>]+)>?(?:\s+[^)]*)?\)", text)
            targets += re.findall(r"`([^`\r\n]+\.md)`", text)
            for value in targets:
                if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*://|^#", value):
                    continue
                target = self.expanded_path(value.split("#", 1)[0], index.parent)
                references.add(target.resolve())
                if not target.is_file():
                    self.add("memory-missing", "WARN", self.label(index), "referenced file missing: " + safe(value))
            for directory in self.walk(index.parent, 3):
                for path in sorted(directory.glob("*.md")):
                    if not self.available():
                        return
                    if path != index and path.resolve() not in references:
                        self.add("memory-orphan", "WARN", self.label(path), "file absent from MEMORY.md index")
                    content = self.read(path)
                    if content is not None and units(content) > 2000:
                        self.add("memory-size", "WARN", self.label(path), "memory file exceeds 2000 characters")

    def run_external(self, check, script, args):
        if not script.is_file():
            self.add(check, "INFO", check, "tool absent; skipped")
            return
        if not self.available():
            return
        try:
            result = subprocess.run([sys.executable, str(script)] + args, cwd=str(script.parent.parent),
                                    capture_output=True, encoding="utf-8", errors="replace",
                                    timeout=max(0.001, self.deadline - time.monotonic()))
            self.add(check, "OK" if result.returncode == 0 else "FAIL", check,
                     "check passed" if result.returncode == 0 else "check failed (exit " + str(result.returncode) + ")")
            output = result.stdout + "\n" + result.stderr
            if secret_spans(output):
                self.add(check, "INFO", check, MASK)
            else:
                for line in output.splitlines():
                    if line.startswith("DRIFT") or (check == "ledger" and line.startswith(("FAIL", "WARN"))):
                        self.add(check, "WARN" if line.startswith(("DRIFT", "WARN")) else "FAIL", check, line)
        except subprocess.TimeoutExpired:
            self.add(check, "FAIL", check, "check timed out")
        except OSError:
            self.add(check, "FAIL", check, "could not start check")

    def full(self, bundle):
        for item in bundle["policy_expected"]:
            if item["engine"] in active_engines(bundle):
                present = hook_present(bundle, item)
                self.add("hooks", "OK" if present else "FAIL", item["engine"] + " " + item["event"],
                         item["id"] + (": present" if present else ": missing event/script reference"))
                name = re.split(r"[\\/]", item["script"])[-1]
                targets = list(self.hook_targets.get((item["engine"], item["event"], name), []))
                if re.match(r"^(?:[A-Za-z]:[\\/]|/)", item["script"]):
                    targets.append(Path(item["script"]))
                if present and targets and not all(target.is_file() for target in targets):
                    self.add("hook-file", "FAIL", item["engine"] + " " + item["event"],
                             item["id"] + ": referenced absolute script missing")
        if "claude" in active_engines(bundle):
            self.hygiene()
            self.memory()
        generator = ROOT / "tools/gen.py"
        config_path = Path(self.config_path) if self.config_path else ROOT / "rig.config.json"
        # Drift only means something against the buyer's own config; without one there is nothing to compare
        if config_path.is_file():
            self.run_external("generator", generator, ["check", "--config", str(config_path.resolve())])
        else:
            self.add("generator", "INFO", "generator", "no rig.config.json; drift check skipped")
        ledger = self.policy.get("ledger", {})
        brain = ledger.get("path") if isinstance(ledger, dict) else None
        paths = self.config.get("paths", {})
        brain = brain or (paths.get("brain") if isinstance(paths, dict) else None)
        if isinstance(brain, str) and brain:
            self.run_external("ledger", self.expanded_path(brain, self.workspace) / "tools/hm.py", ["doctor"])
        else:
            self.add("ledger", "INFO", "ledger", "ledger path absent; skipped")


def render(report):
    lines = []
    for item in sorted(report["deductions"], key=lambda item: -item["points"])[:5]:
        lines.append("INFO score/" + item["code"] + " count " + str(item["count"]) + "; deduction " + str(item["points"]))
    for finding in report["findings"]:
        lines.append(" ".join(str(finding[key]) for key in ("level", "where", "detail")))
    counts = Counter(item["level"] for item in report["findings"])
    lines.append("rig doctor: score {score} (grade {grade}), {warn} warn, {fail} fail".format(
        **report, warn=counts["WARN"], fail=counts["FAIL"]))
    return "\n".join(" ".join(safe(line).replace("\u2014", "-").replace("\u2013", "-").replace("\x00", "").split()) for line in lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect instruction footprint and local rig health.")
    for option in ("config", "claude-home", "codex-home", "workspace", "policy", "bundle", "score-bundle"):
        parser.add_argument("--" + option, type=Path)
    parser.add_argument("--lite", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.score_bundle:
            report = score_bundle(json.loads(args.score_bundle.read_text(encoding="utf-8-sig")))
        else:
            config = json.loads(args.config.read_text(encoding="utf-8-sig")) if args.config else {}
            if not isinstance(config, dict) or not isinstance(config.get("paths", {}), dict):
                raise ValueError()
            paths = config.get("paths", {})
            def path_arg(name, fallback):
                value = getattr(args, name) or paths.get(name) or fallback
                return Path(value).expanduser().resolve()
            doctor = Doctor(path_arg("claude_home", "~/.claude"), path_arg("codex_home", "~/.codex"),
                            path_arg("workspace", Path.cwd()),
                            Path(args.policy or os.environ.get("COMMONRIG_POLICY", "~/.commonrig/policy.json")).expanduser().resolve(),
                            args.config, config)
            bundle = doctor.bundle()
            report = score_bundle(bundle)
            if args.bundle:
                args.bundle.write_text(json.dumps(clean(bundle), indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
            if not args.lite:
                doctor.full(bundle)
            report["findings"] = doctor.findings
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        report = dict(score=0, grade="F", deductions=[], findings=[dict(check="input", level="FAIL", where="doctor", detail="cannot read, validate or write requested input/output")])
    print(json.dumps(clean(report), indent=2, ensure_ascii=True) if args.json else render(report))
    return 0 if args.lite else int(any(item["level"] == "FAIL" for item in report["findings"]))


if __name__ == "__main__":
    sys.exit(main())
