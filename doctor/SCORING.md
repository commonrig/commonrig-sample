# scoring v1

This is the normative CommonRig footprint score, version 1. Generator version is
`1.0.0`. The Python CLI and hosted TypeScript scorer consume the same bundle.
A score measures instruction footprint, not security certification. Health
findings do not change the score. Missing engines are INFO, never FAIL.

## Inputs and normalization

For each installed, enabled engine, load these files in this order:

- Claude: `<claude_home>/CLAUDE.md`, then `<workspace>/CLAUDE.md` if present.
- Codex: `<codex_home>/AGENTS.md`, then `<workspace>/AGENTS.md` if present.

Read UTF-8, remove the leading BOM, replace CRLF and CR with LF. Count characters
as UTF-16 code units (JavaScript `string.length`). Each file's token estimate is
`ceil(chars / 4)`. Sum file estimates per engine. An identical resolved file
path is read once per engine. Missing instruction files contribute zero.
Split lines on LF, preserving the final empty line. Do not trim line contents.
File names in generated bundles are logical names, never source home paths.

Count `<claude_home>/projects/*/memory/MEMORY.md` files and `SKILL.md` files under
each active engine's `skills` directory, at most three directory levels below
that directory. Memory contents and skill contents are not score inputs and are
not included in bundles. Do not follow directory symlinks or junctions. Skip
`.git`, `node_modules`, `library`, `temp`, `bin`, `obj`, `__pycache__`, and names
containing `.bak` during discovery (case insensitive).

## Arithmetic

Start at 100. Counts below are pooled across active engines, except token
thresholds and duplicate sets, which are computed independently per engine.
Apply each cap once to its pooled category. Emit only positive-count categories,
in the table order. `points` is the positive amount subtracted, not a negative
number. `cap` is the maximum positive deduction.

| code | count | points | cap |
| --- | --- | --- | --- |
| tokens | Sum of `ceil(max(0, engine_tokens - 3500) / 250)` | count | 30 |
| dates | Lines containing at least one `[0-9]{4}-[0-9]{2}-[0-9]{2}` match | count | 10 |
| markers | Case-sensitive standalone `SUPERSEDED`, `DEPRECATED`, `RETIRED` occurrences | count * 2 | 10 |
| glyphs | U+2014 and U+2013 code-point occurrences | count * 0.5 | 5 |
| duplicates | Occurrences after the first of an exact non-empty line longer than 40 UTF-16 units, across that engine's concatenated files | count | 10 |
| secrets | Non-overlapping secret-shaped value spans | count * 10 | 30 |
| home_paths | Absolute home path occurrences, pattern below | count * 0.5 | 5 |
| hooks | Missing expected event/script references for active engines | count * 5 | 15 |

A marker is standalone when neither neighbor is an ASCII letter, digit or
underscore. Duplicate comparisons are case-sensitive, preserve whitespace and
include repeats within a file. Whitespace-only lines are excluded. Separate
engines never share duplicate sets. Date strings need not be real calendar dates.

Home path pattern (global, case-sensitive except that drive letter can be either
case): `[A-Za-z]:[\\/]Users[\\/][^\s/\\"'<>]+|/(?:home|Users)/[^\s/\\"'<>]+`.
Count one match per path occurrence, not one per path segment. Tilde paths,
relative paths and environment-variable references do not count.

Subtract `sum(min(cap, count * rate))`, clamp to [0, 100], then round halves up:
`floor(clamped + 0.5)`, equivalent to JavaScript `Math.round` here. Grade the
rounded score: A >= 90, B >= 75, C >= 60, D >= 40, otherwise F.

## Secrets and masked lines

The collector's `secret_spans()` recognizes:

1. Case-insensitive assignment or JSON field names `pgpassword`, `password`,
   `passwd`, `pwd`, `token`, `api_key`, `apikey`, `secret`, followed by optional
   closing quote, whitespace, `=` or `:`, whitespace, then a value.
2. Case-insensitive `Bearer` plus whitespace and at least 20 characters other
   than whitespace, double quote, single quote, `)`, `;`.
3. Word-boundary prefix `sk-`, `ghp_`, or `xox` followed by one or more ASCII
   letters, digits, underscore, plus or hyphen. Prefix matching is case-sensitive.
4. An attached `-pVALUE` after a case-insensitive `mysql` command, up to the next
   semicolon or newline. Whitespace must precede `-p`. Other tools' `-p` flags
   are not passwords.
5. Runs of 32+ `[A-Za-z0-9+/=_-]` characters containing both an ASCII letter and
   digit, excluding recognizable paths, `mcp__` identifiers, word chains, and
   runs that are exactly 40 or 64 lowercase hex characters (content hashes such as
   git SHAs and the generator's source-sha256 footer).

For 1 and 4, VALUE is a double-quoted string without newline, a single-quoted
string without newline, or a run excluding whitespace and `;)"',}`. Capture
only the value, including its quotes when quoted. For 2, capture the token.
For 3 and 5, capture the whole match. Merge overlapping spans (not adjacent
spans) before counting. The executable reference regexes and path/word-chain
exclusions are `VALUE`, `ASSIGN`, `BEARER`, `PREFIX`, `LONG`, and `secret_spans`
in `doctor.py`. A port that collects raw text must reproduce those expressions;
a hosted scorer receiving a masked bundle does not need to recover secrets.

`safe()` withholds an entire excerpt containing a secret, returning exactly
`[withheld secret excerpt]`, with no secret prefix or suffix. Each masked line
has a corresponding `redactions` entry containing only its original numeric
counts. The scorer replaces that line's normal contribution with these counts.
`duplicates` is 0 or 1, computed against earlier original lines of that engine.
Masked placeholder lines are never added to the duplicate set. Lines containing a value detected elsewhere in the instruction files are also
withheld, with zero `secrets` when that line itself has no shaped span. File `chars`
and `est_tokens` describe original normalized text, not shortened masked text.
This preserves scores while withholding source values. No hashes of secrets
are exported. Raw, unmasked bundles can be scored locally with the same detector;
output findings and examples must still be masked.

## Hooks

`hooks.expected` in policy supplies `id`, `engine`, `event`, `script`.
No policy means an empty expected list and zero hook deductions. Only active
engines' entries count. Every expected entry is evaluated separately, including
repeated entries. A reference is present if an installed hook has the exact same
case-sensitive event and script basename; normalize both slash styles when
extracting the expected script basename. Do not use substring matching.

Collect Claude `settings.json` hooks, Codex `hooks.json` hooks and Codex
`config.toml` hooks. Supported structure is `hooks[event]` arrays of command
objects or objects with nested `hooks` arrays. `command` can be a string or
argument array; optional `args` is an array. Split command strings into quoted
or whitespace-delimited arguments, and record each argument's basename. Footprint
scoring checks configured references, not shell execution or script behavior.
Full mode additionally fails missing explicit absolute script paths in commands
or policy. Relative script paths are not resolved against an assumed repository
layout. A command containing a detected secret exports only a masked hook entry.
On Python 3.9/3.10 without `tomllib`, if a Codex config TOML exists, emit INFO
and omit unresolved Codex expectations from the collected bundle so skipped
TOML checks cannot cause false failures. References present in hooks JSON still
count. A supplied bundle is always scored as written, regardless of runtime.

## Bundle JSON schema

Required fields; unknown fields are ignored. Use JSON numbers for integers.

```json
{
  "schema": "commonrig.doctor.bundle/1",
  "generator_version": "1.0.0",
  "engine": "claude",
  "files": [{
    "role": "claude-global",
    "name": "claude/global/CLAUDE.md",
    "chars": 12,
    "est_tokens": 3,
    "lines": ["Be accurate."],
    "redactions": []
  }],
  "hooks": {"claude": [], "codex": []},
  "policy_expected": [],
  "memory_files": 0,
  "skills": 0
}
```

`engine` is `claude`, `codex`, or `both`. With no installed engines use `both`
with empty files, hooks and expectations; local report explains absence.
File roles are `<active-engine>-global` or `<active-engine>-workspace`.
`name` is a string. `chars`, `est_tokens`, `memory_files`, `skills` are
non-negative integers; `est_tokens` must equal `ceil(chars / 4)`.
`lines` is an array of strings. Installed hooks are `{ "event": "PreToolUse",
"script": "guard.mjs" }`; expectations add `id` and `engine`.

Optional per-file `redactions` defaults to `[]`. Each item has exactly these
non-negative integer fields: `line` (zero-based index), `dates`, `markers`,
`glyphs`, `secrets`, `home_paths`, `duplicates`. Indices must be unique and
point to the mask placeholder; `secrets` can be zero for a repeated value; `dates` and `duplicates`
are 0 or 1. No original excerpt or secret value is stored here.
The collector is trusted for original sizes and redaction counts; the score
is diagnostic, not tamper-proof attestation.

## Report JSON schema and CLI

```json
{
  "score": 100,
  "grade": "A",
  "deductions": [],
  "findings": []
}
```

`score` is integer 0..100. `grade` is A/B/C/D/F. Deductions have `code` from the
table, non-negative integer `count`, numeric `points`, numeric `cap`, and an
optional masked string `example`. This implementation omits `example`.
Findings have strings `check`, `where`, `detail` and level OK/INFO/WARN/FAIL.
Pure bundle scoring produces `findings: []`; local collection and full checks
append findings without changing deductions. Findings retain discovery order.

`--lite` collects footprint and prints up to five deductions by descending
points (ties keep table order), followed by collection findings. Exit is always
0. Default full mode also checks hook coverage, permission hygiene, settings
secrets, memory links/orphans/size, generator drift and ledger health. Exit is
1 if any finding is FAIL, else 0. `--json` returns the report above.
`--score-bundle IN` performs only pure scoring, with `--json` for parity.
`--bundle OUT` writes collected masked data, in lite or full mode.
Full-health findings are deliberately absent from uploaded bundles.

Explicit path flags override config `paths`; defaults are `~/.claude`,
`~/.codex`, cwd, and `~/.commonrig/policy.json`. `COMMONRIG_POLICY` overrides
the default policy path. Relative config paths resolve from invocation cwd.
An engine explicitly disabled in config is treated as absent.

Workspace settings discovery stops at project-directory depth 3, with workspace
at depth 0. Full checks inspect allow/ask/deny and additionalDirectories, flag
pinned process ids, specific localhost commands, missing literal Read/Edit/Write
paths, long (>60 characters) non-wildcard Bash rules, and missing directories.
Secret values are FAIL; other hygiene categories are WARN. Retirement is
inferred from a missing referenced path, never from a hardcoded project name.
Settings secrets outside permission lists are also FAIL.

Memory links are local Markdown links or backticked `.md` references in each
MEMORY.md. Remote URLs and fragment-only links are skipped. Missing targets or indices,
unindexed Markdown files and memory Markdown files over 2000 UTF-16 units
(including MEMORY.md itself) are WARN. No memory text is exported.

A shared 10-second budget bounds discovery and subprocess timeouts. A skipped
scan emits WARN; an external timeout emits FAIL. Generator check runs the kit's
`tools/gen.py check --config PATH` if the tool exists, using explicit config or kit-root
`rig.config.json`. A missing config is left to the generator to diagnose. It reports DRIFT lines
and a nonzero exit as FAIL. Ledger check runs `<ledger>/tools/hm.py doctor`, using
policy `ledger.path` then config `paths.brain`, resolving relative ledger paths
against workspace and using ledger directory as cwd.
Missing optional tools are INFO. Subprocess output with a detected secret is
withheld as a whole. File/JSON/TOML error messages never echo parser input.

## Worked examples and parity vectors

The matching `tests/fixtures/doctor/vector-*.bundle.json` and `.report.json`
files are executable vectors. Reports contain no local health findings.

1. **vector-clean**: Claude has exactly 14000 characters, 3500 tokens. No other
   deductions. Memory count 2 and skill count 3 do not affect scoring. Score
   **100, A**, deductions `[]`.
2. **vector-mixed**: Claude has 3751 tokens, Codex 3501: token count 2 + 1 = 3.
   Two dated lines (2 points), two markers (4), three glyphs (1.5), two repeated
   lines (2), one secret span (10), two home paths (1), and one missing expected
   hook (5). Total 28.5 points. Raw score 71.5 rounds to **72, C**.
3. **vector-capped**: Counts in table order are 100, 12, 6, 12, 12, 4, 12, 4.
   Capped deductions are 30, 10, 10, 5, 10, 30, 5, 15. Total 115, clamped to
   **0, F**. This checks all caps and lower clamping.
