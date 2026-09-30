# Orchestration

Free sample. This document is MIT licensed; the complete notice is below. It is
usable on its own, with any coding agent that supports bounded delegation.

## Rules

- The orchestrator owns scope, decisions, integration and the final claim.
- Delegate a bounded result with exact files and observable acceptance criteria.
- Keep ambiguous, tightly coupled or high-consequence decisions close.
- Give parallel writers disjoint ownership and forbid all git writes in briefs.
- Verify returned work before reporting completion.
- After two failed attempts, change the approach rather than repeating the brief.

## Assign roles by responsibility

The orchestrator turns the owner's request into a concrete outcome, identifies
constraints, splits useful lots and resolves tradeoffs. It keeps track of the
whole task and stays available for the owner's corrections. Delegating work does
not delegate accountability for the result or expand permission to publish,
spend money or modify unrelated files.

An implementer delivers one bounded change. It reads relevant context, works only
inside its assigned files, checks behaviour and hands back evidence plus known
limitations. It should report an interface problem instead of quietly modifying
a neighbour's files. An implementer's 'done' means ready for verification.

A reviewer examines requirements, changed behaviour and failure cases. Give it
read-only access and enough original evidence to form an independent view. For
an independent review, do not lead with the implementer's explanation of why the
change is correct. Ask for concrete failing inputs and supporting code paths.
The orchestrator adjudicates findings and integrates the accepted result.

## Decide whether delegation pays

Delegate mechanical changes across many independent files, a bounded inventory,
a test investigation or a document draft with a clear outline. Keep a tiny
single-file change in the current session when writing and reviewing a brief
would take longer than doing it. Keep an unclear specification close until the
unknowns have been resolved. A bug already understood in the current context
may lose more from a handoff than it gains from extra capacity.

A cheaper model can handle well-specified repetition while the strongest model
handles judgement and verification. That is useful only when the total cost is
lower: briefing, execution, retries, review and integration all count. For
example, saving ten minutes of mechanical work is poor economics if review takes
twenty minutes because the brief left naming and behaviour undecided. Prefer
scripts for deterministic transformations when they are simpler to verify.

Use the owner's available model configuration, such as
`config/models.example.json` in CommonRig, rather than a fixed brand ranking.
Prefer suitable subscription capacity before metered APIs, respect interactive
usage reserves, and never send private data to a provider whose training policy
is unknown or permits training on it. More agents also consume local memory,
CPU and attention; concurrency is a resource decision, not a success metric.

## Write a brief the implementer can finish

A brief should stand alone after a restart. Include the following fields, replacing
every placeholder before dispatch:

```text
Outcome: observable result and reason the owner needs it.
Working directory: exact absolute path.
Read first: relevant instruction files and interface contract.
Write only: exact file paths, including tests and handoff.
Read-only dependencies: exact paths or bounded source extracts.
Behaviour: inputs, outputs, failure cases and compatibility constraints.
Acceptance: commands and observations that prove the result.
Limits: runtime, cost, dependencies, network and external-action permissions.
Git: no git writes, including add, commit, checkout, restore, reset,
     stash, clean, merge, rebase and worktree changes.
Collaboration: other writers are active; never revert their changes.
Handoff: changed files, checks with results, unresolved issues, next step.
Stop condition: scope collision, missing contract or two failed attempts.
```

Do not use 'fix whatever you find' when you mean three named files. If acceptance
requires a new test file, include it in ownership. If the implementer discovers
necessary work outside scope, it should report the smallest requested extension
and continue independent work. A vague brief cannot be repaired by confidence.

## Run parallel lanes safely

Use a separate worktree for each independent writer where possible. In a shared
tree, assign disjoint files explicitly and reserve shared manifests, lockfiles
and generated indexes for one integrator. Worktrees isolate files and indexes,
but test databases, ports and build resources may still collide. Allocate them
or serialise the affected operations.

The orchestrator performs authorised git writes after inspecting each lane's
diff, with explicit pathspecs. A reviewer should never tidy the working tree.
Record lane ownership and live jobs so a restarted session does not launch a
second writer into the same files.

## Verify, then integrate

Read the returned files and diff against the brief. Check that no unassigned
files changed. Run the acceptance checks yourself when practical, or inspect
reproducible evidence tied to the exact returned state. An exit code without the
command and input version is weak evidence. Recheck combined behaviour after
integration because individually passing lanes can disagree at an interface.

When an attempt fails, identify whether the cause is an unclear brief, missing
context, a tool failure or an implementation mistake. Give one focused retry
with the new evidence. After two failed attempts, stop repeating the same task:
reduce the lot, obtain an independent diagnosis, switch to a suitable stronger
model, or implement it in the orchestrator. Record what failed so the next
attempt does not rediscover it. Required acceptance criteria remain required.

## Worked example

Sam asks for CSV export of filtered table rows. The orchestrator keeps the UI
wiring and defines a pure serializer contract: a fixed column order, correct
quoting, preserved embedded newlines and an empty-export result containing only
the header. It assigns an implementer exactly `src/export-csv.ts`,
`tests/export-csv.test.ts` and `handoff/export.md`. Existing table code is read-only.
The brief names the repo's focused test command and bans git writes.

A cheaper model writes the serializer because the behaviour is precise. A
reviewer independently probes commas, quotes, newlines and empty rows. It finds
that embedded quotes are not doubled. The implementer fixes that case, records
the test result and hands back the files. The orchestrator inspects the diff,
runs the focused tests and checks a real filtered export after adding UI wiring.
Only then does it report completion. If spreadsheet formula handling matters,
it resolves that requirement explicitly rather than letting a worker guess.

## Why

Two subagents sharing one tree once reverted each other's work while trying to
repair failing tests. In another generic incident, an orchestrator trusted a
polished handoff even though the output omitted the required empty case. Exact
ownership prevents one class of collision; observable acceptance and independent
verification catch another. Delegation works when it reduces effort while keeping
responsibility and evidence visible.

## MIT licence

Copyright (c) CommonRig

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
