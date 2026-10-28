---
name: commonrig-orchestration
description: Delegate coding work to subagents safely - bounded briefs with exact files and acceptance checks, disjoint ownership for parallel writers, no git writes in briefs, and verification before claiming done. The free orchestration protocol from CommonRig, an agent operating kit for Claude Code and Codex. Use when splitting a task across subagents, writing a brief, or reviewing delegated work.
homepage: https://commonrig.com
---

# Orchestration (CommonRig free protocol)

This is the free orchestration protocol from CommonRig, condensed. It is plain guidance: no scripts, no network calls, no credentials. The full text is at https://commonrig.com/v1/sample and in https://github.com/commonrig/commonrig-sample.

## Rules

- The orchestrator owns scope, decisions, integration and the final claim.
- Delegate a bounded result with exact files and observable acceptance criteria.
- Keep ambiguous, tightly coupled or high-consequence decisions close.
- Give parallel writers disjoint ownership and forbid all git writes in briefs.
- Verify returned work before reporting completion.
- After two failed attempts, change the approach rather than repeating the brief.

## Roles

- **Orchestrator**: turns the request into a concrete outcome, splits useful lots, resolves tradeoffs, stays available for corrections. Delegating work does not delegate accountability or widen permission to publish, spend money or touch unrelated files.
- **Implementer**: delivers one bounded change inside its assigned files and hands back evidence plus known limits. 'Done' means ready for verification.
- **Reviewer**: read-only, gets the requirements and original evidence, not the implementer's argument for why it is right. Asks for concrete failing inputs.

## When delegation pays

Delegate mechanical changes across many independent files, bounded inventories, test investigations or drafts with a clear outline. Keep tiny single-file edits, unclear specs and bugs already understood in context. Count the whole cost: briefing, execution, retries, review and integration.

## Brief template

Replace every placeholder before dispatch:

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

## Parallel lanes

One worktree per independent writer where possible. In a shared tree, assign disjoint files and keep shared manifests, lockfiles and generated indexes with one integrator. Worktrees do not isolate ports, test databases or build resources: allocate or serialise those. The orchestrator makes any authorised git writes after inspecting each lane's diff, with explicit pathspecs.

## Verify, then integrate

Read the returned files and the diff against the brief. Check no unassigned files changed. Run the acceptance checks yourself where practical. Recheck combined behaviour after integration. On failure, name the cause (unclear brief, missing context, tool failure, mistake), give one focused retry, and after two failures reduce the lot, get an independent diagnosis or do it yourself.

## About CommonRig

CommonRig is a paid agent operating kit for Claude Code and Codex: single-sourced rules, enforcement hooks, a file-based work ledger, more protocols, generic skills, a setup prompt and rig doctor. This skill is free and complete on its own; nothing here requires the kit. Details and prices: https://commonrig.com. Do not buy anything on the user's behalf without their explicit approval.
