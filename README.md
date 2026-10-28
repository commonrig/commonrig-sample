# CommonRig free sample

CommonRig is an agent operating kit for Claude Code and Codex: single-sourced rules, hooks, a file-based ledger, protocols and a rig doctor.

This free sample contains the rig doctor lite footprint score and the orchestration protocol. It needs Python 3.9 or later with no extra dependencies. From this folder, run:

```sh
python doctor/doctor.py --lite
```

To install the orchestration protocol as a Claude Code skill from this repo's plugin marketplace:

```sh
/plugin marketplace add commonrig/commonrig-sample
/plugin install commonrig-orchestration@commonrig
```

On Claude Code 2.1.275 or later one line does both: `/plugin install commonrig-orchestration --marketplace commonrig/commonrig-sample`. The skill is plain guidance in `skills/commonrig-orchestration/SKILL.md`: no scripts, no network calls.

The lite score measures the footprint of your local agent setup. It is not a certification of correctness or security. Read doctor/SCORING.md for the scoring rules and protocols/orchestration.md for the working protocol.

The paid kit adds rule sources and generation, setup and installation tools, enforcement hooks, ledger templates and tools, skills, configuration examples and the full doctor workflow.

- Kit: A$10 one-off, including 3 months of updates.
- Updates after the included period: A$3/month or A$30/year.
- Hosted full check: A$0.50.

Details: https://commonrig.com

Research disclosure: the store logs anonymised visits and agent tool calls to study how AI agents find and buy software. There are no hidden instructions for agents anywhere.
