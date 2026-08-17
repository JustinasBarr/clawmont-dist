---
allowed-tools: Bash(node:*)
description: Check that Clawmont is actually inspecting tool calls
---

## Context

- Doctor report: !`node "${CLAUDE_PLUGIN_ROOT}/scripts/doctor.mjs" 2>&1`

## Your task

Report the result to the user plainly, in four lines or fewer.

The only question that matters is the **behaviour** block: the hook was spawned
and given one payload that must be denied and one that must not. If both
verdicts are correct, Clawmont is working. If the detection core line says
`NOTHING RESOLVED`, the plugin directory is incomplete and the hook is
inspecting nothing — say so directly; do not soften it, and do not describe the
install as working because the files are present.

Also surface, if present:

- **mode** — `monitor` is the shipped default and it never blocks anything. If
  the user believes they are protected and the mode is `monitor`, that gap is
  the single most important thing on the screen. Tell them `/clawmont:mode
  enforce` turns blocking on.
- **gitignore** — if `.clawmont/` is not ignored in a git repo, the audit trail
  can be committed. It holds redacted excerpts of flagged calls; redaction is
  best-effort, so it does not belong in a repo.

Do not re-run the check, and do not fix anything unless the user asks.
