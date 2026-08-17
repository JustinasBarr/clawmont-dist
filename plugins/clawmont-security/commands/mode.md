---
allowed-tools: Bash(node:*), Bash(cat:*), Read, Write
description: Show or change Clawmont's mode (monitor or enforce)
argument-hint: "[monitor|enforce]"
---

## Context

- Requested mode: `$ARGUMENTS`
- Current config: !`cat "${CLAUDE_PROJECT_DIR:-.}/.clawmont/hook-config.json" 2>/dev/null || echo "no config file — running in monitor (the default)"`

## Your task

**No argument given** → report the current mode and stop. Explain the two in one
line each:

- `monitor` — inspects and records every tool call, blocks nothing. The default.
- `enforce` — additionally blocks the high-confidence set; everything else still
  only warns.

**Argument is `monitor` or `enforce`** → write
`${CLAUDE_PROJECT_DIR:-.}/.clawmont/hook-config.json` containing exactly:

```json
{
  "mode": "<the requested mode>",
  "verbose": false
}
```

Preserve any other keys already in that file. Create the `.clawmont` directory
if it does not exist. Then confirm the change in one line and tell the user it
takes effect on the next tool call — no restart needed.

**Anything else** → say only `monitor` and `enforce` are valid, and stop.

Before switching to `enforce`, say this once, plainly: enforce mode blocks
tool calls, and a wrong block interrupts real work. The honest framing is
monitor first, then enforce once they have seen what it flags in their own
repo. Do not talk them out of it — just make sure the trade is stated.
