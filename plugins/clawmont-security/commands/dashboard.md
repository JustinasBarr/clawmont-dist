---
allowed-tools: Bash(node:*)
description: Show the local security dashboard URL — and whether anything is actually serving it
---

## Context

- Dashboard status: !`node "${CLAUDE_PLUGIN_ROOT}/dashboard-status.mjs" 2>&1`

## Your task

Relay the status above to the user in **two lines or fewer**. It is already
written for a reader; your job is to pass it on, not to restate it at length.

The one rule that matters: **a URL appears only if something answered on it.**
The probe prints one when the dashboard replied to `/api/health`, and names a
port and nothing else in every other case. Do not turn a port back into a link,
do not offer `http://127.0.0.1:18791` from memory, and do not describe the
dashboard as "available at" an address the probe did not confirm. A dead link
from a security tool is worse than no answer.

Two states are worth a sentence of context rather than a bare relay:

- **Not installed / no plugin entry** — the dashboard is part of the OpenClaw
  gateway plugin, a different product surface from this Claude Code plugin.
  Most people here have never installed it, and that is not a fault or a broken
  install. The record they *do* have is the local audit trail — point at
  `/clawmont:audit`, and say plainly that there is nothing to fix.
- **Not running** — the dashboard is served from inside the gateway process, so
  it is down whenever the gateway is. Give them the start command the probe
  printed and stop there. **Do not run it.** Starting a background gateway
  because someone asked where a page lives is a side effect they did not ask
  for, and this command reads only.

Do not re-run the probe, do not edit any config, and do not offer to change the
port. If the status says something else is holding the port, that is a fact
about their machine — report it and leave it to them.
