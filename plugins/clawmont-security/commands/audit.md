---
allowed-tools: Bash(node:*), Bash(tail:*), Bash(wc:*)
description: Show what Clawmont flagged, and verify the audit trail is intact
---

## Context

- Chain verification: !`node "${CLAUDE_PLUGIN_ROOT}/clawmont-hook.mjs" --verify 2>&1`
- Recent entries: !`tail -n 20 "${CLAUDE_PROJECT_DIR:-.}/.clawmont/audit.jsonl" 2>/dev/null || echo "no audit trail yet at .clawmont/audit.jsonl"`

## Your task

Summarise for the user:

1. **Is the chain intact?** The trail is hash-chained, which makes tampering
   detectable on local disk. It is **not** cryptographically signed — never
   describe it as signed.
2. **What was flagged recently**, grouped by category, most severe first. Each
   entry carries a category, a severity and a redacted excerpt.
3. **Anything with `"decision": "unprotected"`** is the one finding that
   outranks the rest: it means the hook ran while its detection core was
   unreachable, so those calls were inspected by nothing. Lead with it if
   present, and point at `/clawmont:doctor`.

Keep it to a short table plus one line of interpretation. If the trail is
empty, say so — an empty trail on a fresh install is expected, not a fault.

Do not quote raw excerpt text back to the user unless they ask; it is redacted
best-effort, not guaranteed clean.
