# Clawmont Security for Claude Code

Runtime security for your coding agent. It inspects **every tool call before it
runs** and **every tool result after**, flags what looks dangerous, and writes a
tamper-evident local record of what happened.

Detection runs on your machine. Nothing about your code, your commands, or your
prompts is sent anywhere.

---

## Install

```
/plugin marketplace add JustinasBarr/clawmont-dist
/plugin install clawmont-security@clawmont
```

Restart Claude Code, or start a new session, and it is live.

**It installs in monitor mode. It will not block anything** until you turn
blocking on — see [Turning on blocking](#turning-on-blocking) below.

---

## Check that it is actually working

```
/clawmont:doctor
```

Run this once after installing. It does not check that the files are present —
it spawns the hook, hands it one payload that must be blocked and one that must
not, and shows you both verdicts.

That distinction matters more than it sounds. A security hook whose detection
engine fails to load will sit there inspecting nothing, and a check that only
looks for files on disk will happily call that a working install. `doctor`
answers the only question worth asking: *did it just stop an attack, and did it
leave ordinary work alone?*

---

## Commands

| Command | What it does |
|---|---|
| `/clawmont:doctor` | Proves the hook is inspecting calls — a real block and a real allow |
| `/clawmont:audit` | What was flagged, and whether the local record is intact |
| `/clawmont:mode` | Show or switch between `monitor` and `enforce` |

---

## Turning on blocking

```
/clawmont:mode enforce
```

- **`monitor`** (default) — inspects and records every tool call, blocks
  nothing.
- **`enforce`** — additionally blocks the high-confidence set. Everything else
  still only warns.

Monitor first is the honest order. Run it for a day on your own repo, look at
`/clawmont:audit`, and turn on blocking once you have seen what it flags on your
actual work. Enforce mode interrupts tool calls, and an interruption you did not
expect costs more trust than it saves.

Mode is stored in `.clawmont/hook-config.json` in your project. The environment
variable `CLAWMONT_CC_MODE=monitor|enforce` overrides it, and
`CLAWMONT_CC_DISABLE=1` turns the hook off entirely without uninstalling.

---

## One thing to do after installing

Add `.clawmont/` to your `.gitignore`.

The audit trail lives there, and it stores a short excerpt of every flagged
call. An excerpt of a call that handled a credential contains credential-shaped
text. The hook redacts before writing, but redaction is a best-effort net over
text the model controls — so the trail should not be one `git add -A` away from
a public repository. `/clawmont:doctor` will tell you if it is not ignored yet.

---

## Honest limits

Read this part. It is the part most security tools leave out.

- **A Claude Code hook fails open by construction.** If the hook crashes, times
  out, or cannot load its detection engine, the tool call proceeds. That is the
  platform's design, not a setting we can change. It means this is a layer that
  *reduces* risk — it is not a containment boundary, and it should sit alongside
  sandboxing and least-privilege credentials, not replace them.
- **It ships in monitor mode.** Out of the box it is a recorder, not a guard.
  Nothing is blocked until you run `/clawmont:mode enforce`.
- **Detection is partial, and we publish the number.** The engine this plugin
  loads measures **79.2% on a fixed 2,324-vector corpus** and **about 33% on
  novel, never-seen attacks**. The corpus figure is the optimistic one — the
  detectors were iterated against that corpus. The ~33% is the number to plan
  around. Both are measured on the full four-boundary engine; this plugin runs
  it at two of those boundaries, so treat them as an upper bound rather than a
  promise about your session.
- **False positives are real, measured, and the reason blocking is opt-in.**
  Replayed against real developer traffic, `enforce` denies **about one ordinary
  tool call in 31 (~3.25%)** — mostly inline interpreters and heredocs, which is
  to say the shell an agent actually writes. That is why `monitor` ships as the
  default. Tuning a rail to stop attacks and tuning it to stay out of your way
  pull in opposite directions; we publish both numbers rather than whichever one
  flatters us that week. (An earlier "0 of 823" figure was withdrawn on
  2026-07-30 — its corpus was synthetic and did not resemble real work.)
- **The audit trail is hash-chained, not signed.** Tampering is detectable on
  local disk. It is not a cryptographic signature and does not prove anything to
  a third party.
- **No guarantees.** This is best-effort defense-in-depth: a layer that reduces
  risk, not one that removes it. Treat any security claim stronger than that —
  from us or from anyone else — as marketing.

---

## Uninstall

```
/plugin uninstall clawmont-security
```

That is the whole removal. The plugin never writes to your `settings.json`, so
there is nothing of ours left behind in your Claude Code configuration.

Two files it created in your project remain, because they are yours to keep or
delete: `.clawmont/audit.jsonl` (the record of what was flagged) and
`.clawmont/hook-config.json` (your mode setting).

---

## Requirements

- **Node.js 22 or newer**, available as `node` on your `PATH`. Claude Code runs
  the hook with it. `/clawmont:doctor` will tell you if it is not usable.
- macOS, Linux, or Windows.

---

## License & more

Source-available under **BUSL-1.1** — see `LICENSE`. It converts to Apache 2.0
on 2028-05-08. It is not an OSI-approved license, so it is not open source.

More about Clawmont Security: **https://clawmont.com**
