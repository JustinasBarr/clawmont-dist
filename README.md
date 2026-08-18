# Clawmont

Public distribution channel for Clawmont. Two things are served from this repo:

| | What it is | Who it is for |
|---|---|---|
| **`plugins/clawmont-security/`** | The **Claude Code** security plugin | Claude Code users |
| **Releases** (up to `v1.1.8`) | `@clawmont/plugin` tarballs — the security layer for the **OpenClaw** runtime | existing OpenClaw installs |

Clawmont is local-first runtime security for coding agents. It inspects agent
inputs, tool calls, tool results and outputs, and records every decision to a
hash-chained, tamper-evident audit trail on your own disk. Keys and audit data
never leave your machine.

## Claude Code

```sh
npx @clawmont/claude-code
```

It installs in **`monitor` mode** — it watches and records, and blocks nothing
until you turn blocking on. Prove it is actually running:

```sh
npx @clawmont/claude-code doctor
```

That spawns the real hook and requires both a real block and a real allow, because
a check that only proves we block would pass a hook that blocks everything.

**macOS and Linux.** Windows is not supported for the Claude Code hook.

Full documentation: [clawmont.com/claude-code-security](https://clawmont.com/claude-code-security/)

## OpenClaw

The post-checkout setup wizard supplies a config token. Install the Clawmont
security layer with the token-aware command:

```sh
curl -fsSL https://api.clawmont.com/install.sh | bash -s -- --config <your-token>
```

Running the installer without `--config` installs OpenClaw only and prints the
steps for obtaining a Clawmont token.

## Measured behaviour

These are two different products measured by two different instruments. They are
not interchangeable, and neither number describes the other.

**The OpenClaw plugin's detection engine**, against a fixed adversarial corpus
(measured 2026-07-26):

| | |
|---|---|
| Detection rate | **79.2%** of 2,324 vectors |
| On fresh, never-seen attacks | **~33%** — the honest number for anything not already in the corpus |
| False positives | **1 / 65** clean negatives |

**The Claude Code hook** is a separate instrument (measured 2026-07-30 to
2026-08-05):

| | |
|---|---|
| Attack harness | **256/256**, with **28 known bypasses pinned open** — both figures are true and we quote them together |
| False positives when blocking is on | About one ordinary tool call in 31 (**~3.25%**), on one operator's traffic over ~3 days. This is why `monitor` is the default |

The gap between 79.2% and ~33% is the important one, and it is why we publish both.
A fixed corpus measures what the detectors were built against; novel plain-English
attacks are an unbounded space. This is **best-effort defence in depth, not a
guarantee** — and it is **detection, not containment**: there is no sandbox, so if
a detector misses, the tool runs. Run Clawmont above real isolation, not instead
of it.

Clawmont **inspects** four boundaries. Only one of them — the tool call, before it
runs — can stop anything. The other three record.

Method, corpus and misses:
[security.clawmont.com](https://security.clawmont.com/) ·
[machine-readable benchmark data](https://security.clawmont.com/data/clawmont-security-benchmark.json)

## License

Clawmont is source-available under **BUSL-1.1** — you can read every line. It is
not an OSI licence and it is not open source. The licence converts to Apache 2.0
on 2028-05-08.

## Official links

- [Clawmont for Claude Code](https://clawmont.com/claude-code-security/)
- [Clawmont AI agent security](https://clawmont.com/agent-security/)
- [MCP security for AI agents](https://clawmont.com/mcp-security/)
- [AI agent runtime security definition](https://clawmont.com/agent-runtime-security/)
- [Security methodology and measured limits](https://clawmont.com/security/)
- [Setup guide](https://clawmont.com/setup/)
