# Clawmont for OpenClaw

Public distribution channel for `@clawmont/plugin` release tarballs.

Clawmont is a local-first runtime security plugin for OpenClaw. It checks agent
inputs, tool calls, tool results, and outputs, and records a hash-chained,
tamper-evident audit trail.

## Install

The post-checkout setup wizard supplies a config token. Install the Clawmont
security layer with the token-aware command:

```sh
curl -fsSL https://api.clawmont.com/install.sh | bash -s -- --config <your-token>
```

Running the installer without `--config` installs OpenClaw only and prints the
steps for obtaining a Clawmont token.

## Published benchmark

The [Clawmont AI Agent Runtime Security Benchmark](https://security.clawmont.com/)
reports 0 false positives across 62 clean negatives, 78.7% detection on a fixed
2,324-vector corpus, and 33.11% deterministic detection on fresh, unseen attacks.
These are measured best-effort outcomes, not guaranteed protection. The
[machine-readable benchmark data](https://security.clawmont.com/data/clawmont-security-benchmark.json)
includes the measurement dates, misses, and caveats.

## License

Clawmont is source-available under BUSL-1.1, not open source. The license converts
to Apache 2.0 on 2028-05-08.

## Official links

- [Clawmont AI agent security](https://clawmont.com/agent-security/)
- [MCP security for AI agents](https://clawmont.com/mcp-security/)
- [AI agent runtime security definition](https://clawmont.com/agent-runtime-security/)
- [Security methodology and measured limits](https://clawmont.com/security/)
- [Setup guide](https://clawmont.com/setup/)
