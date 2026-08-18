#!/usr/bin/env node
/**
 * Where is the local security dashboard, and is anything actually listening?
 *
 * The dashboard is real — `packages/plugin/src/dashboard/`, node:http over a
 * node:sqlite event store, bound to 127.0.0.1 — and it is served from INSIDE
 * the OpenClaw gateway process. It has no life of its own: no gateway, no
 * dashboard. That one fact is what makes this file a probe rather than a
 * lookup. The URL was documented for months while nothing shipped a way to
 * ask for it, and the obvious fix — print `http://127.0.0.1:18791` — is worse
 * than shipping nothing, because it sends a person to a dead link and calls
 * that an answer.
 *
 * So the answer is derived in this order, and every step can be the last:
 *
 *   1. Is the gateway plugin installed at all? `~/.openclaw/openclaw.json`,
 *      `plugins.entries['openclaw-secure']`. Most `clawmont-cc` users have
 *      only the Claude Code hook and have never installed the gateway; for
 *      them there is no dashboard, and saying so IS the answer.
 *   2. Is it switched on? `enabled: false` on the entry, or `dashboard: false`
 *      in its config, are deliberate choices — reported as choices, with the
 *      way back, never as faults.
 *   3. Is something answering? A GET of `/api/health` on the configured port
 *      and the four the server retries onto (EADDRINUSE → port+1…port+4, see
 *      `dashboard/server.ts`). "A socket accepted the connection" is NOT the
 *      test: the body has to be the dashboard's own `{ok:true}`. Anything else
 *      holding that port is reported as exactly that, by name.
 *
 * THE RULE THIS FILE EXISTS TO KEEP: a URL is printed only when something
 * answered on it. Every other state names the port and stops. A link a reader
 * can click is a claim that it works.
 *
 * It READS. It starts nothing. Launching a gateway as a side effect of asking
 * where one is would be a background process the user never asked for, spawned
 * by a security tool, out of a slash command. Printing is safe; launching is
 * not.
 *
 * And it never echoes the gateway config. That file sits beside
 * `~/.openclaw/clawmont.json` and carries provider credentials — the hook
 * denies reading it as a tool call. This reads two keys out of it and prints
 * a port.
 *
 * Runnable directly (`node dashboard-status.mjs`), which is how the bundled
 * `/clawmont:dashboard` calls it: `cli.mjs` is deliberately not shipped in the
 * marketplace plugin, so the plugin gets this module verbatim instead of a
 * second copy of the logic. Exit code is 0 only when there is a live URL.
 */

import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Kept in step with `packages/plugin/src/dashboard/server.ts` by hand, because
 * neither the TypeScript source nor the obfuscated dist is on a hook user's
 * machine. Drift here is survivable in one direction only: if the server's
 * retry span ever grows, this probe reports "not running" for a dashboard that
 * moved further than we look — which is a false negative that names a port,
 * not a dead link. The gateway's own `[Clawmont] dashboard ready at …` log
 * line carries the truth, and the not-running message points at it.
 */
const DEFAULT_DASHBOARD_PORT = 18791;
const PORT_RETRY_SPAN = 5;

const PLUGIN_ENTRY_ID = 'openclaw-secure';
const PROBE_TIMEOUT_MS = 1200;

const gatewayConfigPath = () => join(homedir(), '.openclaw', 'openclaw.json');

/**
 * One port, one question: is the Clawmont dashboard on the other end?
 *
 * Three answers, and the middle one is the reason this is not a boolean. A
 * refused connection means nothing is there. A `{ok:true}` body means the
 * dashboard is. Anything else — a 404, HTML, a different service that happens
 * to like this port — is a listener we must not claim as ours.
 */
async function probePort(port) {
  let res;
  try {
    res = await fetch(`http://127.0.0.1:${port}/api/health`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
  } catch {
    return { port, kind: 'silent' };
  }
  try {
    const body = await res.json();
    if (res.ok && body?.ok === true) {
      return { port, kind: 'dashboard', version: typeof body.version === 'string' ? body.version : null };
    }
  } catch {
    /* answered, but not with our health document — foreign, below */
  }
  return { port, kind: 'foreign' };
}

/**
 * The whole question, answered once, as data. `state` is the only field a
 * caller should branch on; everything else is detail for the line it prints.
 */
export async function dashboardStatus({ configPath = gatewayConfigPath() } = {}) {
  const base = { configPath, port: DEFAULT_DASHBOARD_PORT };

  if (!existsSync(configPath)) return { ...base, state: 'not-installed', why: 'no-gateway-config' };

  let cfg;
  try {
    cfg = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch (err) {
    return { ...base, state: 'config-unreadable', detail: err.message };
  }

  const entry = cfg?.plugins?.entries?.[PLUGIN_ENTRY_ID];
  if (!entry || typeof entry !== 'object') {
    return { ...base, state: 'not-installed', why: 'no-plugin-entry' };
  }
  if (entry.enabled === false) return { ...base, state: 'plugin-disabled' };

  const pluginConfig = entry.config && typeof entry.config === 'object' ? entry.config : {};
  const raw = pluginConfig.dashboardPort;
  const port =
    typeof raw === 'number' && Number.isInteger(raw) && raw > 0 && raw < 65536 ? raw : DEFAULT_DASHBOARD_PORT;

  if (pluginConfig.dashboard === false) return { ...base, port, state: 'dashboard-disabled' };

  // In parallel: five sequential 1.2s timeouts would make "not running" — the
  // common answer on a machine that only has the hook — take six seconds.
  const ports = Array.from({ length: PORT_RETRY_SPAN }, (_, i) => port + i).filter((p) => p < 65536);
  const results = await Promise.all(ports.map(probePort));

  const live = results.find((r) => r.kind === 'dashboard');
  if (live) {
    return {
      ...base,
      port,
      state: 'running',
      boundPort: live.port,
      url: `http://127.0.0.1:${live.port}`,
      version: live.version,
    };
  }

  const foreign = results.find((r) => r.kind === 'foreign');
  if (foreign) return { ...base, port, state: 'port-taken', foreignPort: foreign.port };

  return { ...base, port, state: 'not-running' };
}

/**
 * The status as a person reads it: one line of fact, one line of what to do
 * about it. `ok` is true only in the state that has a live URL, so a caller
 * can turn this into an exit code without re-deciding what "fine" means.
 */
export function renderDashboardStatus(status) {
  const { state, port, configPath } = status;

  switch (state) {
    case 'running': {
      const version = status.version ? `plugin ${status.version}, ` : '';
      const lines = [
        `Clawmont dashboard: ${status.url}  (${version}answering now)`,
        'Open it in a browser. Everything it shows was recorded on this machine and stays here.',
      ];
      if (status.boundPort !== port) {
        lines.push(
          `Note: bound to ${status.boundPort}, not the configured ${port} — the gateway retried past a port already in use.`,
        );
      }
      return { ok: true, lines };
    }

    case 'not-running':
      return {
        ok: false,
        lines: [
          `Dashboard is not running — nothing answered on 127.0.0.1:${port} (or the four ports it retries onto).`,
          'It is served by the OpenClaw gateway process, so start that:  openclaw gateway start',
        ],
      };

    case 'port-taken':
      return {
        ok: false,
        lines: [
          `Something is listening on 127.0.0.1:${status.foreignPort}, and it is not the Clawmont dashboard — it did not answer /api/health.`,
          `Free that port and run  openclaw gateway restart, or set plugins.entries.${PLUGIN_ENTRY_ID}.config.dashboardPort in ${configPath}.`,
        ],
      };

    case 'plugin-disabled':
      return {
        ok: false,
        lines: [
          `The ${PLUGIN_ENTRY_ID} plugin is disabled in ${configPath}, so nothing serves the dashboard — and nothing is inspecting the gateway either.`,
          `Turn it back on:  openclaw plugins enable ${PLUGIN_ENTRY_ID} && openclaw gateway restart`,
        ],
      };

    case 'dashboard-disabled':
      return {
        ok: false,
        lines: [
          `The dashboard is switched off for this install (dashboard: false in ${configPath}) — the gateway is still inspecting, it just serves no page.`,
          `Remove that key and run  openclaw gateway restart  to serve it on port ${port}.`,
        ],
      };

    case 'config-unreadable':
      return {
        ok: false,
        lines: [
          `${configPath} could not be read as JSON (${status.detail}), so where the dashboard would live is unknown.`,
          'Fix that file first — the gateway cannot start against it either.',
        ],
      };

    case 'not-installed':
    default:
      return {
        ok: false,
        lines: [
          status.why === 'no-gateway-config'
            ? `No dashboard on this machine: the OpenClaw gateway is not installed (${configPath} does not exist).`
            : `No dashboard on this machine: ${configPath} has no ${PLUGIN_ENTRY_ID} plugin entry.`,
          'The dashboard ships with the gateway plugin. The Claude Code hook records to .clawmont/audit.jsonl instead — `clawmont-cc audit` is the report you have, and it says so when the trail is still empty.',
        ],
      };
  }
}

/** Print it, and exit non-zero for every state that has no live URL. */
export async function runDashboard() {
  const status = await dashboardStatus();
  const { ok, lines } = renderDashboardStatus(status);
  for (const line of lines) console.log(line);
  return ok ? 0 : 1;
}

/** True when this file was invoked directly rather than imported. Both sides
 *  go through realpath: a plugin root under a symlinked path (`/tmp` on macOS
 *  is one) resolves differently on the two, and the difference would silently
 *  turn the bundled command into a no-op. */
const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
})();

if (invokedDirectly) process.exit(await runDashboard());
