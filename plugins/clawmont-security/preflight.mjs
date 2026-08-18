#!/usr/bin/env node
/**
 * Does this install actually protect anything?
 *
 * The installer used to answer that question by writing a config file and
 * printing "✓ Clawmont installed". It never once asked the hook to inspect
 * anything. On any machine without this monorepo the detection core was
 * unreachable, every call fell open, and the only visible artifact was that
 * green checkmark — a security product that had been installed, was running,
 * and was inspecting nothing.
 *
 * So the check is behavioural, not structural. It spawns the real hook binary,
 * the same way Claude Code will, feeds it a payload that MUST be denied and one
 * that MUST NOT be, and reads the verdicts. Resolving a path proves the path
 * resolves; only a blocked attack proves the thing works.
 *
 * Runs against a throwaway project dir, so probing never writes to the user's
 * audit trail.
 */

import { mkdtempSync, rmSync, existsSync, readFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';

const SELF_DIR = dirname(fileURLToPath(import.meta.url));
const HOOK = join(SELF_DIR, 'clawmont-hook.mjs');

/**
 * The hook's own "I could not start" sentence, READ FROM THE HOOK.
 *
 * This used to be the literal `/NOT protecting this session/i`, typed here and
 * matched against the hook's output. The hook's headline was rewritten to
 * "Nothing is being recorded this session — Clawmont could not start", and this
 * regex has matched nothing since: `unprotected` was permanently false, so
 * doctor's one branch that says "build the detection core first" could not be
 * reached and every broken-core install got the generic "wrong verdicts"
 * message instead. Nothing failed. It just stopped being true.
 *
 * So it is derived, the same way selftest.mjs derives the product mark, and it
 * THROWS rather than degrading: a sentinel that cannot be found is a check that
 * proves nothing, and a check that proves nothing must not read as a passing one.
 */
const UNPROTECTED_SENTINEL = (() => {
  const decl = /^const UNPROTECTED_HEADLINE =\n\s*'(.+)';$/m.exec(readFileSync(HOOK, 'utf8'));
  if (!decl) {
    throw new Error(
      'preflight: clawmont-hook.mjs no longer declares UNPROTECTED_HEADLINE — '
      + 'the unprotected-core check would silently never fire',
    );
  }
  // Escaped whole: the headline is prose with an em dash in it, and half of it
  // is not a safer match, it is a different one.
  return new RegExp(decl[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
})();

/**
 * Two probes, because either one alone passes for the wrong reason: a hook that
 * denies everything blocks the attack, and a hook that inspects nothing allows
 * the benign command. Only both together distinguish "working" from "broken in
 * one of the two convenient directions".
 *
 * Deliberately a path the guard classifies on SHAPE, so the probe needs no file
 * on disk and behaves identically on every machine.
 */
const ATTACK = {
  label: 'blocks a credential-theft attempt',
  input: { command: `cat ${join(homedir(), '.ssh', 'id_rsa')}` },
  want: 'deny',
};
const BENIGN = {
  label: 'leaves an ordinary command alone',
  input: { command: 'git status --short' },
  want: 'allow',
};

function runHook(input, projectDir) {
  const payload = JSON.stringify({
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    session_id: 'preflight',
    tool_input: input,
  });
  const env = { ...process.env, CLAUDE_PROJECT_DIR: projectDir, CLAWMONT_CC_MODE: 'enforce' };
  // The kill switch would make every probe pass by making the hook do nothing —
  // exactly the state this check exists to detect. Probe with it off.
  delete env.CLAWMONT_CC_DISABLE;

  let stdout = '';
  let stderr = '';
  try {
    stdout = execFileSync(process.execPath, [HOOK], {
      input: payload,
      encoding: 'utf8',
      env,
      timeout: 30_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    stdout = err.stdout ?? '';
    stderr = err.stderr ?? '';
  }

  let parsed = null;
  try {
    parsed = stdout.trim() ? JSON.parse(stdout) : null;
  } catch {
    /* not JSON — treated as no verdict below */
  }
  const decision = parsed?.hookSpecificOutput?.permissionDecision ?? 'allow';
  return { decision, stdout, stderr, systemMessage: parsed?.systemMessage ?? '' };
}

/**
 * @returns {{ok: boolean, checks: Array<{label: string, ok: boolean, detail: string}>,
 *            unprotected: boolean, hookPath: string}}
 */
export function preflight() {
  const checks = [];
  let unprotected = false;

  if (!existsSync(HOOK)) {
    return {
      ok: false,
      unprotected: true,
      hookPath: HOOK,
      checks: [{ label: 'hook binary present', ok: false, detail: `not found at ${HOOK}` }],
    };
  }

  const sandbox = mkdtempSync(join(tmpdir(), 'clawmont-preflight-'));
  try {
    for (const probe of [ATTACK, BENIGN]) {
      const r = runHook(probe.input, sandbox);
      const ok = probe.want === 'deny' ? r.decision === 'deny' : r.decision !== 'deny';
      // The hook says so itself when its core is missing — the loud path.
      if (UNPROTECTED_SENTINEL.test(r.systemMessage) || UNPROTECTED_SENTINEL.test(r.stderr)) {
        unprotected = true;
      }
      checks.push({
        label: probe.label,
        ok,
        detail: ok ? `verdict: ${r.decision}` : `verdict: ${r.decision} (expected ${probe.want})`,
      });
    }
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }

  return { ok: checks.every((c) => c.ok), checks, unprotected, hookPath: HOOK };
}

/**
 * IS IT ALIVE, AND WHEN DID IT LAST DO ANYTHING?
 *
 * `preflight()` above proves the hook WORKS when spawned by hand. It cannot
 * prove Claude Code is still spawning it — the hook can be perfect and
 * unregistered, and that install looks exactly like a quiet one. The two facts
 * that separate them live in the project's own directory:
 *
 *   lastRun   the newest row in `.clawmont/audit.jsonl`. Silence with a fresh
 *             row is a quiet session; silence with a row from Tuesday is a rail
 *             nothing is calling.
 *   faults    lines in `.clawmont/hook-errors.log`. Every failure path appends
 *             exactly one, so the line count IS the count.
 *
 * The push side of the same question is the receipt's fault floor in
 * clawmont-hook.mjs, which speaks when `faults` grows mid-session. This is the
 * pull side: the answer on demand, for the reader who has seen nothing and
 * wants to know whether that is good news.
 *
 * @param {string} projectDir  Where `.clawmont/` lives; defaults to cwd.
 */
export function liveness(projectDir = process.cwd()) {
  const dir = join(projectDir, '.clawmont');
  const out = { trail: false, lastRunMs: null, rows: null, faults: 0, faultsAtMs: null };
  try {
    const trail = join(dir, 'audit.jsonl');
    const st = statSync(trail);
    out.trail = true;
    out.lastRunMs = Date.now() - st.mtimeMs;
    // Counted, not parsed. The question is "has anything been recorded", and a
    // line this cannot parse is still a line something wrote.
    out.rows = readFileSync(trail, 'utf8').split('\n').filter(Boolean).length;
  } catch {
    /* no trail — reported as `trail: false`, which is its own answer */
  }
  try {
    const log = join(dir, 'hook-errors.log');
    out.faults = readFileSync(log, 'utf8').split('\n').filter(Boolean).length;
    out.faultsAtMs = Date.now() - statSync(log).mtimeMs;
  } catch {
    /* no error log is the healthy case */
  }
  return out;
}

/**
 * Where the hook resolved its detection core — asked of the hook, not guessed.
 *
 * `--where` exits non-zero when nothing resolved, which is precisely the case
 * whose output the caller most needs to print. So the exit code is ignored and
 * stdout is read either way.
 */
export function coreReport() {
  const r = spawnSync(process.execPath, [HOOK, '--where'], { encoding: 'utf8', timeout: 30_000 });
  try {
    return JSON.parse(r.stdout);
  } catch {
    return { resolved: false, error: (r.stderr || r.error?.message || 'no output').trim(), candidates: [] };
  }
}
