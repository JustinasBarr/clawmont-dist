#!/usr/bin/env node
/**
 * `clawmont-cc audit` — turn `.clawmont/audit.jsonl` into insights.
 *
 * The audit trail is the only place a user can see what Clawmont did, and it is
 * a hash-chained JSONL file that opens into 18,000 lines of JSON. Useless to a
 * person. This command reads it once, streamed, and produces:
 *
 *   1. a terminal summary (always),
 *   2. a self-contained HTML report with inline-SVG charts, written to the OS
 *      temp dir and opened in the default browser (`--out` / `--no-open`),
 *   3. `--json`: the computed stats object on stdout, nothing else.
 *
 * Rules this file lives by:
 *
 * · ZERO dependencies — node builtins only, same policy as the rest of the
 *   package. The HTML makes no network request of any kind: no CDN, no fonts,
 *   no fetch, and no <script> at all — every chart is static inline SVG.
 * · EVERY ROW-DERIVED STRING IS ESCAPED before it reaches HTML. Excerpts and
 *   summaries are literal attack payloads — a prompt-injection string that made
 *   an agent misbehave is exactly the string most likely to be sitting in
 *   `excerpt`. Row data is only ever rendered as text content, never as an
 *   attribute, URL, or element name, and a CSP meta tag backstops the escaping
 *   by refusing to execute anything anyway.
 * · THE FILE IS STREAMED line by line. 11 MB / 18K rows must not become an
 *   18K-element array of parsed objects; totals accumulate as we go and only
 *   bounded structures (last 20 flagged rows, per-day counters) are kept.
 * · A LINE WE CANNOT PARSE IS COUNTED, NEVER FATAL. The report says how many
 *   lines were skipped; the chain check below reports the same file as broken,
 *   because the verifier — correctly — refuses to vouch for it.
 * · CHAIN VERIFICATION IS NOT RE-DERIVED. `clawmont-hook.mjs --verify` is the
 *   one implementation of the chain walk (including the length anchor), so this
 *   command spawns exactly that and relays its verdict. A second copy of the
 *   algorithm is how the harness diverged from prod last time.
 * · ONE FILE IS WRITTEN INTO `.clawmont/` AS A MATTER OF COURSE: `audit.html`,
 *   the report kept beside the trail. Everything else there stays untouched, the
 *   evidence stays append-only, and other reports go to `os.tmpdir()`.
 *
 *   There is exactly one other write, and it is narrow enough to state in full:
 *   `reconcilePause()` restores `.clawmont/hook-config.json` to `enforce` once a
 *   human's `clawmont-cc pause` has expired. It only ever RAISES protection, it
 *   never writes any other value, and every failure is a silent no-op — see the
 *   function for the argument. Nothing else in this file touches that file.
 *
 *   That sibling exists because of one sentence of founder feedback — *"still
 *   clicking on audit.jsonl opens just array not the dashboard"*. An editor
 *   renders `.jsonl` as text and always will; the click belongs to the OS. So
 *   the honest fix is not to intercept the click but to put a file in the same
 *   folder whose click DOES open the dashboard. It is written by us and by the
 *   hook — never by the agent: `.clawmont/audit.html` is guarded exactly like
 *   the trail (clawmont-hook.mjs, AUDIT_PATH_RE), because a user-facing report
 *   an injected agent can rewrite is a forgery surface, not a report.
 */

import {
  createReadStream, existsSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, mkdtempSync,
  rmSync, lstatSync, statSync, renameSync, unlinkSync,
} from 'node:fs';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';
import { join, dirname, resolve, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

/**
 * WHY THIS FILE IMPORTS NOTHING OF OURS.
 *
 * `scripts/build-plugin-package.mjs` mirrors exactly three files into the plugin
 * bundle — the hook, `preflight.mjs`, and this one — and it says why in its own
 * comment: they "import nothing but node builtins and their sibling hook, so
 * they copy cleanly". `allowlist.mjs` is NOT mirrored. A static import of it
 * here would therefore load fine in the monorepo and in the npm package, and
 * throw on module load for every bundle customer — taking the Stop-triggered
 * sibling report down with it, on the one channel nobody tests by hand.
 *
 * So the two functions this file needs are MIRRORED, and the mirror is checked
 * rather than trusted: `controls.selftest.mjs` asserts these produce byte-
 * identical output to `allowlist.mjs` across a corpus that includes the cases
 * the two would most plausibly disagree on. That is the same
 * checked-duplication the rest of this package uses for exactly this reason,
 * and it is the pattern that keeps a silent divergence — a number that resolves
 * to a grant that never matches — from being possible.
 *
 * If they ever diverge the test fails; it cannot fail quietly.
 */
export function canonicalize(command) {
  return String(command ?? '').trim().replace(/\s+/g, ' ');
}
export function fingerprint(command) {
  return createHash('sha256').update(canonicalize(command), 'utf8').digest('hex');
}

/**
 * The grant store, loaded only if it is there to load.
 *
 * Dynamic and guarded for the reason the hook guards its own import of this
 * module: a missing `allowlist.mjs` must degrade to "we cannot show the grants"
 * and never to "the report crashed". Null means the module is absent — which is
 * a different fact from "there are no grants", and the page says so by omitting
 * the panel rather than claiming emptiness it cannot vouch for.
 */
let GRANT_MOD;
async function grantModule() {
  if (GRANT_MOD !== undefined) return GRANT_MOD;
  try {
    GRANT_MOD = await import('./allowlist.mjs');
  } catch {
    GRANT_MOD = null;
  }
  return GRANT_MOD;
}

const SELF_DIR = dirname(fileURLToPath(import.meta.url));
const HOOK_PATH = join(SELF_DIR, 'clawmont-hook.mjs');

/** Same resolution as the hook: the project is the cwd unless Claude Code says otherwise. */
export function defaultAuditPath() {
  return join(process.env.CLAUDE_PROJECT_DIR ?? process.cwd(), '.clawmont', 'audit.jsonl');
}

/** Bounded structures: the report keeps insights, not records. */
const RECENT_LIMIT = 20;
const EXCERPT_MAX = 160;
const CHART_MAX_DAYS = 90;
const CATEGORY_MAX_ROWS = 25;
const KEY_MAX = 60;

const FLAGGED = new Set(['warn', 'deny']);

// ---------------------------------------------------------------------------
// THE WINDOW — what "recently" means, and why the report has one at all
// ---------------------------------------------------------------------------
//
// This report had no time flag of any kind, so it was all-time cumulative. On a
// trail that records ~1,100 calls a day that is a page which looks the same
// every morning: the numbers only ever grow, nothing is ever resolved, and the
// second week's report is indistinguishable from the first. A report nobody can
// tell apart from yesterday's is a report nobody opens.
//
// So the default is a TRAILING WINDOW and the window is NAMED wherever a number
// derived from it is printed. Precedent, in this repo and outside it:
//
//   · `ux-score.mjs --gate` already scores a trailing 7 days, states the
//     boundary on its own output line, and reports "N of M rows". Everything
//     below deliberately mirrors that vocabulary — the same reader reads both.
//   · Apple's App Privacy Report is a rolling 7-day on-device window.
//     Cloudflare's DDoS report is a fixed Mon–Sun week. Sentry leads with
//     week-over-week deltas. All three chose a window over a running total.
//
// Two properties keep the window from becoming a way to hide things:
//
//   · IT IS ALWAYS STATED. Never a bare count. Every surface that prints a
//     windowed number prints the window beside it and the way to widen it.
//   · IT IS NEVER THE FALLBACK FOR CONFUSION. An unparseable `--since` is an
//     error, not a silent default. Snyk's documented footgun is a malformed
//     expiry that silently becomes permanent; the same shape here would be a
//     mistyped window silently becoming a narrower one.
//
// The CHAIN VERDICT is deliberately outside the window: it is a statement about
// the whole file, and a windowed integrity claim would be a weaker sentence
// wearing the same words. `verifyChainStatus` always reads everything.

/** Trailing days the report shows when nobody said otherwise. */
export const DEFAULT_WINDOW_SPEC = '7d';

/** The spelling that turns the window off. */
export const WINDOW_ALL = 'all';

const SINCE_RE = /^(\d+(?:\.\d+)?)\s*(h|hr|hrs|hour|hours|d|day|days)$/i;
const SINCE_DATE_RE = /^\d{4}-\d{2}-\d{2}([T ][\d:.]+Z?)?$/;

/**
 * `7d` · `24h` · `30d` · `2026-08-10` · `all` → the boundary, in words and in ISO.
 *
 * Returns `{ ok, since, label, spec, reason }`. `since` is null for all-time.
 * Compared as ISO strings downstream rather than parsed dates: `auditAppend`
 * writes `new Date().toISOString()`, which is fixed-width and UTC, so lexical
 * order is chronological order and a bare `YYYY-MM-DD` is a clean UTC midnight.
 * Same comparison `ux-score.mjs` makes, for the same reason.
 */
export function parseSince(text, now = Date.now()) {
  const raw = String(text ?? '').trim();
  if (!raw) return { ok: true, since: null, label: 'all time', spec: WINDOW_ALL, reason: '' };
  const lower = raw.toLowerCase();
  if (lower === WINDOW_ALL || lower === 'always' || lower === 'everything') {
    return { ok: true, since: null, label: 'all time', spec: WINDOW_ALL, reason: '' };
  }
  const rel = SINCE_RE.exec(lower);
  if (rel) {
    const n = Number(rel[1]);
    if (!Number.isFinite(n) || n <= 0) {
      return { ok: false, since: null, label: '', spec: raw, reason: `"${raw}" is not a length of time` };
    }
    const hours = /^h/.test(rel[2]) ? n : n * 24;
    const since = new Date(now - hours * 3600_000).toISOString();
    const label = /^h/.test(rel[2])
      ? `the last ${n} ${n === 1 ? 'hour' : 'hours'}`
      : `the last ${n} ${n === 1 ? 'day' : 'days'}`;
    return { ok: true, since, label, spec: lower, reason: '' };
  }
  if (SINCE_DATE_RE.test(raw)) {
    const since = raw.replace(' ', 'T');
    return { ok: true, since, label: `since ${raw.slice(0, 10)}`, spec: raw, reason: '' };
  }
  return {
    ok: false,
    since: null,
    label: '',
    spec: raw,
    reason: `"${raw}" is not a window — use 7d, 24h, 30d, a YYYY-MM-DD date, or all`,
  };
}

/** The window a report was built over, as one sentence a reader can check. */
export function windowLine(stats) {
  const w = stats.window;
  if (!w) return '';
  const seen = `${nf(stats.totalEvents)} of ${nf(w.total)} recorded ${w.total === 1 ? 'row' : 'rows'}`;
  if (!w.since) return `all time · ${seen}`;
  return `${w.label} · ${seen}`;
}

/** The way out of the window, printed wherever the window is. Never implied. */
export const WINDOW_HINT = 'clawmont-cc audit --since all shows everything; --since 30d widens it.';

// ---------------------------------------------------------------------------
// FINDING IDS — the number a person types instead of a command
// ---------------------------------------------------------------------------
//
// THE PROBLEM. To lift a false block today a user must type:
//
//     clawmont-cc allow "<the exact command that was blocked>" --reason <key>
//
// which asks them to reproduce command text byte for byte, quote it correctly
// for their shell, and know a reason key. Every one of those three is a way to
// get a grant that silently never matches — the hook says so itself at
// `overrideHint`. The fix is that the report NUMBERS what it shows and the user
// types the number: `clawmont-cc allow 3`.
//
// THE SCHEME, and why it is not the other two.
//
// An id is the ORDINAL OF FIRST APPEARANCE, among flagged rows, of a distinct
// (subject fingerprint, reason) pair in the trail. The first such pair the trail
// ever recorded is #1, the second is #2, and a pair keeps its number for as long
// as the trail exists.
//
//   · Rejected — POSITION IN A RECENT-N LIST (#1 = newest). It renumbers under
//     the reader: the agent appends one row while the page is open and #3 is now
//     a different finding than the one they read. A user typing a number off a
//     page that renumbered is worse than the friction we set out to remove,
//     because the failure is silent and lands on the wrong subject.
//   · Rejected — A SHORT HASH OF THE ROW (`allow f3a9`). Stable, but it is not a
//     number a person reads off a screen and types, which was the whole request,
//     and a short hash needs collision handling that a long one does not.
//   · Rejected — A SIDECAR INDEX FILE mapping id → finding. It is a new file in
//     `.clawmont/` that decides what a human's grant means, which makes it a
//     forgery target that the hook's control-plane guard does not yet cover.
//
// WHY THE ORDINAL IS STABLE, stated as the property it actually depends on: the
// trail is APPEND-ONLY and hash-chained. A fixed prefix of the stream therefore
// yields a fixed answer, so appending rows can only ever hand out HIGHER ids. No
// existing id changes and none is reused. That is exactly the window the grant
// flow needs — read a number off the page, type it into a terminal — and it
// holds even if the agent is still running while the human reads.
//
// The two boundaries, stated rather than hidden:
//   · `clawmont-cc archive` rotates the trail away, and numbering restarts at 1.
//     That is a deliberate human act, it prints what it did, and a grant already
//     made is unaffected — grants are keyed on (fingerprint, reason), never on
//     the id. The id is a handle for typing, not the thing that is stored.
//   · An EDITED trail could renumber. It would also break the hash chain, which
//     this report already reports as the loudest thing on the page.
const FINDING_KEY_CAP = 50_000;

/**
 * `PUBLIC_REASONS` inverted — the audit row's `summary` back to the reason key.
 *
 * The trail records `category` and `summary`, never `reason`, and the two are
 * NOT the same field: `scanReply` writes `category: 'secret_exposure'` with
 * `reason: 'secret_in_reply'`. The allowlist matches on the reason, so keying a
 * grant off `category` would produce a grant for a finding that never fires.
 * `summary` is `publicReason(reason)` and the table's values are unique, so the
 * inversion is exact.
 *
 * Duplicated from the hook rather than imported, for the reason `override-cli.mjs`
 * duplicates `GRANTABLE_REASONS`: importing `clawmont-hook.mjs` executes it.
 * `audit-report.selftest.mjs` parses the hook's table and asserts this one
 * matches it exactly, so the duplication is checked rather than trusted.
 */
export const PUBLIC_REASON_TO_KEY = new Map([
  ['access to a protected credential path', 'protected_path'],
  ['write to a sensitive file path', 'protected_path_write'],
  ['dangerous command shape', 'dangerous_command'],
  ['credential material detected', 'secret_exposure'],
  ['credential material in written content', 'secret_in_content'],
  ['credential material in a template/example file (advisory)', 'secret_in_content_template'],
  ['credential material in tool output', 'secret_in_output'],
  ['credential material in the submitted prompt', 'secret_in_prompt'],
  ['credential material in the model reply', 'secret_in_reply'],
  ['prompt-injection signal', 'prompt_injection'],
  ['prompt-injection signal in tool output', 'prompt_injection_output'],
  ['prompt-injection signal in the submitted prompt', 'prompt_injection_prompt'],
  ['the reply moves data toward a destination outside this machine', 'exfiltration_in_reply'],
  ['write targets an executable configuration path', 'config_write'],
  ['written content embeds a remote-fetch gadget', 'config_write_gadget'],
  ['tool input exceeds the inspection size limit', 'oversized_input'],
  ['the command is too large to inspect — this call was NOT examined', 'uninspected_input'],
  ['inspection did not finish — this call was only PARTLY examined', 'inspection_incomplete'],
  ['inspection hit its time backstop — this call was only PARTLY examined', 'inspection_backstop'],
  ['detection core could not be loaded — this call was NOT inspected', 'detector_core_unavailable'],
  ['an attempt to grant a Clawmont override from inside the agent', 'override_self_grant'],
  ['an attempt to change the Clawmont enforcement settings from inside the agent', 'security_control_write'],
  ['an attempt to alter or suppress the Clawmont audit record from inside the agent', 'security_audit_write'],
  ['an attempt to switch Clawmont off by running its own installer, CLI or kill switch', 'security_control_disarm'],
]);

/**
 * Findings a grant may never cover, duplicated from `override-cli.mjs` for the
 * same checked-duplication reason. The numbered path must refuse exactly the
 * same set the typed path refuses — a convenience that quietly widened the
 * grantable set would be a bypass wearing a number.
 */
export const NON_GRANTABLE = new Set([
  'inspection_incomplete', 'inspection_backstop', 'detector_core_unavailable',
  'uninspected_input', 'override_self_grant', 'security_control_write',
  'security_audit_write', 'security_control_disarm',
]);

/** The hook's own rule for "this text is safe to hand back as a grant key". */
const SECRET_BEARING_REASONS = /^secret_|_secret/;
const OVERRIDE_HINT_MAX_CHARS = 160; // == clawmont-hook.mjs OVERRIDE_HINT_MAX_CHARS

/** Every reason key the hook can emit. A grant may name one of these and nothing else. */
export const KNOWN_REASONS = new Set(PUBLIC_REASON_TO_KEY.values());

/**
 * The reason key a row is about. `summary` first (exact), `category` as the floor.
 *
 * The floor is SANITISED, not trusted. `category` is a row field, which on a
 * foreign or tampered trail is an attacker's string, and this value is printed
 * unescaped into the terminal summary — a category carrying `\n  chain  …` or an
 * ANSI sequence would forge a chain verdict or clear the screen. That defect is
 * exactly what the terminal-injection suite exists to catch, and it caught this
 * one. Control characters go, length is capped, and anything that is not
 * reason-key-shaped is reported as unknown rather than passed through.
 */
export function rowReason(row) {
  const fromSummary = typeof row?.summary === 'string' ? PUBLIC_REASON_TO_KEY.get(row.summary) : null;
  if (fromSummary) return fromSummary;
  const cat = cleanKey(row?.category, '');
  return cat || null;
}

/**
 * May `clawmont-cc allow <id>` turn this row into a grant?
 *
 * The answer has to be NO whenever the grant would not actually match at
 * enforcement time, because a grant that silently does nothing is the single
 * failure this whole feature exists to remove. Four gates, each closing a
 * concrete way the recorded subject differs from the text the hook will
 * fingerprint:
 *
 *  1. ROUTE. The hook consults the allowlist only on `command` (its key is
 *     `scanned`, which is what the row's subject is). `write` has a path, not a
 *     command. `generic+command` keys on `commandArgument(input)` while the row's
 *     subject is the whole JSON payload — a different string, so a grant built
 *     from the subject would never fire.
 *  2. TRUNCATION AND REDACTION. `excerpt` is `redactSecrets(...).slice(0, 300)`.
 *     `bytes` is the length of the text that was actually scanned, so
 *     `bytes === excerpt.length` is the cheap proof that neither happened. The
 *     length cap is the hook's own 160, so the numbered path is never more
 *     permissive than the command the block message already prints.
 *  3. CREDENTIAL MATERIAL. Same rule as `overrideHint`: on a secret-bearing
 *     reason the text is described, never reproduced. It is also the case where
 *     a same-length redaction could defeat gate 2.
 *  4. NON-GRANTABLE. "We did not look" and "the agent reached for Clawmont
 *     itself" are not judgements to overrule, by number or by any other route.
 *
 * Every gate fails toward refusal, and the refusal names what to do instead.
 */
export function grantability(entry) {
  if (!entry.reason) return { grantable: false, why: 'this row records no finding to grant' };
  // A reason the hook cannot emit is a reason no grant can ever match, so the
  // number must not offer to create one. This also means a tampered `category`
  // cannot invent a grantable finding out of a string it chose.
  if (!KNOWN_REASONS.has(entry.reason)) {
    return { grantable: false, why: 'this row names a finding Clawmont does not recognise' };
  }
  if (NON_GRANTABLE.has(entry.reason)) {
    return { grantable: false, why: `${entry.reason} can never be overridden`, nonGrantable: true };
  }
  if (entry.route !== 'command') {
    return {
      grantable: false,
      why: entry.route === 'write'
        ? 'a write target has no command text for a grant to key on'
        : `the ${entry.route || 'unknown'} route records a payload, not the command a grant is keyed to`,
    };
  }
  if (SECRET_BEARING_REASONS.test(entry.reason)) {
    return { grantable: false, why: 'the recorded text is redacted because it carries credential material' };
  }
  if (!Number.isFinite(entry.bytes) || entry.bytes !== entry.subject.length) {
    return { grantable: false, why: 'the recorded text was shortened or redacted, so it is not the command the hook will match' };
  }
  if (entry.subject.length > OVERRIDE_HINT_MAX_CHARS) {
    return { grantable: false, why: `the command is longer than ${OVERRIDE_HINT_MAX_CHARS} characters` };
  }
  if (/[\n\r]/.test(entry.subject)) {
    return { grantable: false, why: 'the command spans more than one line' };
  }
  return { grantable: true, why: '' };
}

/** The finding a flagged row is about, or null when the row cannot carry one. */
function findingFrom(row) {
  const subject = typeof row?.excerpt === 'string' ? row.excerpt : '';
  const reason = rowReason(row);
  if (!subject.trim() || !reason) return null;
  return {
    reason,
    // `subject` is RAW because it is what a grant is fingerprinted over — cleaning
    // it would produce a grant that never matches. `display` is the same string
    // made safe to print, and it is the only one any surface may render.
    subject,
    display: cleanText(subject, 200),
    fingerprint: fingerprint(subject),
    // Sanitised for the same reason `reason` is: `route` is interpolated into
    // the refusal sentence that `grantability` prints to a terminal.
    route: cleanKey(row.route, ''),
    bytes: typeof row.bytes === 'number' ? row.bytes : NaN,
  };
}

/** One id per (subject, reason) pair. The pair, spelled out, is the key. */
// The separator is written as an ESCAPE, never as a literal NUL byte. A raw
// NUL makes grep classify this whole file as binary, and every grep-based
// gate over it then passes vacuously on an empty match set - the exact
// defect fixed in clawmont-hook.mjs (58eb81bf) and pinned by selftest.mjs.
const findingKey = (f) => `${f.fingerprint}\u0000${f.reason}`;

/** How many numbered findings the report itself renders. Bounded like everything else. */
const ACTION_LIMIT = 12;

/**
 * How many `clawmont-cc review` will carry. Larger than the report's list on
 * purpose — the report is a glance and the review is a sitting — and still
 * bounded, because "keep every distinct finding a 20,000-row trail ever saw" is
 * the one structure this file has always refused to build.
 */
export const REVIEW_LIMIT = 50;

// ---------------------------------------------------------------------------
// WHY THE HUMAN GAVE — a closed vocabulary, with the deferral costing something
// ---------------------------------------------------------------------------
//
// `GRANTABLE_REASONS` is a list of DETECTOR finding types: it records what the
// hook thought, and there was nowhere for the person to say what THEY think.
// That gap is not cosmetic. On this repository's own trail, 689 of 2,519 unique
// flags were correct-but-expected security-development work — literally attack
// fixtures being edited — and every one of them looked, in the record, exactly
// like an unresolved finding.
//
// The design is GitHub push protection's, which is the best of the ones
// surveyed, and the load-bearing part of it is the ASYMMETRY:
//
//     "It's used in tests"     closes quietly
//     "It's a false positive"  closes quietly
//     "I'll fix it later"      STAYS OPEN and keeps notifying
//
// The honest answers are the cheap ones and the deferral is the expensive one,
// so the incentive runs toward telling the truth. GitGuardian ships
// `test_credential` as a first-class reason for the same purpose.
//
// This is a note ON a grant, never a route around one: it changes what the
// report SHOWS, not what the hook allows. A grant with `--because later` still
// only covers the one subject and the one finding it always covered, still
// expires, and is still refused for every non-grantable reason.
export const GRANT_BECAUSE = new Map([
  ['test-fixture', {
    label: 'used in tests',
    quiet: true,
    note: 'the subject is test material — the finding closes quietly',
  }],
  ['false-positive', {
    label: 'a false positive',
    quiet: true,
    note: 'the detector was wrong here — the finding closes quietly',
  }],
  ['later', {
    label: 'to be fixed later',
    quiet: false,
    note: 'deferred, not resolved — this finding keeps being shown until it is',
  }],
]);

/** Is this grant one that closes its finding quietly? Absent `because` behaves as today. */
export const grantIsQuiet = (g) => GRANT_BECAUSE.get(g?.because)?.quiet !== false;

/** Has a one-shot grant already been used? A spent grant is not permission. */
export const grantIsSpent = (g) => Boolean(g?.once && g?.spentAt);

/**
 * A grouping key taken from a row — sanitised two ways at once.
 *
 *  1. Control characters (C0 incl. ESC and newline, DEL, C1) are stripped.
 *     These keys are printed UNescaped in the terminal summary, so a `category`
 *     or `tool` carrying `\n` or an ANSI sequence could otherwise forge summary
 *     lines — including a fake chain verdict — or clear the screen. A row field
 *     is attacker-influenced (a tool name, a foreign trail), so this is load-
 *     bearing, not cosmetic.
 *  2. Length is capped, so a 400-char category cannot stretch a table cell or a
 *     legend unbounded.
 *
 * Prototype-name keys (`__proto__`, `constructor`, `toString`) are handled
 * separately, by every accumulator being a null-prototype object — see
 * `computeStats`. Without that, `tool:"constructor"` alone turned a counter
 * into a function and NaN-ed the whole tool chart.
 */
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g;
const cleanKey = (v, fallback) => {
  const s = String(v ?? '').replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim().slice(0, KEY_MAX);
  return s || fallback;
};

/** A row-derived string for the terminal, where nothing is escaped downstream. */
const cleanText = (v, max = EXCERPT_MAX) =>
  String(v ?? '').replace(CONTROL_CHARS, ' ').slice(0, max);

/**
 * One pass over the file, streamed. Returns the stats object that every other
 * function renders from — the `--json` output is exactly this plus the chain
 * verdict.
 */
export async function computeStats(file, {
  wantId = null,
  since = null,
  windowLabel = '',
  windowSpec = WINDOW_ALL,
  grants = null,
  actionLimit = ACTION_LIMIT,
} = {}) {
  // Every accumulator is a NULL-PROTOTYPE object. A row field is an attacker's
  // string, and on a plain `{}` the keys `__proto__`, `constructor` and
  // `toString` collide with inherited members: `tool:"constructor"` turned a
  // counter into the Object function (NaN-ing the whole chart) and
  // `category:"__proto__"` both swallowed its own row and mutated
  // Object.prototype process-wide. `Object.create(null)` has no such members,
  // so every key is an ordinary data property.
  const stats = {
    file: resolve(file),
    totalEvents: 0,
    malformed: 0,
    range: { first: null, last: null },
    sessions: 0,
    modes: Object.create(null),
    decisions: Object.create(null),
    events: Object.create(null),
    categories: Object.create(null),   // category -> { warn, deny }
    severities: Object.create(null),   // severity -> count, flagged rows only
    toolsFlagged: Object.create(null), // tool -> warn+deny count
    perDay: [],       // [{ day, allow, warn, deny, other }] sorted by day
    lastMode: null,
    recent: [],       // last RECENT_LIMIT flagged rows, truncated fields only
    // The numbered findings this report offers as actions: the ACTION_LIMIT most
    // recently seen distinct (subject, reason) pairs, each carrying the id it was
    // assigned on first appearance. Bounded like every other structure here.
    actions: [],
    findingCount: 0,  // distinct pairs the trail has ever recorded
    idsCapped: false, // the trail carries more distinct pairs than we will number
    wanted: null,     // the entry `wantId` asked for, found at any depth
    // The window this pass was taken over, and everything it left out — so the
    // report can never print a smaller number without printing why.
    window: {
      since,
      label: windowLabel || (since ? 'a window' : 'all time'),
      spec: windowSpec,
      total: 0,    // rows read, in and out of the window alike
      before: 0,   // rows older than the boundary
      undated: 0,  // rows carrying no usable timestamp, which no window can place
    },
    // Calls the live grants covered, keyed by grant id. This is the record NOT
    // shrinking as the allowlist grows: everything below makes suppression
    // easier, and this is the structure that keeps it visible.
    covered: Object.create(null),
    coveredCalls: 0,   // total calls in the window a live grant covered
    overriddenCalls: 0, // rows the hook itself recorded as overridden at the time
  };

  // fingerprint\0reason -> the live grant covering it. Bounded by the number of
  // grants a human has made, which is the smallest structure in this file.
  const grantByKey = new Map();
  for (const g of grants ?? []) {
    if (g && typeof g.fingerprint === 'string' && typeof g.reason === 'string') {
      grantByKey.set(findingKey(g), g);
    }
  }

  const sessions = new Set();
  const perDay = new Map();
  const bump = (obj, key) => { obj[key] = (obj[key] ?? 0) + 1; };
  // key -> id, in first-appearance order. See the FINDING IDS block above for
  // why this is an ordinal over the append-only trail rather than a position in
  // a list that would renumber under the reader.
  const idByKey = new Map();
  // id -> its most recent occurrence, in recency order. A Map preserves
  // insertion order, so re-inserting on every sighting and dropping the head
  // past ACTION_LIMIT keeps this at a dozen entries however long the trail is.
  const seenById = new Map();

  const rl = createInterface({ input: createReadStream(file, 'utf8'), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let e;
    try {
      e = JSON.parse(line);
    } catch {
      stats.malformed++;
      continue;
    }
    if (e === null || typeof e !== 'object' || Array.isArray(e)) {
      stats.malformed++;
      continue;
    }

    stats.window.total++;
    const ts = typeof e.ts === 'string' ? e.ts : null;

    // THE WINDOW. A row outside it is TALLIED, never silently dropped: the
    // counts below are smaller than the file, and every surface that prints
    // them says by how much.
    //
    // An undated row is excluded rather than kept, on the same reasoning
    // `ux-score.mjs windowRows` gives: no window can honestly place a row it
    // cannot date, and keeping it would make a windowed count quietly include
    // rows from outside the window.
    let inWindow = true;
    if (since) {
      if (!ts) { stats.window.undated++; inWindow = false; }
      else if (ts < since) { stats.window.before++; inWindow = false; }
    }

    // Grouping keys are sanitised (control chars stripped, length capped) so a
    // hostile `mode`/`tool`/`category` cannot forge a terminal line. `decision`
    // drives control flow, so it is matched against the known vocabulary rather
    // than trusted as a label.
    const mode = cleanKey(e.mode, 'unknown');
    const decisionRaw = typeof e.decision === 'string' ? e.decision : '';
    const decision = ['allow', 'warn', 'deny', 'unprotected'].includes(decisionRaw) ? decisionRaw : cleanKey(decisionRaw, 'unknown');
    const category = cleanKey(e.category, 'uncategorised');

    /**
     * THE ID IS ASSIGNED OVER THE WHOLE TRAIL, NEVER OVER THE WINDOW.
     *
     * This is the one part of the pass a window may not touch, and it is worth
     * being explicit about why. An id is the ordinal of first appearance of a
     * (subject, reason) pair over the append-only trail — see the FINDING IDS
     * block above. If the window decided which rows got numbered, then
     * `clawmont-cc audit --since 7d` would print #3 for one finding while
     * `clawmont-cc allow 3` — which resolves over the whole trail, because a
     * grant is not a windowed thing — landed on another. A number pointing at
     * something other than what the reader read is the single failure the whole
     * numbered-control design exists to remove, and a window is not worth
     * reintroducing it for.
     *
     * So: the counter runs over every flagged row in the file. Only the
     * DISPLAY below is windowed.
     */
    let id = null;
    let slot = null;
    let f = null;
    if (FLAGGED.has(decision)) {
      // `e.excerpt` is used raw here on purpose: `cleanText` replaces control
      // characters with spaces, and a fingerprint taken over the cleaned string
      // would not match the text the hook scans. Everything rendered downstream
      // is cleaned separately.
      f = findingFrom(e);
      if (f) {
        const key = findingKey(f);
        slot = idByKey.get(key) ?? null;
        if (!slot) {
          if (idByKey.size >= FINDING_KEY_CAP) stats.idsCapped = true;
          else {
            slot = { id: idByKey.size + 1, n: 0, w: 0 };
            idByKey.set(key, slot);
          }
        }
        if (slot) {
          slot.n++;
          if (inWindow) slot.w++;
          id = slot.id;
        }
      }
    }

    // An id asked for by name is resolved at any depth AND outside the window:
    // `clawmont-cc allow <id>` is about a finding, not about a week.
    if (slot && wantId !== null && id === wantId) {
      stats.wanted = {
        id,
        reason: f.reason,
        subject: f.subject,
        display: f.display,
        fingerprint: f.fingerprint,
        route: f.route,
        bytes: f.bytes,
        category,
        decision,
        tool: cleanKey(e.tool, 'unknown'),
        lastTs: cleanText(ts ?? '', 32),
        count: slot.n,
      };
    }

    if (!inWindow) continue;

    stats.totalEvents++;
    if (ts) {
      if (!stats.range.first || ts < stats.range.first) stats.range.first = ts;
      if (!stats.range.last || ts > stats.range.last) stats.range.last = ts;
    }
    if (typeof e.session === 'string' && e.session) sessions.add(e.session);

    const event = cleanKey(e.event, 'unknown');
    bump(stats.modes, mode);
    bump(stats.decisions, decision);
    bump(stats.events, event);
    stats.lastMode = mode;

    const day = ts && /^\d{4}-\d{2}-\d{2}/.test(ts) ? ts.slice(0, 10) : null;
    if (day) {
      const d = perDay.get(day) ?? { allow: 0, warn: 0, deny: 0, other: 0 };
      d[decision === 'allow' || decision === 'warn' || decision === 'deny' ? decision : 'other']++;
      perDay.set(day, d);
    }

    if (FLAGGED.has(decision)) {
      const c = stats.categories[category] ?? { warn: 0, deny: 0 };
      c[decision]++;
      stats.categories[category] = c;
      // Per-row severity is kept as raw data for `--json` — it is what the trail
      // literally says. It is NEVER aggregated into a rendered figure: see the
      // note above `actionsTaken` for why a severity total is the one number
      // this report may not print.
      bump(stats.severities, cleanKey(e.severity, 'unspecified'));
      bump(stats.toolsFlagged, cleanKey(e.tool, 'unknown'));

      // A call the hook itself let through on a human's authority, as the row
      // recorded it at the time. Counted separately from the coverage below,
      // because this one is a fact about what happened and that one is a fact
      // about what the allowlist says now.
      if (e.overridden === true) stats.overriddenCalls++;

      if (f && slot) {
        // WHAT A GRANT IS COVERING, in calls rather than in principle.
        //
        // ClawSec keeps suppressed findings in the report under an
        // informational section, excluded from the totals but never from the
        // page; Semgrep still generates an ignored finding and moves it to the
        // Ignored state. Same rule here, and it is the property that makes
        // every other control in this file safe to use: the numbered grant, the
        // one-shot, the reason and the review sitting all make suppression
        // cheaper, and this is what stops the record shrinking as they are used.
        //
        // COUNTED WHETHER OR NOT THE GRANT IS STILL LIVE. A spent one-shot has
        // stopped being permission and has NOT stopped having covered a call —
        // and dropping its count the moment it is spent would make the record
        // shrink at exactly the moment something was let through, which is the
        // failure this whole section exists to prevent. Liveness decides whether
        // a finding is CLOSED (see `settle`); it does not decide whether history
        // happened.
        //
        // ONLY CALLS THE GRANT COULD HAVE COVERED. Matching is on (subject,
        // finding), which the same command matched before the grant existed
        // too — counting those would attribute a block to a permission that did
        // not exist yet, and inflate the number in the direction that flatters
        // the allowlist. The boundary is the grant's own timestamp.
        const covering = grantByKey.get(findingKey(f));
        if (covering && (!covering.grantedAt || (ts && ts >= covering.grantedAt))) {
          const cv = stats.covered[covering.id] ?? {
            grantId: covering.id,
            findingId: id,
            reason: f.reason,
            display: f.display,
            because: typeof covering.because === 'string' ? covering.because : '',
            once: Boolean(covering.once),
            spent: grantIsSpent(covering),
            calls: 0,
            denied: 0,
            lastTs: '',
          };
          cv.calls++;
          if (decision === 'deny') cv.denied++;
          cv.lastTs = cleanText(ts ?? cv.lastTs, 32);
          stats.covered[covering.id] = cv;
          stats.coveredCalls++;
        }

        const entry = {
          id,
          reason: f.reason,
          subject: f.subject,
          display: f.display,
          fingerprint: f.fingerprint,
          route: f.route,
          bytes: f.bytes,
          category,
          decision,
          tool: cleanKey(e.tool, 'unknown'),
          lastTs: cleanText(ts ?? '', 32),
          // Calls INSIDE the window. The id is all-time; what it did lately is
          // what a reader is being asked about.
          count: slot.w,
        };
        seenById.delete(id);
        seenById.set(id, entry);
        if (seenById.size > actionLimit) seenById.delete(seenById.keys().next().value);
      }

      stats.recent.push({
        ts: cleanText(ts ?? '', 32),
        tool: cleanKey(e.tool, ''),
        id,
        decision,
        category,
        severity: cleanKey(e.severity, ''),
        // Summary and excerpt are the literal payloads the report exists to
        // show; control chars are stripped so a bidi/ANSI trick cannot reorder
        // the evidence, and HTML-escaping downstream makes the rest inert.
        summary: cleanText(e.summary),
        excerpt: cleanText(e.excerpt),
      });
      if (stats.recent.length > RECENT_LIMIT) stats.recent.shift();
    }
  }

  stats.sessions = sessions.size;
  stats.findingCount = idByKey.size;
  // Most recent first — the order a person reviewing a run reads in. Each entry
  // carries whether `clawmont-cc allow <id>` may act on it and, when it may not,
  // the sentence that says why.
  // Each numbered finding carries whether a live grant already covers it, and
  // — the asymmetry — whether that grant was a deferral. A `later` grant leaves
  // the finding on the list it was on; the two honest reasons take it off. See
  // GRANT_BECAUSE.
  const settle = (e) => {
    const covering = grantByKey.get(findingKey(e));
    if (!covering || grantIsSpent(covering)) return {};
    const because = typeof covering.because === 'string' ? covering.because : '';
    return {
      grant: {
        id: covering.id,
        because,
        once: Boolean(covering.once),
        expiresAt: covering.expiresAt,
        calls: stats.covered[covering.id]?.calls ?? 0,
      },
      // `settled` means "nothing is being asked of you about this one". A
      // deferral is explicitly NOT settled: that is the whole cost of choosing it.
      settled: grantIsQuiet(covering),
      deferred: because === 'later',
    };
  };
  stats.actions = [...seenById.values()].reverse().map((e) => ({ ...e, ...grantability(e), ...settle(e) }));
  if (stats.wanted) stats.wanted = { ...stats.wanted, ...grantability(stats.wanted) };
  stats.perDay = [...perDay.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([day, d]) => ({ day, ...d }));
  return stats;
}

/**
 * Resolve one id back to the finding it names, from the trail itself.
 *
 * Deliberately the SAME streaming pass the report renders from, rather than a
 * second implementation that agrees with it today. If the number a user reads
 * and the number `allow` resolves ever came from different code, the difference
 * would show up as a grant landing on the wrong subject — silently, and only for
 * the users whose trails happen to differ.
 */
export async function resolveFinding(file, id) {
  const n = Number(id);
  if (!Number.isInteger(n) || n < 1) return null;
  const stats = await computeStats(file, { wantId: n });
  return stats.wanted;
}

/**
 * The chain verdict, from the one implementation that owns the algorithm.
 *
 * `clawmont-hook.mjs --verify` resolves its audit path from the project dir, so
 * a file already at `<project>/.clawmont/audit.jsonl` is verified in place —
 * anchors included. Any other path is staged into a throwaway project layout in
 * the temp dir first (the verifier reads a location, not an argument).
 */
export function verifyChainStatus(file) {
  const abs = resolve(file);
  let projectDir;
  let staged = null;
  if (basename(abs) === 'audit.jsonl' && basename(dirname(abs)) === '.clawmont') {
    projectDir = dirname(dirname(abs));
  } else {
    staged = mkdtempSync(join(tmpdir(), 'clawmont-audit-verify-'));
    mkdirSync(join(staged, '.clawmont'), { recursive: true });
    copyFileSync(abs, join(staged, '.clawmont', 'audit.jsonl'));
    projectDir = staged;
  }
  try {
    const out = execFileSync(process.execPath, [HOOK_PATH, '--verify'], {
      env: { ...process.env, CLAUDE_PROJECT_DIR: projectDir },
      encoding: 'utf8',
      input: '',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 120_000,
    });
    // The length anchor lives OUTSIDE the trail, keyed by the real project path
    // (clawmont-hook.mjs anchorComplaint). A staged copy has no anchor, so the
    // hash walk ran but the "is any of it MISSING?" half did not — say so, or a
    // truncated out-of-tree trail reads as a clean "OK".
    const detail = staged ? `${cleanVerdict(out)} (hash chain only; length not checked for a trail outside its project)` : cleanVerdict(out);
    return { ok: true, anchored: !staged, detail };
  } catch (err) {
    const said = `${err.stdout ?? ''}${err.stderr ?? ''}`.trim();
    return { ok: false, anchored: !staged, detail: said ? cleanVerdict(said) : 'the verifier did not run' };
  } finally {
    if (staged) rmSync(staged, { recursive: true, force: true });
  }
}

const cleanVerdict = (s) => String(s).trim().replace(/^clawmont-hook:\s*/gm, '').split('\n')[0];

// ---------------------------------------------------------------------------
// Rendering — terminal
// ---------------------------------------------------------------------------

const nf = (n) => Number(n ?? 0).toLocaleString('en-US');

const topEntries = (obj, limit) =>
  Object.entries(obj).sort(([, a], [, b]) => b - a).slice(0, limit);

const flaggedTotal = (c) => c.warn + c.deny;

function dayCount(range) {
  if (!range.first || !range.last) return 0;
  const ms = Date.parse(range.last) - Date.parse(range.first);
  return Number.isFinite(ms) ? Math.max(1, Math.round(ms / 86_400_000) + 1) : 0;
}

// ---------------------------------------------------------------------------
// THE HEADLINE — what Clawmont DID. Shared by the terminal and the HTML page,
// because one behaviour rendered twice is the only way they stay the same.
// ---------------------------------------------------------------------------

/**
 * The only groups this report promotes, and the same classes the hook uses to
 * decide what may never be silenced. A reader had to know which of 25 category
 * names mattered before the page told them anything; these four are the answer,
 * each carrying the reason it is on the list in the words of what happened.
 *
 * They are also, deliberately, the definition of "surfaced" in the headline —
 * see `actionsTaken`. Nothing else is promoted, and in particular NO SEVERITY
 * CLASS is: `critical` is a property of a pattern, not of a consequence, and
 * grouping by it is the defect this section replaced.
 *
 * WHAT THIS COPY MAY NOT DO, on the same rules as the terminal voice:
 *  · no state claims — "all clear", "you are protected", "you are covered".
 *    Every sentence here is past tense about what was RECORDED.
 *  · no efficacy claims — nothing about what was caught, prevented or stopped
 *    beyond the literal count of calls that did not run.
 *  · monitor's posture is never omitted where it changes the meaning.
 */
const ATTENTION = [
  {
    key: 'stopped',
    // ONE CLOSED VERDICT VOCABULARY ACROSS BOTH SURFACES. The receipt and this
    // report are read by the same person, and the same number was called
    // `stopped` here, `stopped` on the receipt and `blocked` on the deny. The
    // word is `did not run` everywhere now — see clawmont-hook.mjs's renderBlock
    // headline, which emits it structurally. The KEY stays `stopped` because it
    // is an internal identifier, not copy.
    label: 'Did not run',
    match: null, // denies are counted from the decision split, not a category
    why: 'these calls did not run',
  },
  {
    key: 'control-plane',
    label: 'Clawmont’s own controls',
    match: new Set(['security_control_write', 'override_self_grant', 'security_audit_write',
      'security_control_disarm', 'config_write_gadget']),
    why: 'something tried to change Clawmont’s settings, its record, or grant itself an override',
  },
  {
    key: 'credentials',
    label: 'Credential material',
    match: new Set(['secret_exposure', 'secret_in_content', 'secret_in_content_template',
      'secret_in_output', 'secret_in_prompt', 'secret_in_reply']),
    why: 'rotate anything that turns out to be real',
  },
  {
    key: 'gaps',
    label: 'Not fully inspected',
    match: new Set(['inspection_incomplete', 'inspection_backstop',
      'uninspected_input', 'detector_core_unavailable']),
    why: 'these calls were read only in part, or not at all',
  },
];

/** The attention groups that actually occurred, in the order above. */
function attentionItems(stats) {
  const items = [];
  const stopped = stats.decisions.deny ?? 0;
  for (const group of ATTENTION) {
    if (group.key === 'stopped') {
      if (stopped > 0) items.push({ ...group, count: stopped });
      continue;
    }
    let count = 0;
    for (const [cat, c] of Object.entries(stats.categories)) {
      if (group.match.has(cat)) count += flaggedTotal(c);
    }
    if (count > 0) items.push({ ...group, count });
  }
  return items;
}

/**
 * ---------------------------------------------------------------------------
 * WHY THE LEAD IS ACTIONS AND NOT MATCHES
 * ---------------------------------------------------------------------------
 * This report used to print, and the page used to headline, a line of this
 * shape:
 *
 *     high-sev   676 monitor-mode warnings carried critical or high severity
 *
 * Every row behind that number was honest. The number was not. Measured over
 * two days of real use across two projects (docs/FINDINGS-2026-08-12-two-day-
 * log-review.md, Finding 2): 676 "critical or high" events, of which **zero**
 * were real, and on the non-security project 244 of 257 criticals were
 * injection flags on a game's own design docs. Counting pattern matches under a
 * severity label converts "some regexes matched" into "you had 676
 * near-misses", and that is the sentence that ends up on a slide.
 *
 * So the aggregate is DELETED, not moved and not softened — a lower, gentler
 * severity total is the same defect in a smaller font. What leads instead is
 * the only thing this file can state without inference:
 *
 *     N stopped · M surfaced to you · K recorded
 *
 *   · stopped   — calls that did not run. `decision === 'deny'`, nothing else.
 *   · surfaced  — findings this report puts in front of a reader, which is
 *                 exactly the attention list rendered below the headline. Not a
 *                 model of what the hook printed in the terminal (that model
 *                 lives in ux-score.mjs and is validated against the hook by
 *                 `--conform`); a third copy of the speaking rules here would
 *                 drift from both. "Surfaced" means surfaced BY THIS REPORT,
 *                 and the list is directly underneath so the claim checks
 *                 itself.
 *   · recorded  — rows in the trail. A count of a log, and it says so.
 *
 * None of the three is a severity, a threat count, or an efficacy claim.
 */
export function actionsTaken(stats) {
  return {
    stopped: stats.decisions.deny ?? 0,
    surfaced: attentionItems(stats)
      .filter((i) => i.key !== 'stopped')
      .reduce((n, i) => n + i.count, 0),
    recorded: stats.totalEvents,
  };
}

/** The lead line, byte-identical in the terminal and in the page headline. */
export function actionsLine(stats) {
  const a = actionsTaken(stats);
  // `surfaced` was vendor vocabulary for a thing that happened to the reader;
  // `shown to you` is the same fact in their words. `stopped` becomes the one
  // verdict word the hook also emits — the receipt and this line now agree.
  return `${nf(a.stopped)} did not run · ${nf(a.surfaced)} shown to you · ${nf(a.recorded)} recorded`;
}

/**
 * What to say when the answer is zero — the common case, and the one the old
 * headline was quietly dressing up.
 *
 * A skeptical developer reading "0 stopped" next to thousands of flags asks two
 * questions, and the sentence has to answer both before they ask: did anything
 * get through, and why are all these numbers here? So it says plainly that
 * every call ran, names monitor as the reason where monitor is the reason, and
 * states what the counts below actually are. No "you are protected", no "all
 * clear", no near-miss framing.
 */
export function nothingStoppedSentence(stats) {
  const monitorOnly = !stats.decisions.deny && !stats.modes.enforce;
  return 'Every call in this record ran.'
    + (monitorOnly ? ' The recorded mode was monitor, which blocks nothing.' : '')
    + ' The counts below are what the detectors matched in a log, not incidents.';
}

/**
 * The shared shape of one numbered finding, so the terminal and the page cannot
 * describe the same id differently. Returns plain strings; escaping is the
 * caller's job because only the caller knows whether it is writing HTML.
 */
export function actionLines(a) {
  const when = a.lastTs ? a.lastTs.slice(0, 16).replace('T', ' ') : '';
  return {
    id: `#${a.id}`,
    // Closed verdict set, same five words as the hook. `warned` was a sixth
    // word for a row that was recorded and nothing else.
    verdict: a.decision === 'deny' ? 'did not run' : 'recorded',
    subject: cleanText(a.display ?? a.subject, 120),
    facts: [a.reason, a.tool, `${nf(a.count)} ${a.count === 1 ? 'call' : 'calls'}`, when]
      .filter(Boolean).join(' · '),
    command: a.grantable ? `clawmont-cc allow ${a.id}` : null,
    why: a.grantable ? '' : a.why,
    // What a grant already says about this finding, in the words the human
    // chose. Empty when nobody has said anything, which is the common case.
    granted: a.grant
      ? `${a.grant.once ? 'one-shot grant' : 'granted'}${a.grant.because ? ` — ${GRANT_BECAUSE.get(a.grant.because)?.label ?? a.grant.because}` : ''}`
      : '',
    // A deferral is the one grant that leaves its finding on the list. It says
    // so here rather than looking like an oversight.
    deferred: Boolean(a.deferred),
  };
}

/** The one sentence that explains what a number in front of a finding is for. */
export const ACTIONS_LEAD =
  'Type the number, not the command. A grant covers that one subject and that one'
  + ' finding, expires in 24 hours, and you must run it yourself.';

/**
 * The second sentence: why YOU think it is fine, in three words the record can
 * keep. Printed under a grantable finding, once, and never as a fourth
 * paragraph of instructions.
 *
 * The ordering is the design. `test-fixture` and `false-positive` come first
 * and cost nothing; `later` comes last and is described by what it costs. That
 * is GitHub push protection's asymmetry, spelled out where the choice is made
 * rather than in a manual.
 */
export const WHY_LEAD =
  '--because test-fixture | false-positive closes it quietly; --because later keeps showing it.';

/**
 * The findings still asking something of the reader.
 *
 * A finding a human closed with an honest reason leaves this list — that is the
 * whole point of being able to say why. A DEFERRED one does not: `later` means
 * "not yet", and a list that dropped those would make the cheap answer and the
 * expensive answer cost the same.
 */
export function openActions(stats) {
  return (stats.actions ?? []).filter((a) => !a.settled);
}

/** The findings a grant closed, most recent first. Never dropped, only moved. */
export function settledActions(stats) {
  return (stats.actions ?? []).filter((a) => a.settled);
}

export function renderTerminalSummary(stats, chain) {
  const line = (label, value) => `  ${label.padEnd(11)}${value}`;
  const out = [`Clawmont audit — ${stats.file}`, ''];

  // THE WINDOW, above the numbers it governs. Every count on this summary is a
  // count inside it, so a reader must not meet one before meeting the window —
  // and the way to widen it is on the same line, not in a help page.
  if (stats.window?.since) {
    out.push(line('window', windowLine(stats)));
    out.push(`  ${' '.repeat(11)}${WINDOW_HINT}`);
    out.push('');
    // A window that caught nothing is a fact worth one plain sentence, and the
    // summary below would otherwise read as "nothing has ever happened here".
    if (stats.totalEvents === 0 && stats.window.total > 0) {
      out.push(`  ${' '.repeat(11)}Nothing was recorded in this window. The trail itself carries ${nf(stats.window.total)} ${stats.window.total === 1 ? 'row' : 'rows'}.`);
      out.push('');
    }
  }

  // ACTIONS FIRST. Whatever else this summary grows, the first thing a reader
  // sees is what was done, and the widest number on the line is a count of a
  // log labelled as one.
  out.push(line('actions', actionsLine(stats)));
  if ((stats.decisions.deny ?? 0) === 0) out.push(`  ${' '.repeat(11)}${nothingStoppedSentence(stats)}`);
  out.push('');

  out.push(line('events', `${nf(stats.totalEvents)} recorded${stats.malformed ? ` · ${nf(stats.malformed)} unreadable ${stats.malformed === 1 ? 'line' : 'lines'} skipped` : ''}`));
  if (stats.range.first) {
    const span = dayCount(stats.range);
    out.push(line('range', `${stats.range.first.slice(0, 16).replace('T', ' ')} → ${stats.range.last.slice(0, 16).replace('T', ' ')}${span ? ` (${span} ${span === 1 ? 'day' : 'days'})` : ''}`));
  }
  out.push(line('sessions', nf(stats.sessions)));
  out.push(line('modes', topEntries(stats.modes, 4).map(([k, v]) => `${k} ${nf(v)}`).join(' · ')));
  out.push(line('decisions', ['allow', 'warn', 'deny']
    .filter((d) => stats.decisions[d])
    .concat(Object.keys(stats.decisions).filter((d) => !['allow', 'warn', 'deny'].includes(d)))
    .map((d) => `${d} ${nf(stats.decisions[d])}`)
    .join(' · ') || 'none'));

  const cats = topEntries(Object.fromEntries(
    Object.entries(stats.categories).map(([k, v]) => [k, flaggedTotal(v)]),
  ), 3);
  // Raw per-category counts, which are honest: a count of how often a named
  // detector matched. They are NOT relabelled as severity, threats or
  // near-misses — see the note above `actionsTaken` for the aggregate that used
  // to sit on the next line and why it is gone rather than reworded.
  if (cats.length) out.push(line('findings', cats.map(([k, v]) => `${k} ${nf(v)}`).join(' · ')));
  out.push(line('chain', chain.detail));

  // THE NUMBERED FINDINGS. Last, because a summary should not open with a list
  // of chores — but present in the terminal as well as the page, because the
  // number is worthless if the two surfaces disagree about which finding it is.
  const open = openActions(stats);
  const settled = stats.actions.length - open.length;
  if (open.length) {
    out.push('');
    out.push(line('numbered', `${nf(open.length)} ${open.length === 1 ? 'finding' : 'findings'} you can act on${stats.findingCount > open.length ? ` (of ${nf(stats.findingCount)} recorded)` : ''}`));
    out.push(`  ${' '.repeat(11)}${ACTIONS_LEAD}`);
    out.push('');
    for (const a of open) {
      const l = actionLines(a);
      // Column width follows the vocabulary: `did not run` is 11 characters and
      // the old 9-wide column ran the verdict into the subject.
      out.push(`    ${l.id.padEnd(5)}${l.verdict.padEnd(12)}${l.subject}`);
      out.push(`    ${' '.repeat(14)}${l.facts}`);
      if (l.deferred) {
        // Still on the list, and the reason it is still on the list is the one
        // the human gave. This is the deferral costing something.
        out.push(`    ${' '.repeat(14)}deferred — still shown until it is fixed   clawmont-cc revoke <n> ends the grant`);
      } else if (l.command) {
        out.push(`    ${' '.repeat(14)}${l.command}   (24 hours; --days 7 for longer, --once for one call)`);
        out.push(`    ${' '.repeat(14)}${WHY_LEAD}`);
      } else {
        out.push(`    ${' '.repeat(14)}not grantable by number — ${l.why}`);
      }
    }
    out.push('');
    out.push(`  ${' '.repeat(11)}clawmont-cc allowlist   what is already granted, and how to revoke it`);
    out.push(`  ${' '.repeat(11)}clawmont-cc review      go through them one at a time`);
  }
  // The record not shrinking. Findings a grant closed are OFF the list above and
  // still counted here, with the calls they covered — because every control this
  // report offers makes suppression easier and this is the line that keeps it
  // honest. Same rule ClawSec and Semgrep apply to an ignored finding.
  if (settled > 0 || stats.coveredCalls > 0) {
    out.push('');
    out.push(line('covered', `${nf(settled)} ${settled === 1 ? 'finding' : 'findings'} closed by a grant · ${nf(stats.coveredCalls)} ${stats.coveredCalls === 1 ? 'call' : 'calls'} matched a grant in this window · ${nf(stats.overriddenCalls)} ran on one`));
    out.push(`  ${' '.repeat(11)}They are not gone — clawmont-cc allowlist names every one and how to end it.`);
  }
  // WHERE THE SUPPORT ADDRESS LIVES NOW.
  //
  // It used to sit on every per-call deny, and soliciting labour from the
  // person we had just interrupted — on every CORRECT deny — is the tax that
  // trains people to skim. It is not deleted, because a false deny really is a
  // bug we want reported: it moved here, to the surface a reader chose to open.
  if (stats.decisions.deny) {
    out.push('');
    out.push(`  ${' '.repeat(11)}a call that should have run is a bug — support@clawmont.com`);
  }
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// Rendering — HTML. Every row-derived string passes through esc(); row data is
// only ever text content, never an attribute value, URL, or element name.
// ---------------------------------------------------------------------------

export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

/** Decision colors: allow is routine work and recessive; warn/deny are status colors. */
const COLOR = { allow: '#3987e5', warn: '#fab219', deny: '#d03b3b', other: '#898781' };
// The per-row pill a human reads, so it speaks the closed verdict set rather
// than a fourth and fifth word for the same two outcomes. `warned` and `denied`
// were the report's own dialect for what the receipt calls `recorded` and
// `did not run`.
const DECISION_LABEL = { allow: 'allowed', warn: 'recorded', deny: 'did not run' };

/** Stacked per-day bars. Data values are numbers; day labels are escaped. */
function svgPerDay(perDay) {
  const days = perDay.slice(-CHART_MAX_DAYS);
  if (!days.length) return '<p class="empty">No dated events to chart.</p>';
  const W = 720; const H = 200; const PAD_L = 46; const PAD_B = 22; const PAD_T = 8;
  const plotW = W - PAD_L - 6;
  const plotH = H - PAD_B - PAD_T;
  const max = Math.max(1, ...days.map((d) => d.allow + d.warn + d.deny + d.other));
  const step = plotW / days.length;
  const barW = Math.max(2, Math.min(28, step - 2));
  const y = (v) => plotH * (v / max);

  const gridLines = [0.5, 1].map((f) => {
    const gy = PAD_T + plotH - y(max * f);
    return `<line x1="${PAD_L}" y1="${gy}" x2="${W - 6}" y2="${gy}" stroke="#2c2c2a" stroke-width="1"/>`
      + `<text x="${PAD_L - 6}" y="${gy + 4}" text-anchor="end" class="tick">${nf(Math.round(max * f))}</text>`;
  }).join('');

  const labelEvery = Math.max(1, Math.ceil(days.length / 8));
  const bars = days.map((d, i) => {
    const x = PAD_L + i * step + (step - barW) / 2;
    let top = PAD_T + plotH;
    const segs = ['allow', 'warn', 'deny', 'other'].map((k) => {
      const h = y(d[k]);
      if (h <= 0) return '';
      top -= h;
      const hh = Math.max(h - 1, 0.75); // 1px gap between stacked segments
      return `<rect x="${x.toFixed(1)}" y="${top.toFixed(1)}" width="${barW.toFixed(1)}" height="${hh.toFixed(1)}" fill="${COLOR[k]}"/>`;
    }).join('');
    const label = i % labelEvery === 0
      ? `<text x="${(x + barW / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle" class="tick">${esc(d.day.slice(5))}</text>`
      : '';
    const title = `<title>${esc(d.day)}: ${nf(d.allow)} allowed, ${nf(d.warn)} recorded, ${nf(d.deny)} did not run${d.other ? `, ${nf(d.other)} other` : ''}</title>`;
    return `<g>${title}${segs}</g>${label}`;
  }).join('');

  const truncated = perDay.length > days.length
    ? `<p class="note">Showing the most recent ${days.length} of ${perDay.length} days.</p>` : '';
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Events per day, stacked by decision">`
    + `<line x1="${PAD_L}" y1="${PAD_T + plotH}" x2="${W - 6}" y2="${PAD_T + plotH}" stroke="#383835" stroke-width="1"/>`
    + gridLines + bars + '</svg>' + truncated;
}

/**
 * Horizontal bars: [{ label, value, color }] — labels escaped, values numbers.
 *
 * `width` is the viewBox width, and it is a LEGIBILITY control, not a layout
 * one: the SVG always fills its column, so a 720-wide viewBox dropped into a
 * half-width panel scales every label down to about 6px. The two-up panels pass
 * a narrow viewBox so their text lands near the size it claims to be.
 */
function svgHBars(rows, { maxRows = 10, width = 720 } = {}) {
  // Coerce every value to a finite number. Accumulators are null-proto so keys
  // like `constructor` can no longer poison a counter, but a NaN reaching the
  // geometry would still emit `width="NaN"` and blank the chart — belt and
  // braces on the surface a hostile trail is trying to hide things from.
  const shown = rows.slice(0, maxRows).map((r) => ({ ...r, value: Number.isFinite(r.value) ? r.value : 0 }));
  if (!shown.length) return '<p class="empty">Nothing to chart.</p>';
  const max = Math.max(1, ...shown.map((r) => r.value));
  const W = width;
  const rowH = W < 500 ? 24 : 26;
  const LABEL_W = Math.round(W * 0.28);
  const VAL_W = Math.round(W * 0.13);
  // ~6.6px per character at this font size, less a margin — a label that runs
  // past the left edge of the viewBox is clipped mid-word and reads as a typo.
  const maxChars = Math.max(10, Math.round((LABEL_W - 12) / 6.6));
  const H = shown.length * rowH;
  const barMax = W - LABEL_W - VAL_W;
  const body = shown.map((r, i) => {
    const yMid = i * rowH + rowH / 2;
    const w = Math.max(2, barMax * (r.value / max));
    const label = r.label.length > maxChars ? `${r.label.slice(0, maxChars - 1)}…` : r.label;
    return `<g><title>${esc(r.label)}: ${nf(r.value)}</title>`
      + `<text x="${LABEL_W - 8}" y="${yMid + 4}" text-anchor="end" class="lbl">${esc(label)}</text>`
      + `<rect x="${LABEL_W}" y="${yMid - 8}" width="${w.toFixed(1)}" height="16" rx="4" fill="${r.color}"/>`
      + `<text x="${(LABEL_W + w + 8).toFixed(1)}" y="${yMid + 4}" class="val">${nf(r.value)}</text></g>`;
  }).join('');
  const dropped = rows.length > shown.length
    ? `<p class="note">Top ${shown.length} of ${rows.length} shown.</p>` : '';
  return `<svg viewBox="0 0 ${W} ${H}" role="img">${body}</svg>${dropped}`;
}

const legend = () => `
  <p class="legend">
    <span><i style="background:${COLOR.allow}"></i>allowed</span>
    <span><i style="background:${COLOR.warn}"></i>recorded</span>
    <span><i style="background:${COLOR.deny}"></i>did not run</span>
  </p>`;

/** Mode, and what that mode is not doing — never one without the other. */
const POSTURE = {
  monitor: 'monitor — records, blocks nothing',
  enforce: 'enforce — blocking on',
};

/**
 * The verdict. The HEAD is the actions line and nothing else — the same string
 * the terminal prints, so the two surfaces cannot say different things about
 * the same file.
 *
 * `flagged` is not promoted into the headline, and neither is any severity
 * total: measured on a real trail roughly three-quarters of flags are false
 * positives (docs/THREAT-QUALITY-ANALYSIS) and every one of the 676 critical-
 * or-high events in the two-day window was one, so a big number in either place
 * states a security fact that is mostly wrong.
 */
function verdict(stats) {
  const a = actionsTaken(stats);
  // A quiet week over a trail that is not empty. Said plainly, because every
  // other sentence on this page would otherwise read as a claim about the
  // project rather than about the last seven days.
  if (stats.totalEvents === 0 && (stats.window?.total ?? 0) > 0) {
    return {
      tone: 'quiet',
      head: `Nothing recorded in ${stats.window.label}`,
      sub: `This trail carries ${nf(stats.window.total)} ${stats.window.total === 1 ? 'row' : 'rows'}, none of them in this window.`
        + ' Widen it with clawmont-cc audit --since all.',
    };
  }
  if (a.stopped > 0) {
    return {
      tone: 'deny',
      head: actionsLine(stats),
      sub: `${nf(a.stopped)} ${a.stopped === 1 ? 'call did' : 'calls did'} not run. Everything else in this record ran.`
        + (a.surfaced > 0 ? ` ${nf(a.surfaced)} further ${a.surfaced === 1 ? 'finding is' : 'findings are'} listed below.` : ''),
    };
  }
  if (a.surfaced > 0) {
    return {
      tone: 'warn',
      head: actionsLine(stats),
      sub: `${nothingStoppedSentence(stats)} ${nf(a.surfaced)} recorded ${a.surfaced === 1 ? 'finding is' : 'findings are'} worth a look — they are listed below.`,
    };
  }
  return {
    tone: 'quiet',
    head: actionsLine(stats),
    sub: `${nothingStoppedSentence(stats)} Nothing in this record asks anything of you.`,
  };
}

/**
 * The page's whole visual language, in one place so the empty state and the
 * report cannot drift into looking like two different products.
 */
/**
 * The real brand mark, INLINED AS MARKUP — never linked, never fetched.
 *
 * The terminal can only carry a character, which is why the hook's `MARK` is a
 * single glyph. This page is HTML, so it can carry the actual mark: a shield
 * holding contour lines that rise to a summit, in the brand red.
 *
 * THREE THINGS ABOUT THIS COPY OF IT, each load-bearing.
 *
 *   NO `xmlns` ATTRIBUTE. The source file at packages/marketing/public/
 *   favicon.svg carries `xmlns="http://www.w3.org/2000/svg"`, and this report
 *   is pinned by audit-report.selftest.mjs to contain no `https?://` at all —
 *   the mechanical half of "this page makes no network request". An inline
 *   `<svg>` in an HTML5 document is placed in the SVG namespace by the parser
 *   itself, so the attribute is redundant here and dropping it keeps that pin
 *   green WITHOUT weakening it. Do not re-add it.
 *
 *   NO `<?xml?>` PROLOG. Valid in a standalone .svg file, meaningless inline.
 *
 *   THE GRADIENT ID IS NAMESPACED. `id="cm"` in the source would collide with
 *   any other `cm` on a page; SVG ids are document-global, and a collision
 *   silently repaints the mark with someone else's gradient.
 *
 * Everything else is byte-identical to the brand file: pure path data and one
 * gradient, no external references of any kind, which is the property that
 * made inlining possible rather than a compromise. It is decorative beside a
 * text eyebrow that already says the name, so it is hidden from assistive
 * technology rather than repeating that name.
 */
const BRAND_MARK = '<svg class="mark" viewBox="0 0 64 64" role="presentation" aria-hidden="true" '
  + 'fill="none" stroke="url(#cm-brand)" stroke-linejoin="round" stroke-linecap="round">'
  + '<defs><linearGradient id="cm-brand" x1="0" y1="0" x2="1" y2="1">'
  + '<stop offset="0" stop-color="#f76e78"/><stop offset="1" stop-color="#e5383b"/>'
  + '</linearGradient></defs>'
  + '<path d="M32 6 L53 14 V31 C53 44 44 53 32 58 C20 53 11 44 11 31 V14 Z" stroke-width="3" opacity="0.55"/>'
  + '<path d="M15 44 L32 19 L49 44" stroke-width="3.4"/>'
  + '<path d="M21 44 L32 28 L43 44" stroke-width="3.4"/>'
  + '<path d="M27 44 L32 37 L37 44" stroke-width="3.4"/>'
  + '</svg>';

const PAGE_CSS = `  /* One page, one type scale, three inks. Everything below is structure the
     reader can feel: the verdict is the largest thing on the page, the numbers
     are quiet until you look for them, and the evidence tables are last
     because nobody starts there. No fonts are fetched — the stack is whatever
     the OS already has, which is also the only stack a file:// page with no
     network access can honestly use. */
  :root {
    color-scheme: dark;
    --bg: #0a0a0b; --surface: #131315; --raised: #17171a;
    --line: rgba(255,255,255,0.09); --line-strong: rgba(255,255,255,0.16);
    --ink: #f4f3f1; --ink-2: #b8b6b0; --ink-3: #86847e;
    --allow: ${COLOR.allow}; --warn: ${COLOR.warn}; --deny: ${COLOR.deny}; --ok: #37a05a;
    --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--bg); color: var(--ink); font: 15px/1.55 var(--sans);
         padding: 40px 24px 64px; -webkit-font-smoothing: antialiased; }
  main { max-width: 880px; margin: 0 auto; display: grid; gap: 18px; }
  .eyebrow { font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase;
             color: var(--ink-3); font-weight: 600;
             display: flex; align-items: center; gap: 8px; }
  /* The brand mark, inlined as markup rather than fetched. See BRAND_MARK. */
  .eyebrow .mark { width: 18px; height: 18px; flex: none; display: block; }
  /* The headline is the actions line — three counts and two separators. It is
     set in tabular figures and allowed to wrap at the separators on a narrow
     window rather than shrinking, because the numbers are the content. */
  h1 { font-size: 27px; line-height: 1.25; font-weight: 620; letter-spacing: -0.02em;
       margin-top: 10px; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
  h2 { font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase;
       font-weight: 600; color: var(--ink-3); margin-bottom: 14px; }
  section { background: var(--surface); border: 1px solid var(--line);
            border-radius: 14px; padding: 20px; overflow-x: auto; }

  /* The verdict. Tone is carried by one hairline of colour, not a filled panel:
     a red slab at the top of every report trains people to stop seeing red. */
  .hero { border-radius: 16px; padding: 26px 24px 22px; position: relative; }
  .hero::before { content: ""; position: absolute; left: 0; top: 18px; bottom: 18px;
                  width: 3px; border-radius: 3px; background: var(--ink-3); }
  .hero.deny::before { background: var(--deny); }
  .hero.warn::before { background: var(--warn); }
  .hero.quiet::before { background: var(--ok); }
  .hero .lede { color: var(--ink-2); font-size: 15px; margin-top: 8px; max-width: 58ch; }
  .stamp { color: var(--ink-2); font-size: 12.5px; margin-top: 14px; font-variant-numeric: tabular-nums; }
  .sub { color: var(--ink-3); font-size: 12px; margin-top: 4px; overflow-wrap: anywhere; }
  .posture { display: inline-block; margin-top: 14px; font-size: 12px; color: var(--ink-2);
             border: 1px solid var(--line-strong); border-radius: 999px; padding: 3px 12px; }
  /* The window sits with the verdict, not in a footnote: every number on this
     page is a number inside it. */
  .window { margin-top: 12px; font-size: 12.5px; color: var(--ink-2); max-width: 70ch; }
  .window strong { color: var(--ink); font-weight: 580; }

  /* Needs a look — the only list on the page that asks for anything. */
  .attn { list-style: none; padding: 0; margin: 20px 0 0; display: grid; gap: 1px;
          background: var(--line); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
  .attn li { display: flex; align-items: baseline; gap: 14px; background: var(--raised); padding: 12px 16px; }
  .attn .n { font-size: 20px; font-weight: 620; font-variant-numeric: tabular-nums;
             min-width: 3.2ch; text-align: right; color: var(--warn); }
  .attn li.is-deny .n { color: var(--deny); }
  .attn .t { display: flex; flex-direction: column; }
  .attn strong { font-weight: 580; font-size: 14px; }
  .attn .w { color: var(--ink-3); font-size: 12.5px; }

  .chain { font-size: 13.5px; color: var(--ink-2); display: flex; gap: 10px; align-items: baseline; }
  .chain::before { content: ""; width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--ok); }
  .chain.broken::before { background: var(--deny); }
  /* No rows, no chain, no verdict — so no colour that reads as one. */
  .chain.unproven::before { background: var(--ink-3); }
  /* A broken chain is not a status line, it is the most important sentence on
     the page: the record itself is the thing under attack. It gets the weight. */
  .chain.broken { color: var(--ink); font-size: 15px; font-weight: 560;
                  border-color: rgba(208,59,59,0.45); background: rgba(208,59,59,0.07); }

  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(124px, 1fr)); gap: 10px; }
  .tile { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 15px 16px; }
  .tile .v { font-size: 23px; font-weight: 620; font-variant-numeric: tabular-nums; letter-spacing: -0.01em; }
  .tile .l { font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-3); margin-top: 4px; }

  svg { width: 100%; height: auto; display: block; }
  svg text { font: 11px var(--sans); fill: var(--ink-2); }
  svg .tick { fill: var(--ink-3); font-variant-numeric: tabular-nums; }
  svg .val { fill: var(--ink); font-variant-numeric: tabular-nums; font-weight: 560; }
  svg .lbl { fill: var(--ink-2); }
  .legend { display: flex; gap: 16px; font-size: 12px; color: var(--ink-3); margin-top: 12px; }
  .legend i { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 6px; }
  .note, .empty { color: var(--ink-3); font-size: 12px; margin-top: 10px; }
  .two { display: grid; grid-template-columns: 1fr; gap: 18px; }
  @media (min-width: 760px) { .two { grid-template-columns: 1fr 1fr; } }

  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th { text-align: left; color: var(--ink-3); font-weight: 500; font-size: 11px;
       letter-spacing: 0.06em; text-transform: uppercase; padding: 0 12px 8px 0;
       border-bottom: 1px solid var(--line-strong); }
  td { padding: 8px 12px 8px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
  tr:last-child td { border-bottom: 0; }
  td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
  td.ts { white-space: nowrap; color: var(--ink-3); font-variant-numeric: tabular-nums; }
  code { font: 12px var(--mono); background: var(--bg); border: 1px solid var(--line);
         padding: 1px 6px; border-radius: 5px; overflow-wrap: anywhere; color: var(--ink-2); }
  .pill { font-size: 11px; padding: 2px 9px; border-radius: 999px; white-space: nowrap; font-weight: 560; }
  .pill.deny { background: rgba(208,59,59,0.16); color: #e87b72; }
  .pill.warn { background: rgba(250,178,25,0.14); color: var(--warn); }
  .callout { border-left: 3px solid var(--warn); }
  .callout.paused { border-left-color: var(--allow); }
  .callout h2 { font-size: 14px; text-transform: none; letter-spacing: 0; color: var(--ink); margin-bottom: 8px; }
  .callout p { color: var(--ink-2); font-size: 13px; margin-top: 8px; }

  /* The numbered findings. The number is the largest thing in the row because
     the number is the only thing the reader has to carry to their terminal. */
  .lead-note { color: var(--ink-2); font-size: 13px; margin: -6px 0 16px; max-width: 62ch; }
  .acts { list-style: none; padding: 0; margin: 0; display: grid; gap: 1px;
          background: var(--line); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
  .acts li { display: flex; gap: 14px; background: var(--raised); padding: 14px 16px; align-items: flex-start; }
  .acts .idx { font-size: 19px; font-weight: 640; font-variant-numeric: tabular-nums;
               color: var(--ink); min-width: 3.4ch; text-align: right; flex: none; padding-top: 1px; }
  .acts .body { display: grid; gap: 6px; min-width: 0; flex: 1; }
  .acts .what { display: flex; gap: 9px; align-items: baseline; flex-wrap: wrap; }
  .acts .subj { color: var(--ink); }
  .acts .facts { color: var(--ink-3); font-size: 12.5px; }
  .acts .facts.nope { color: var(--ink-2); }
  .acts .facts.why { color: var(--ink-3); font-size: 11.5px; }
  /* A deferred finding stays on the list and looks like it is staying: the
     marker is the visible half of "later costs something". */
  .acts li.is-deferred { border-left: 2px solid var(--warn); }
  .cmd { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; margin-top: 2px; }
  .cmd .hint { color: var(--ink-3); font-size: 11.5px; }
  .muted { color: var(--ink-3); font-size: 11.5px; }
  /* A spent one-shot is still listed. It reads as used, never as missing. */
  tr.spent td { color: var(--ink-3); }
  /* Click once, get the whole command. The page's entire capability over a
     control is to make its text easy to take somewhere else. */
  code.pick { user-select: all; -webkit-user-select: all; cursor: copy;
              border-color: var(--line-strong); color: var(--ink); }
  td.idcell { color: var(--ink-2); font-weight: 560; }
  footer { color: var(--ink-3); font-size: 12px; overflow-wrap: anywhere; padding: 0 4px; }`;

/**
 * @param stats    the object `computeStats` returned
 * @param chain    the verdict `verifyChainStatus` returned
 * @param opts.sibling  true when this page is `.clawmont/audit.html`, the copy
 *   the hook keeps refreshed. It gets one extra sentence — how it stays current
 *   and what to do about it. A one-off `--out` report must NOT carry that
 *   sentence: nothing refreshes it, and telling a reader otherwise is the kind
 *   of small false claim this file exists not to make.
 *
 * There is no `<meta http-equiv="refresh">` on either page, deliberately. The
 * file is rebuilt at most once every five minutes, so a self-reloading tab would
 * spend most reloads replacing a page with an identical one — losing scroll
 * position and selection while someone is mid-sentence reading the evidence. A
 * page that moves under its reader is precisely the "annoying" this product was
 * told to stop being. The generated stamp states the age instead, and the
 * sentence below names reload as the action.
 */
export function renderHtml(stats, chain, { sibling = false, grants = [], pause = null } = {}) {
  const generated = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const flagged = (stats.decisions.warn ?? 0) + (stats.decisions.deny ?? 0);

  // ---------------------------------------------------------------------
  // The controls. Everything below DISPLAYS a command and never performs one.
  // A `file://` page has no privileged channel, and any file it could write is
  // a file the agent can write too — so the page's whole capability here is to
  // show the exact text a human will type in their own terminal.
  // ---------------------------------------------------------------------
  const openList = openActions(stats);
  const settledList = settledActions(stats);
  const actionList = openList.length ? `
    <section id="actions">
      <h2>What you can do — ${nf(openList.length)} numbered ${openList.length === 1 ? 'finding' : 'findings'}${stats.findingCount > openList.length ? ` of ${nf(stats.findingCount)} recorded` : ''}</h2>
      <p class="lead-note">${esc(ACTIONS_LEAD)}</p>
      <ol class="acts">${openList.map((a) => {
    const l = actionLines(a);
    return `
        <li${a.deferred ? ' class="is-deferred"' : ''}>
          <span class="idx">${esc(l.id)}</span>
          <div class="body">
            <p class="what"><span class="pill ${a.decision === 'deny' ? 'deny' : 'warn'}">${esc(l.verdict)}</span> <code class="subj">${esc(l.subject)}</code></p>
            <p class="facts">${esc(l.facts)}</p>
            ${a.deferred
      ? `<p class="facts nope">Deferred — you said you would fix this later, so it keeps being shown. <code class="pick">clawmont-cc allowlist</code> names the grant and ends it.</p>`
      : l.command
        ? `<p class="cmd"><code class="pick">${esc(l.command)}</code><span class="hint">click to select · 24 hours · <code class="pick">clawmont-cc allow ${a.id} --days 7</code> for longer · <code class="pick">clawmont-cc allow ${a.id} --once</code> for one call</span></p>
             <p class="facts why">${esc(WHY_LEAD)}</p>`
        : `<p class="facts nope">Not grantable by number — ${esc(l.why)}.</p>`}
          </div>
        </li>`;
  }).join('')}</ol>
      ${stats.idsCapped ? '<p class="note">This trail carries more distinct findings than this report will number; the oldest are unnumbered.</p>' : ''}
    </section>` : '';

  /**
   * WHAT A GRANT LET THROUGH, in calls.
   *
   * This section used to name the grants and stop there, which meant that as
   * the allowlist grew the visible record shrank: a finding covered by a grant
   * simply stopped appearing anywhere, and the page got quieter the more was
   * being suppressed. That is backwards, and it is the property every other
   * control added here would have made worse.
   *
   * So the grant rows now carry the CALLS they covered inside this window, and
   * the settled findings are listed rather than deleted. Same rule ClawSec
   * states outright — suppressed findings still appear in the report under an
   * informational section, excluded from the totals but not from the page — and
   * the same one Semgrep applies by moving an ignored finding to the Ignored
   * state instead of dropping it.
   */
  const grantRow = (g) => {
    const cov = stats.covered?.[g.id] ?? null;
    const why = GRANT_BECAUSE.get(g.because);
    const spent = grantIsSpent(g);
    return `<tr${spent ? ' class="spent"' : ''}>
          <td class="n">${nf(g.n)}</td>
          <td><code>${esc(cleanText(g.preview, 80))}</code></td>
          <td>${esc(cleanText(g.reason, 40))}</td>
          <td>${why ? esc(why.label) : '<span class="muted">not said</span>'}${g.once ? `<br><span class="muted">${spent ? 'one-shot · spent' : 'one-shot · unused'}</span>` : ''}</td>
          <td class="n">${nf(cov?.calls ?? 0)}</td>
          <td class="ts">${spent ? 'spent' : `in ${esc(untilPhrase(g.expiresAt))}`}</td>
          <td><code class="pick">clawmont-cc revoke ${nf(g.n)}</code></td>
        </tr>`;
  };
  const settledNote = settledList.length
    ? `<p class="note">${nf(settledList.length)} numbered ${settledList.length === 1 ? 'finding is' : 'findings are'} closed by a grant and therefore absent from the list above: ${settledList.map((a) => `#${nf(a.id)}`).join(', ')}. They are excluded from what asks something of you, never from the record.</p>`
    : '';
  const grantList = grants === null ? '' : grants.length ? `
    <section id="allowlist">
      <h2>What Clawmont is letting through — ${nf(grants.length)} active ${grants.length === 1 ? 'grant' : 'grants'}, ${nf(stats.coveredCalls ?? 0)} ${(stats.coveredCalls ?? 0) === 1 ? 'call' : 'calls'} matched since they were made</h2>
      <table>
        <thead><tr><th>#</th><th>covers</th><th>finding</th><th>because</th><th class="n">calls since</th><th>expires</th><th>end it early</th></tr></thead>
        <tbody>${grants.map(grantRow).join('')}</tbody>
      </table>
      <p class="note">Each grant covers one exact command and one finding. Nothing here is permanent — every grant expires on its own, a one-shot ends at the first call it covers, and anything not listed is still being enforced.</p>
      ${settledNote}
    </section>` : `
    <section id="allowlist">
      <h2>What Clawmont is letting through</h2>
      <p class="empty">Nothing. There is no active grant, so every finding is being handled normally.</p>
    </section>`;

  // "Stop blocking" — shown only where it is true, and it is not a toggle. The
  // page cannot pause anything; it can only tell you the command that can.
  const pauseNote = pause?.paused ? `
    <section class="callout paused">
      <h2>Blocking is paused until ${esc(String(pause.until).slice(0, 16).replace('T', ' '))} UTC</h2>
      <p>A human paused enforcement for this project${pause.by ? ` (${esc(cleanText(pause.by, 40))})` : ''}. Every call is still inspected and still recorded; only denial is off, and it returns on its own. End it now with <code class="pick">clawmont-cc resume</code>.</p>
    </section>` : stats.lastMode === 'enforce' ? `
    <section class="callout">
      <h2>Stop blocking</h2>
      <p><strong>This page cannot turn blocking off. That is deliberate.</strong> It is a local report, not a control channel. To pause blocking for this project, type this in a terminal you control:</p>
      <p class="cmd"><code class="pick">clawmont-cc pause</code><span class="hint">one hour, this project, then enforcement returns on its own</span></p>
      <p class="note">Clawmont keeps recording throughout. A pause may run from 15 minutes to 24 hours (<code>--for 4h</code>); there is no permanent option.</p>
    </section>` : '';

  const items = attentionItems(stats);
  const v = verdict(stats);
  const posture = POSTURE[stats.lastMode] ?? esc(stats.lastMode ?? 'unknown');

  /**
   * THE WINDOW, named on the page rather than assumed.
   *
   * The default is a trailing week, so every number above and below is a
   * windowed number, and a windowed number printed without its window is the
   * kind of figure that ends up on a slide meaning something else. The badge
   * states the span, how much of the file it covers, and the command that shows
   * the rest — because a window a reader cannot widen is a window that hides
   * things.
   */
  const w = stats.window ?? null;
  const windowBadge = w?.since ? `
    <p class="window"><strong>Showing ${esc(w.label)}</strong> — ${nf(stats.totalEvents)} of ${nf(w.total)} recorded ${w.total === 1 ? 'row' : 'rows'}${w.before ? `, ${nf(w.before)} older` : ''}${w.undated ? `, ${nf(w.undated)} undated and unplaceable` : ''}. Run <code class="pick">clawmont-cc audit --since all</code> for everything.</p>`
    : '<p class="window"><strong>Showing all time</strong> — every row in this trail.</p>';

  const attentionList = items.length ? `
    <ul class="attn">${items.map((i) => `
      <li class="${i.key === 'stopped' ? 'is-deny' : ''}">
        <span class="n">${nf(i.count)}</span>
        <span class="t"><strong>${i.label}</strong><span class="w">${i.why}</span></span>
      </li>`).join('')}</ul>` : '';

  const tiles = [
    ['events recorded', nf(stats.totalEvents)],
    ['did not run', nf(stats.decisions.deny ?? 0)],
    ['recorded findings', nf(stats.decisions.warn ?? 0)],
    ['sessions', nf(stats.sessions)],
    ['days covered', nf(dayCount(stats.range))],
    ['last recorded mode', esc(stats.lastMode ?? '—')],
  ].map(([label, value]) => `<div class="tile"><div class="v">${value}</div><div class="l">${label}</div></div>`).join('');

  const decisionRows = ['allow', 'warn', 'deny']
    .filter((d) => stats.decisions[d])
    .map((d) => ({ label: DECISION_LABEL[d], value: stats.decisions[d], color: COLOR[d] }))
    .concat(Object.entries(stats.decisions)
      .filter(([d]) => !['allow', 'warn', 'deny'].includes(d))
      .map(([d, v]) => ({ label: d, value: v, color: COLOR.other })));

  const categoryAll = Object.entries(stats.categories)
    .sort(([, a], [, b]) => flaggedTotal(b) - flaggedTotal(a));
  // Capped like every other structure — the module's own promise is "only
  // bounded structures are kept", and a foreign trail can carry thousands of
  // distinct categories. The count in the heading stays honest about the whole.
  const categoryRows = categoryAll.slice(0, CATEGORY_MAX_ROWS)
    .map(([cat, c]) => ({ label: cat, value: flaggedTotal(c), color: COLOR.warn, warn: c.warn, deny: c.deny }));
  const categoryMore = categoryAll.length > categoryRows.length
    ? `<p class="note">Top ${categoryRows.length} of ${nf(categoryAll.length)} categories shown.</p>` : '';

  const categoryTable = categoryRows.length ? `
    <table>
      <thead><tr><th>category</th><th class="n">recorded</th><th class="n">did not run</th><th class="n">total</th></tr></thead>
      <tbody>${categoryRows.map((r) => `<tr><td>${esc(r.label)}</td><td class="n">${nf(r.warn)}</td><td class="n">${nf(r.deny)}</td><td class="n">${nf(r.value)}</td></tr>`).join('')}</tbody>
    </table>${categoryMore}` : '<p class="empty">No flagged events.</p>';

  const toolRows = topEntries(stats.toolsFlagged, 10)
    .map(([tool, v]) => ({ label: tool, value: v, color: COLOR.allow }));

  // There is deliberately NO severity roll-up on this page — no chip row, no
  // callout, no "N critical". `stats.severities` stays in `--json` because it is
  // what the rows literally say, but a rendered severity total is a count of
  // pattern matches wearing a consequence label, and it is the exact figure
  // Finding 2 says must never reach a reader. See `actionsTaken`.

  const recent = [...stats.recent].reverse();
  const recentTable = recent.length ? `
    <table>
      <thead><tr><th class="n">#</th><th>time</th><th>tool</th><th>decision</th><th>category</th><th>summary</th><th>excerpt</th></tr></thead>
      <tbody>${recent.map((r) => `<tr>
        <td class="n idcell">${r.id === null ? '—' : nf(r.id)}</td>
        <td class="ts">${esc(r.ts.slice(0, 16).replace('T', ' '))}</td>
        <td>${esc(r.tool)}</td>
        <td><span class="pill ${r.decision === 'deny' ? 'deny' : 'warn'}">${esc(DECISION_LABEL[r.decision] ?? r.decision)}</span></td>
        <td>${esc(r.category)}</td>
        <td>${esc(r.summary)}</td>
        <td><code>${esc(r.excerpt)}</code></td>
      </tr>`).join('')}</tbody>
    </table>` : '<p class="empty">No warned or denied events in this trail.</p>';

  // Where the severity callout used to be. It said "N monitor-mode warnings
  // carried critical or high severity", every word of it true and the whole of
  // it misleading — on the founder's own two-day window that N was 676 and its
  // real content was zero. The replacement is not a gentler version of the same
  // sentence; it is the headline above, which counts calls that did not run.
  // The one thing worth keeping from it — that monitor blocks nothing — is
  // stated where it belongs, on the posture pill and in the no-stop sentence.
  const modeNote = stats.lastMode === 'monitor' ? `
    <section class="callout">
      <h2>Monitor mode records and blocks nothing</h2>
      <p>Enforce mode denies a narrow, high-confidence subset of flagged calls before they run — not every flag. Turn it on per session with <code>CLAWMONT_CC_MODE=enforce claude</code>.</p>
    </section>` : '';

  const chainClass = chain.ok ? 'ok' : 'broken';
  const detail = chain.detail.charAt(0).toUpperCase() + chain.detail.slice(1);
  const chainLine = esc(detail)
    + (stats.malformed ? ` · ${nf(stats.malformed)} unreadable ${stats.malformed === 1 ? 'line' : 'lines'} skipped` : '');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Clawmont — audit insights</title>
<style>
${PAGE_CSS}
</style>
</head>
<body>
<main>
  <section class="hero ${v.tone}">
    <p class="eyebrow">${BRAND_MARK}<span>Clawmont — audit insights</span></p>
    <h1>${v.head}</h1>
    <p class="lede">${v.sub}</p>
    <p class="posture">Last recorded mode: ${posture}</p>
    ${windowBadge}
    ${attentionList}
    <p class="stamp">Generated ${generated} UTC from ${nf(stats.totalEvents)} ${stats.totalEvents === 1 ? 'event' : 'events'}${stats.range.first ? ` · ${esc(stats.range.first.slice(0, 10))} → ${esc(stats.range.last.slice(0, 10))}` : ''}</p>
    <p class="sub">${esc(stats.file)}${sibling ? ' · rebuilt after a turn once this page is five minutes old and the trail has moved — reload to update' : ''}</p>
  </section>

  <section class="chain ${chainClass}"><span>${chainLine}</span></section>

  ${pauseNote}
  ${actionList}
  ${grantList}

  <div class="tiles">${tiles}</div>

  <section>
    <h2>Events per day</h2>
    ${svgPerDay(stats.perDay)}
    ${legend()}
  </section>

  <div class="two">
    <section>
      <h2>Decisions</h2>
      ${svgHBars(decisionRows, { width: 380 })}
    </section>
    <section>
      <h2>Findings by tool</h2>
      ${svgHBars(toolRows, { width: 380 })}
    </section>
  </div>

  <section>
    <h2>Flags by category — ${nf(flagged)} total</h2>
    ${categoryTable}
    <p class="note">How often each named detector matched. A match is a pattern in text, not an incident — on a measured trail most of these are ordinary work that resembles an attack. Read the rows before drawing a conclusion from a count.</p>
  </section>

  ${modeNote}

  <section>
    <h2>Recent findings${recent.length ? ` — last ${recent.length}` : ''}</h2>
    ${recentTable}
    ${recent.length ? '<p class="note">Excerpts are truncated and rendered as inert text — some are literal attack payloads. The full record is the audit trail itself.</p>' : ''}
  </section>

  <footer>Generated locally by <code>clawmont-cc audit</code>. This page loads no external resource and makes no network request.</footer>
</main>
</body>
</html>
`;
}

/**
 * The marker that says "this HTML is the zero-row page".
 *
 * `siblingRefreshDue` looks for it so an empty report becomes due the moment the
 * first call is recorded, instead of leaving a "nothing here yet" page in front
 * of a user for the next five minutes of the normal throttle (design §8.4). It
 * is an HTML comment, so it never reaches the reader, and it is generated by us
 * rather than derived from any row.
 */
export const EMPTY_REPORT_MARKER = '<!--clawmont:empty-report-->';

/** A report small enough that reading it to check the marker is free. */
const EMPTY_REPORT_PROBE_BYTES = 16 * 1024;

/**
 * The zero-row page.
 *
 * The old behaviour was to print a line and return before writing any HTML, so
 * the file a fresh install told people to open did not exist. This is the page
 * that goes there instead, and the thing it must not do is dress absence up as
 * analytics: no zero-filled charts, no `0 threats`, no green chain verdict, no
 * claim that protection is active. With no row there is no behavioural evidence
 * and no chain to verify, and the page says exactly that.
 */
export function renderEmptyHtml(file, { sibling = false, project = null } = {}) {
  const generated = new Date().toISOString().slice(0, 16).replace('T', ' ');
  return `<!doctype html>
<html lang="en">
${EMPTY_REPORT_MARKER}
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Clawmont — ready to record</title>
<style>
${PAGE_CSS}
  .facts-list { list-style: none; padding: 0; margin: 22px 0 0; display: grid; gap: 1px;
                background: var(--line); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
  .facts-list li { background: var(--raised); padding: 12px 16px; font-size: 13px; color: var(--ink-2); }
  .facts-list b { color: var(--ink); font-weight: 560; }
</style>
</head>
<body>
<main>
  <section class="hero quiet">
    <p class="eyebrow">${BRAND_MARK}<span>Clawmont — audit insights</span></p>
    <h1>Ready to record. No agent calls have been recorded here yet.</h1>
    <p class="lede">Start or restart Claude Code in ${project ? `<b>${esc(basename(project))}</b>` : 'this project'} and use it normally. After the first tool call, this page will show what the agent attempted, what it named, and anything Clawmont stopped.</p>
    <ul class="facts-list">
      <li><b>Monitor</b> — records; blocks nothing. That is the default until you opt in.</li>
      <li><b>Record location</b> <code>${esc(file)}</code></li>
      <li><b>Local only</b> — this page loads no external resource and sends nothing.</li>
    </ul>
    <p class="stamp">Generated ${generated} UTC${sibling ? ' · reload after the first recorded call' : ''}</p>
  </section>

  <!-- Deliberately \`unproven\`, not the default: the chain dot is green, and a
       green dot beside a trail with no rows is a verdict nothing has earned. -->
  <section class="chain unproven"><span>Verification begins with the first record — there is no chain to check yet.</span></section>

  <section class="callout">
    <h2>How to make the first record</h2>
    <p>Open Claude Code in this project and ask it to do something ordinary — read a file, run <code>git status</code>. Clawmont inspects the call, appends a row, and this page fills in. You do not need to run an attack to see it work; if you want proof it inspects anything, run <code class="pick">clawmont-cc doctor</code>.</p>
  </section>

  <footer>Generated locally by <code>clawmont-cc audit</code>. This page loads no external resource and makes no network request.</footer>
</main>
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export function parseArgs(argv) {
  const opts = {
    json: false, open: true, file: null, out: null, help: false,
    sibling: true, siblingOnly: false, force: false, unknown: [],
    // The window, as the user spelled it. Resolved to a boundary in `main`, so
    // an unparseable value can be REPORTED rather than silently becoming a
    // narrower report.
    since: DEFAULT_WINDOW_SPEC,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--since') opts.since = argv[++i] ?? '';
    else if (a === '--all') opts.since = WINDOW_ALL;
    else if (a === '--json') opts.json = true;
    else if (a === '--no-open') opts.open = false;
    else if (a === '--file') opts.file = argv[++i] ?? null;
    else if (a === '--out') opts.out = argv[++i] ?? null;
    else if (a === '--no-sibling') opts.sibling = false;
    // How the hook calls us: refresh `.clawmont/audit.html` and nothing else —
    // no temp copy, no browser, no summary on a stdio that is `ignore` anyway.
    else if (a === '--sibling-only') { opts.siblingOnly = true; opts.open = false; }
    else if (a === '--force') opts.force = true;
    else if (a === '--help' || a === '-h' || a === 'help') opts.help = true;
    else opts.unknown.push(a);
  }
  return opts;
}

/**
 * Where the report goes without `--out`: one STABLE file per project, inside a
 * directory under the OS temp dir that only this user can write to.
 *
 * Stable, because the Stop receipt links to this path. A link is only useful if
 * it survives the next turn, so the report is a file that gets refreshed rather
 * than a new file each run.
 *
 * Safe, because a predictable path plus a symlink-following `writeFileSync` is
 * an arbitrary-file-overwrite on a shared `/tmp`: another user pre-plants a
 * symlink and our write lands wherever it points — including back inside
 * `.clawmont/`, the one place this module promises never to write. The
 * protection is the CONTAINING DIRECTORY: created 0700, then checked to be a
 * real directory we own with no group/other access. Nobody else can plant
 * anything inside a directory only we may write to. If any of that cannot be
 * established, we fall back to an unguessable `mkdtemp` name — a link that
 * changes is a smaller loss than a write we cannot vouch for.
 */
export function defaultOutPath(auditFile) {
  const project = basename(dirname(dirname(resolve(auditFile)))) || 'project';
  const slug = project.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 40) || 'project';
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'u';
  const dir = join(tmpdir(), `clawmont-reports-${uid}`);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const st = lstatSync(dir);
    const exclusivelyOurs = st.isDirectory()
      && !st.isSymbolicLink()
      && (typeof process.getuid !== 'function' || st.uid === process.getuid())
      && (process.platform === 'win32' || (st.mode & 0o077) === 0);
    if (!exclusivelyOurs) throw new Error('report directory is not exclusively ours');
    return join(dir, `${slug}.html`);
  } catch {
    return join(mkdtempSync(join(tmpdir(), 'clawmont-audit-')), `${slug}.html`);
  }
}

// ---------------------------------------------------------------------------
// The sibling report — `.clawmont/audit.html`, next to `.clawmont/audit.jsonl`.
// ---------------------------------------------------------------------------

/** The one filename we own inside `.clawmont/`. */
export const SIBLING_NAME = 'audit.html';

/** The control directory, by name — the sibling only exists inside one. */
const CONTROL_DIR = '.clawmont';

/**
 * How long a sibling report is considered current.
 *
 * The hook rebuilds this file on `Stop`, which fires on EVERY assistant turn. A
 * rebuild reads the whole trail and spawns the chain verifier, so an unthrottled
 * refresh would be a full re-parse per turn forever. Five minutes is the trade:
 * long enough that a working session pays for a handful of rebuilds instead of
 * hundreds, short enough that the page a user clicks is about as current as the
 * turn they just watched. The page stamps its own age, so the staleness is
 * stated rather than hidden.
 */
export const SIBLING_WINDOW_MS = 5 * 60 * 1000;

/**
 * Where this trail's sibling report goes — or null when there is no such place.
 *
 * Null for anything that is not a project trail at `<project>/.clawmont/
 * audit.jsonl`. `--file /tmp/whatever.jsonl` must not drop an `audit.html` into
 * `/tmp`: the sibling's whole purpose is to sit in the folder the user already
 * opens, and a trail outside a project has no such folder.
 */
export function siblingReportPath(auditFile) {
  const abs = resolve(auditFile);
  if (basename(abs) !== 'audit.jsonl') return null;
  const dir = dirname(abs);
  if (basename(dir) !== CONTROL_DIR) return null;
  return join(dir, SIBLING_NAME);
}

/**
 * Should the sibling be rebuilt right now? The single definition of the throttle.
 *
 * Two independent reasons to skip, both cheap enough to ask on a hot path
 * (two `stat`s, no read):
 *
 *   · **Written recently.** Inside `windowMs` the answer is no, whatever else
 *     changed. This is the clause that bounds cost, and it is the only one the
 *     hook re-implements — see `refreshSiblingReport` in clawmont-hook.mjs,
 *     whose pre-filter is deliberately a STRICT SUBSET of this test so it can
 *     never skip a refresh this function would have granted.
 *   · **Nothing new to show.** If the trail has not changed since the report was
 *     written, a rebuild produces the same bytes. Growth is what makes the next
 *     windowed refresh worth doing; a quiet project rebuilds nothing, forever.
 *
 * A missing report is always due — the first one has to come from somewhere.
 * So is a report that is not a regular file: a symlink sitting on that name is
 * either a mistake or a plant, and `writeReportFile` replaces the NAME rather
 * than following it.
 *
 * `mtime`, not size, is what "changed" means here. It catches a truncation or
 * an overwrite as well as an append, and an audit trail that shrank is exactly
 * the case a stale report must not survive.
 */
export function siblingRefreshDue(auditFile, { now = Date.now(), windowMs = SIBLING_WINDOW_MS } = {}) {
  const out = siblingReportPath(auditFile);
  if (!out) return { due: false, out: null, why: 'not a project trail' };

  let trail;
  try {
    trail = statSync(auditFile);
  } catch {
    return { due: false, out, why: 'no trail to report on' };
  }

  let report;
  try {
    report = lstatSync(out);
  } catch {
    return { due: true, out, why: 'no report yet' };
  }
  if (!report.isFile()) return { due: true, out, why: 'report is not a regular file' };
  // The one case that outranks the throttle: the page currently on screen says
  // "nothing has been recorded here yet" and something now has been. Leaving
  // that page up for the next five minutes teaches a new user that the product
  // does not work. Bounded by size, so this is a small read on a small file and
  // never touches a real report (design §8.4).
  if (trail.size > 0 && report.size > 0 && report.size <= EMPTY_REPORT_PROBE_BYTES) {
    try {
      if (readFileSync(out, 'utf8').includes(EMPTY_REPORT_MARKER)) {
        return { due: true, out, why: 'first record after an empty report' };
      }
    } catch { /* unreadable report — the tests below still decide */ }
  }
  if (now - report.mtimeMs < windowMs) return { due: false, out, why: 'refreshed recently' };
  if (trail.mtimeMs <= report.mtimeMs) return { due: false, out, why: 'trail unchanged since the report' };
  return { due: true, out, why: 'trail changed' };
}

/**
 * Write a report the way a file that already has readers has to be written.
 *
 * Temp file in the same directory, then `rename`. Two things fall out of that,
 * and both are the reason it is not a plain `writeFileSync`:
 *
 *  · **A reader never sees half a page.** `rename` is atomic within a
 *    filesystem, so the browser either gets the old report or the new one. A
 *    truncate-then-write leaves a window where it gets neither.
 *  · **A symlink on the destination is REPLACED, not followed.** This matters
 *    concretely: the hook runs this as the user, so a symlink pre-planted at
 *    `.clawmont/audit.html` and pointed at `~/.zshrc` would turn our own
 *    refresh into an arbitrary-file overwrite. `rename` swaps the name.
 *
 * The temp file is created exclusively (`wx`) with an unpredictable suffix, so
 * the same trick cannot be played one level down on the temp name either.
 */
export function writeReportFile(outPath, html) {
  const dir = dirname(outPath);
  const suffix = `${process.pid.toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  const tmp = join(dir, `.${basename(outPath)}.${suffix}.tmp`);
  try {
    writeFileSync(tmp, html, { flag: 'wx' });
    renameSync(tmp, outPath);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* nothing to clean up */ }
    throw err;
  }
  return outPath;
}

// ---------------------------------------------------------------------------
// PAUSE — "stop blocking for an hour", with the hour actually enforced
// ---------------------------------------------------------------------------
//
// A block with no recourse gets the product uninstalled, and the recourse a
// person reaches for first is not a per-command grant, it is "leave me alone for
// a bit". So `clawmont-cc pause` exists, and every property below is there to
// stop it becoming the off switch this product must not have.
//
//  · BOUNDED, ALWAYS. 15 minutes to 24 hours, one hour by default, and no
//    permanent option. A duration we cannot parse becomes the default, never
//    infinity — the same failure direction the allowlist takes.
//  · ONE PROJECT. It writes the project's own `.clawmont/hook-config.json`, so
//    the pause covers the project the human is standing in and nothing else.
//  · IT STILL RECORDS. `monitor` is the mode it sets, which inspects every call
//    and appends every row; only denial stops. The user is told that.
//  · SHORTER THAN A GRANT'S CEILING ON PURPOSE. A one-command grant may run
//    seven days; a pause covers every finding in the project, so 24 hours is the
//    ceiling. Breadth buys a shorter clock.
export const PAUSE_DEFAULT_MINUTES = 60;
export const PAUSE_MIN_MINUTES = 15;
export const PAUSE_MAX_MINUTES = 24 * 60;

export const controlConfigPath = (clawmontDir) => join(clawmontDir, 'hook-config.json');

/**
 * The project's `.clawmont/` directory for a trail, or null when the trail is
 * not a project trail. Same test `siblingReportPath` uses, and for the same
 * reason: `--file /tmp/whatever.jsonl` has no project controls to speak about.
 */
export function controlDirFor(auditFile) {
  const abs = resolve(auditFile);
  const dir = dirname(abs);
  return basename(abs) === 'audit.jsonl' && basename(dir) === '.clawmont' ? dir : null;
}

/**
 * The live grants, numbered for `clawmont-cc revoke <n>`.
 *
 * Numbered by grant time, oldest first, so the list a person reads matches the
 * order they created it in. Unlike a finding id these numbers are NOT stable —
 * a grant expiring changes them — which is exactly why the printed revoke
 * command carries the durable `g_` id as well. Revoking is the safe direction:
 * the worst a stale number can do is remove a permission that is still wanted,
 * and the CLI names the subject before it acts either way.
 */
export async function listGrants(clawmontDir, now = new Date()) {
  if (!clawmontDir) return [];
  const mod = await grantModule();
  if (!mod) return null; // the store module is not on this channel — say nothing
  try {
    const store = mod.prune(mod.load(clawmontDir), now);
    return [...store.grants]
      .sort((a, b) => String(a.grantedAt).localeCompare(String(b.grantedAt)))
      .map((g, i) => ({ ...g, n: i + 1 }));
  } catch {
    return []; // an unreadable store is not a reason to fail the report
  }
}

/** "in 3 hours" / "in 6 days" — how long a grant has left, in words. */
export function untilPhrase(iso, now = Date.now()) {
  const hours = (Date.parse(iso) - now) / 3600_000;
  if (!Number.isFinite(hours)) return 'unknown';
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))} minutes`;
  if (hours < 48) return `${Math.round(hours)} hours`;
  return `${Math.round(hours / 24)} days`;
}

/**
 * `15m`, `2h`, `90` (minutes), clamped into the window.
 *
 * Returns `{ minutes, clamped, reason }`. Nothing here can return "forever":
 * `99d` clamps to 24 hours and says so, and unparseable text falls back to the
 * default and says so. A caller printing `reason` is telling the user the truth
 * about what they are getting rather than what they asked for.
 */
export function parsePauseDuration(text) {
  const raw = String(text ?? '').trim().toLowerCase();
  if (!raw) return { minutes: PAUSE_DEFAULT_MINUTES, clamped: false, reason: '' };
  const m = /^(\d+(?:\.\d+)?)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?$/.exec(raw);
  if (!m) {
    return {
      minutes: PAUSE_DEFAULT_MINUTES,
      clamped: true,
      reason: `"${text}" is not a duration — using the ${PAUSE_DEFAULT_MINUTES}-minute default`,
    };
  }
  const n = Number(m[1]);
  const unit = m[2] ?? 'm';
  const factor = /^d/.test(unit) ? 1440 : /^h/.test(unit) ? 60 : 1;
  const asked = n * factor;
  if (!Number.isFinite(asked) || asked <= 0) {
    return { minutes: PAUSE_DEFAULT_MINUTES, clamped: true, reason: `"${text}" is not a duration — using the ${PAUSE_DEFAULT_MINUTES}-minute default` };
  }
  const minutes = Math.round(Math.min(Math.max(asked, PAUSE_MIN_MINUTES), PAUSE_MAX_MINUTES));
  if (minutes === Math.round(asked)) return { minutes, clamped: false, reason: '' };
  return {
    minutes,
    clamped: true,
    reason: asked > PAUSE_MAX_MINUTES
      ? `a pause may not exceed ${PAUSE_MAX_MINUTES / 60} hours — shortened to ${describeMinutes(minutes)}`
      : `a pause may not be shorter than ${PAUSE_MIN_MINUTES} minutes — extended to ${describeMinutes(minutes)}`,
  };
}

export function describeMinutes(minutes) {
  if (minutes < 60) return `${minutes} minutes`;
  const h = minutes / 60;
  return `${Number.isInteger(h) ? h : h.toFixed(1)} ${h === 1 ? 'hour' : 'hours'}`;
}

/** The mode file, parsed. Unreadable or not an object reads as empty. */
export function readControlConfig(clawmontDir) {
  try {
    const parsed = JSON.parse(readFileSync(controlConfigPath(clawmontDir), 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Replace the mode file atomically, preserving every key we did not set.
 *
 * Same temp-then-rename discipline as `writeReportFile`, and for a sharper
 * reason: a half-written `hook-config.json` does not fail to parse loudly, it
 * parses as nothing, and `loadMode()` answers `monitor`. A torn write to this
 * file is a silent disarm.
 */
export function writeControlConfig(clawmontDir, cfg) {
  const out = controlConfigPath(clawmontDir);
  mkdirSync(clawmontDir, { recursive: true });
  const suffix = `${process.pid.toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  const tmp = join(clawmontDir, `.hook-config.json.${suffix}.tmp`);
  try {
    writeFileSync(tmp, `${JSON.stringify(cfg, null, 2)}\n`, { flag: 'wx' });
    renameSync(tmp, out);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* nothing to clean up */ }
    throw err;
  }
  return out;
}

/** What the stored pause means right now. A malformed pause is no pause. */
export function pauseInfo(cfg, now = Date.now()) {
  const p = cfg?.pause;
  const until = p && typeof p.until === 'string' ? Date.parse(p.until) : NaN;
  if (!p || typeof p !== 'object' || Number.isNaN(until)) return { paused: false, expired: false, until: null, restoreMode: null };
  const restoreMode = p.restoreMode === 'enforce' ? 'enforce' : 'monitor';
  return {
    paused: until > now,
    expired: until <= now,
    until: new Date(until).toISOString(),
    restoreMode,
    by: typeof p.by === 'string' ? p.by : '',
  };
}

/**
 * Put enforcement back when the clock runs out — the half that makes the expiry
 * real rather than a promise printed at pause time.
 *
 * This runs from the report, which the hook spawns on every Stop, so it needs no
 * daemon and no scheduled job. Two properties make it safe to run there, and
 * both are load-bearing:
 *
 *  · IT ONLY EVER RAISES. The single write it can perform sets `mode` to
 *    `enforce`, and only when a stored pause of a project that WAS enforcing has
 *    already expired. A pause that was restoring `monitor` needs no write at all,
 *    so there is no code path here that can lower protection.
 *  · IT FAILS SILENT AND CLOSED. Anything unparseable, missing, or unwritable
 *    leaves the file exactly as it is and returns null. A report that cannot
 *    restore enforcement must not also break the report.
 *
 * The durable version of this belongs in the hook, deriving effective mode from
 * the current time on every invocation — see the follow-up note in
 * docs/FOLLOWUPS-2026-08-12-t11-simple-controls.md. Until that lands, this is
 * the honest approximation and its limit is stated on the page: the clock is
 * read when Clawmont next writes a report, not at the instant it expires.
 */
export function reconcilePause(clawmontDir, now = Date.now()) {
  try {
    const cfg = readControlConfig(clawmontDir);
    const info = pauseInfo(cfg, now);
    if (!info.expired) return null;
    const { pause: _dropped, ...rest } = cfg;
    if (info.restoreMode !== 'enforce') {
      // Nothing to restore — drop the stale record only if it is safe to.
      if (cfg.mode === 'monitor' || cfg.mode === undefined) {
        writeControlConfig(clawmontDir, { ...rest, mode: 'monitor' });
        return { restored: 'monitor', until: info.until };
      }
      return null;
    }
    writeControlConfig(clawmontDir, { ...rest, mode: 'enforce' });
    return { restored: 'enforce', until: info.until };
  } catch {
    return null; // a report must never fail because a control file would not budge
  }
}

/**
 * Best-effort open. Returns whether the opener was SPAWNED, not whether it
 * succeeded — a missing `xdg-open` fails with an async ENOENT the try/catch
 * cannot see, so the caller must not turn this into a "done" claim. The error
 * handler keeps that async failure from surfacing as an unhandled event.
 */
export function openInBrowser(path) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [path]]
    : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', path]]
      : ['xdg-open', [path]];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => { /* opener missing — the user still has the path */ });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

const USAGE = `Usage: clawmont-cc audit [--since 7d] [--file <audit.jsonl>] [--out <report.html>] [--json] [--no-open]

Reads the project's .clawmont/audit.jsonl and reports what Clawmont did:
a terminal summary plus a self-contained HTML report (written to the OS
temp dir, opened in your browser). Nothing leaves your machine.

It also refreshes .clawmont/audit.html — the same report, kept next to the
trail, so the folder you already open has a file that opens the dashboard.

THE DEFAULT IS THE LAST 7 DAYS, and the window is named on both surfaces.
An all-time report looks the same every morning, which is why nobody opens
one; the chain verdict is always over the whole file regardless.

  --since <spec>  7d · 24h · 30d · YYYY-MM-DD · all   (default: 7d)
  --all           the same as --since all
  --file <path>   read a different audit trail
  --out <path>    write the HTML report here instead of the temp dir
  --json          print the computed stats as JSON; no HTML, no browser
  --no-open       write the HTML report but do not open it
  --no-sibling    do not touch .clawmont/audit.html`;

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(USAGE);
    return 0;
  }
  for (const u of opts.unknown) console.error(`clawmont-cc audit: ignoring unknown argument ${JSON.stringify(u)}`);

  // A window we cannot read is an ERROR, not a default. The failure this avoids
  // is Snyk's documented one in mirror image: there, a malformed expiry silently
  // became permanent; here, a mistyped `--since` would silently narrow the
  // record. Both are the same bug — a typo quietly changing what is shown.
  const win = parseSince(opts.since);
  if (!win.ok) {
    console.error(`clawmont-cc audit: ${win.reason}`);
    return 2;
  }
  const windowOpts = { since: win.since, windowLabel: win.label, windowSpec: win.spec };

  const file = resolve(opts.file ?? defaultAuditPath());
  const controlDir = controlDirFor(file);
  const project = controlDir ? dirname(controlDir) : null;

  // Put enforcement back if a human's pause has run out. Cheap (one small read,
  // and a write only when there is something to restore), and it runs on the
  // hook's own Stop path so the expiry needs no daemon. See `reconcilePause`.
  if (controlDir) reconcilePause(controlDir);

  if (!existsSync(file)) {
    // A project that has been installed but has not recorded anything yet is the
    // normal first-run state, not an error. It gets the page that says so, so the
    // file a fresh install points at exists before the first call rather than
    // after it.
    const sibling = controlDir ? join(controlDir, SIBLING_NAME) : null;
    if (sibling && !opts.json && opts.sibling) {
      try {
        mkdirSync(controlDir, { recursive: true });
        writeReportFile(sibling, renderEmptyHtml(file, { sibling: true, project }));
        if (!opts.siblingOnly) {
          console.log(`clawmont-cc audit: nothing has been recorded in this project yet.\n\n  in project ${sibling}   (open this one — it fills in after the first tool call)`);
          if (opts.open) openInBrowser(sibling);
        }
        return 0;
      } catch { /* fall through to the error below */ }
    }
    if (opts.siblingOnly) return 0;
    console.error(
      `clawmont-cc audit: no audit trail at ${file}\n` +
      'Nothing has been recorded there yet. Run this from a project the hook guards,\n' +
      'or point at a trail directly: clawmont-cc audit --file <path>/.clawmont/audit.jsonl',
    );
    return 1;
  }

  // The hook's path: decide first, parse nothing if the answer is no. This is
  // the process that Stop spawns on every turn, so the throttle has to be the
  // FIRST thing it does, before an 11 MB stream and a chain verifier.
  if (opts.siblingOnly) {
    const due = opts.force
      ? { due: true, out: siblingReportPath(file), why: 'forced' }
      : siblingRefreshDue(file);
    if (!due.due || !due.out) return 0;
    const siblingGrants = await listGrants(controlDir);
    const stats = await computeStats(file, { ...windowOpts, grants: siblingGrants ?? [] });
    if (stats.window.total === 0 && stats.malformed === 0) {
      writeReportFile(due.out, renderEmptyHtml(file, { sibling: true, project }));
      return 0;
    }
    writeReportFile(due.out, renderHtml(stats, verifyChainStatus(file), {
      sibling: true,
      grants: siblingGrants,
      pause: controlDir ? pauseInfo(readControlConfig(controlDir)) : null,
    }));
    return 0;
  }

  // Grants are read BEFORE the pass, not after: the stream counts the calls each
  // live grant covered, which is what keeps a growing allowlist from quietly
  // shrinking the record.
  const grants = await listGrants(controlDir);
  const stats = await computeStats(file, { ...windowOpts, grants: grants ?? [] });
  const chain = verifyChainStatus(file);
  const controls = {
    grants,
    pause: controlDir ? pauseInfo(readControlConfig(controlDir)) : null,
  };

  if (opts.json) {
    process.stdout.write(JSON.stringify({ ...stats, chain }, null, 2) + '\n');
    return 0;
  }

  console.log(renderTerminalSummary(stats, chain));

  // An existing but zero-row trail still gets a page. The old behaviour returned
  // here, which left the file a fresh install tells people to open missing.
  //
  // The test is on the WHOLE FILE, not the window. A trail with a thousand rows
  // and a quiet week is not "ready to record" — it is a report that says nothing
  // happened lately, and saying "no agent calls have been recorded here yet"
  // about a project with a full trail would be false.
  if (stats.window.total === 0 && stats.malformed === 0) {
    const outPath = resolve(opts.out ?? defaultOutPath(file));
    writeReportFile(outPath, renderEmptyHtml(file, { project }));
    let emptySibling = null;
    const sp = opts.sibling ? siblingReportPath(file) : null;
    if (sp && sp !== outPath) {
      try {
        writeReportFile(sp, renderEmptyHtml(file, { sibling: true, project }));
        emptySibling = sp;
      } catch { /* a read-only .clawmont/ is not a reason to fail the command */ }
    }
    const opened = opts.open ? openInBrowser(outPath) : false;
    console.log(
      '\nThe trail is empty — no calls have been recorded in this project yet.'
      + `\n\n  report     ${outPath}`
      + (emptySibling ? `\n  in project ${emptySibling}   (open this one — it fills in after the first tool call)` : '')
      + (opened ? '\n  opening    in your default browser…' : ''),
    );
    return 0;
  }

  const outPath = resolve(opts.out ?? defaultOutPath(file));
  writeReportFile(outPath, renderHtml(stats, chain, controls));
  const opening = opts.open ? openInBrowser(outPath) : false;

  // The sibling is refreshed unconditionally here: the user asked for this
  // report by name, so the throttle — which exists to bound what the hook does
  // uninvited — has nothing to protect them from.
  let sibling = null;
  const siblingPath = opts.sibling ? siblingReportPath(file) : null;
  if (siblingPath && siblingPath !== outPath) {
    try {
      writeReportFile(siblingPath, renderHtml(stats, chain, { ...controls, sibling: true }));
      sibling = siblingPath;
    } catch (err) {
      // A read-only or missing `.clawmont/` is not a reason to fail the command
      // the user actually ran — say what did not happen and move on.
      console.error(`\n  note       could not refresh ${siblingPath}: ${err?.message ?? err}`);
    }
  }

  // "opening", not "opened": the opener runs detached and may not exist. The
  // path is the guarantee; the browser is best-effort.
  console.log(
    `\n  report     ${outPath}`
    + (sibling ? `\n  in project ${sibling}   (open this one any time — it is refreshed as you work)` : '')
    + (opening ? '\n  opening    in your default browser…' : ''),
  );
  return 0;
}

const isDirectRun = (() => {
  try {
    return import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
})();

if (isDirectRun) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`clawmont-cc audit: ${err?.message ?? err}`);
    process.exit(1);
  });
}
