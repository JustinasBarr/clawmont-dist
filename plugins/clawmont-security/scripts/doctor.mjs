#!/usr/bin/env node
/**
 * `/clawmont:doctor` — does this plugin actually protect anything?
 *
 * The question is behavioural, not structural, and the difference is the whole
 * reason this file exists. A structural check ("the plugin directory is there,
 * the hook file is there") is exactly what passed on every machine where the
 * detection core was unreachable, the hook fell open on every call, and the
 * only visible artifact was a green checkmark. Resolving a path proves the path
 * resolves; only a blocked attack proves the thing works.
 *
 * So this spawns the real hook — the same file `hooks/hooks.json` points Claude
 * Code at — feeds it one payload that must be denied and one that must not, and
 * prints both verdicts.
 *
 * It reports; it never changes anything.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const PLUGIN_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const projectDir = process.env.CLAUDE_PROJECT_DIR ?? process.cwd();

const version = (() => {
  try {
    return JSON.parse(readFileSync(join(PLUGIN_ROOT, '.claude-plugin', 'plugin.json'), 'utf8')).version;
  } catch {
    return 'unknown';
  }
})();

console.log(`clawmont-security ${version} — doctor\n`);

const { preflight, coreReport } = await import(join(PLUGIN_ROOT, 'preflight.mjs'));

// 1. Where the detection core resolved — asked of the hook itself, never
//    re-derived here. A second copy of the resolution logic can agree with
//    itself while disagreeing with what the hook will actually load.
const core = coreReport();
console.log('detection core');
for (const c of core.candidates ?? []) {
  console.log(`  ${c.exists ? '✓' : '✗'} ${String(c.source).padEnd(22)} ${c.path}`);
}
console.log(core.resolved ? `  → using ${core.source}: ${core.path}` : '  → NOTHING RESOLVED');

// 2. The verdicts. Both directions, because either alone passes for the wrong
//    reason: a hook that denies everything blocks the attack, and a hook that
//    inspects nothing allows the benign command.
const result = preflight();
console.log('\nbehaviour (the real hook, spawned exactly as Claude Code spawns it)');
for (const c of result.checks) console.log(`  ${c.ok ? '✓' : '✗'} ${c.label.padEnd(38)} ${c.detail}`);

// 3. Mode. Blocking is opt-in; monitor is the shipped default, and a user who
//    believes they are protected while running in monitor mode is a worse
//    outcome than one who knows they are only watching.
const configPath = join(projectDir, '.clawmont', 'hook-config.json');
let mode = 'monitor (default — never blocks)';
if (process.env.CLAWMONT_CC_MODE) {
  mode = `${process.env.CLAWMONT_CC_MODE} (from CLAWMONT_CC_MODE)`;
} else if (existsSync(configPath)) {
  try {
    const cfg = JSON.parse(readFileSync(configPath, 'utf8'));
    if (cfg.mode) mode = `${cfg.mode} (from ${configPath})`;
  } catch {
    mode = `unreadable config at ${configPath} — falling back to monitor`;
  }
}
console.log('\nconfiguration');
console.log(`  mode          : ${mode}`);
console.log(`  kill switch   : ${process.env.CLAWMONT_CC_DISABLE ? 'ON — the hook is disabled' : 'off (set CLAWMONT_CC_DISABLE=1 to disable)'}`);
console.log(`  audit trail   : ${join(projectDir, '.clawmont', 'audit.jsonl')}`);

// 4. The one thing a plugin install cannot do for you.
//
//    The npm installer appends `.clawmont/` to .gitignore; a marketplace plugin
//    never runs an installer, so nothing has. The audit trail stores an excerpt
//    of every flagged call, and an excerpt of a call that handled a credential
//    contains credential-shaped text. The hook redacts before writing, but
//    redaction is a best-effort net over a channel the model controls — so the
//    trail must not be one `git add -A` away from a public repo.
if (existsSync(join(projectDir, '.git'))) {
  const gitignore = join(projectDir, '.gitignore');
  const ignored = existsSync(gitignore)
    && readFileSync(gitignore, 'utf8').split('\n').some((l) => l.trim() === '.clawmont/');
  console.log(`  gitignore     : ${ignored ? '✓ .clawmont/ is ignored' : '✗ .clawmont/ is NOT ignored — add it before committing'}`);
}

if (result.ok) {
  console.log('\n✓ Clawmont is working — an attack was blocked and an ordinary command was not.');
  process.exit(0);
}

console.error(
  '\n✗ Clawmont is NOT protecting this session.\n' +
  (result.unprotected
    ? '  The detection core could not be loaded. For a marketplace install this means\n' +
      '  the plugin directory is incomplete — reinstall it:\n' +
      '    /plugin uninstall clawmont-security\n' +
      '    /plugin install clawmont-security@clawmont\n'
    : '  The hook ran but returned the wrong verdicts. Do not rely on it.\n') +
  '  Detail: https://clawmont.com\n',
);
process.exit(1);
