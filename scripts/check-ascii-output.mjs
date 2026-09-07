#!/usr/bin/env node
// Refuse non-ASCII characters inside Java string literals under src/main.
//
// Why this exists: bash writes UTF-8 bytes straight through, but Java re-encodes System.out
// through the console charset, which on a Windows console is not UTF-8. An em-dash or a ✅ in a
// printed literal therefore arrives as "?" — and the lines that suffered were gate verdicts
// ("[GATE] PASS ?") and the one Heimdall line that says enforcement is switched off. Prose in
// comments and javadoc never reaches a console, so it is left alone.
//
//   node scripts/check-ascii-output.mjs          # exit 1 and list every offender
//
// This is not a gate; it asserts about the source, not about behavior. CI runs it because the
// failure mode is invisible on the platform CI runs on.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';

const SKIP = new Set(['target', '.git', 'build', 'node_modules']);
// A Java string literal: double-quoted, backslash escapes consume the next character.
const LITERAL = /"(?:[^"\\]|\\.)*"/g;

function* javaSources(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* javaSources(p);
    else if (name.endsWith('.java') && p.includes(`src${sep}main${sep}`)) yield p;
  }
}

const offenders = [];
for (const file of javaSources(process.argv[2] ?? '.')) {
  readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
    const t = line.trimStart();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;
    for (const lit of line.match(LITERAL) ?? []) {
      const bad = [...new Set([...lit].filter((c) => c.charCodeAt(0) > 127))];
      if (bad.length) {
        const codes = bad.map((c) => 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0'));
        offenders.push(`${file}:${i + 1}  ${codes.join(' ')}  ${line.trim().slice(0, 110)}`);
        break;
      }
    }
  });
}

if (offenders.length) {
  console.error('non-ASCII in Java string literals (a Windows console prints these as "?"):');
  for (const o of offenders) console.error('  ' + o);
  console.error(`\n${offenders.length} line(s). Use "-" for an em-dash, "->" for an arrow, and no emoji.`);
  process.exit(1);
}
console.log('ascii-output OK: no non-ASCII in any Java string literal under src/main');
