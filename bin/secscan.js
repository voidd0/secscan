#!/usr/bin/env node
'use strict';

const path = require('path');
const { scanPath, PATTERNS } = require('../src/scanner');

function help() {
  console.log(`secscan — scan a path for accidentally-committed secrets

Usage:
  secscan [path]            scan path (default: cwd)
  secscan --json [path]     emit JSON findings instead of human output
  secscan --no-redact [p]   show full secret value (DANGEROUS, for one-off triage)
  secscan --list-patterns   show every detector this build ships with
  secscan --help            this message

Exit code:
  0  no findings
  1  findings present
  2  invalid args / IO error
`);
}

function listPatterns() {
  console.log('detectors shipped:');
  for (const p of PATTERNS) {
    console.log(`  ${p.severity.padEnd(8)} ${p.kind}`);
  }
}

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
const COLOR = process.stdout.isTTY ? {
  red: s => `\x1b[31m${s}\x1b[0m`,
  yellow: s => `\x1b[33m${s}\x1b[0m`,
  cyan: s => `\x1b[36m${s}\x1b[0m`,
  dim: s => `\x1b[2m${s}\x1b[0m`,
  bold: s => `\x1b[1m${s}\x1b[0m`,
} : { red: s => s, yellow: s => s, cyan: s => s, dim: s => s, bold: s => s };

function severityColor(sev) {
  if (sev === 'critical') return COLOR.red;
  if (sev === 'high') return COLOR.yellow;
  if (sev === 'medium') return COLOR.cyan;
  return COLOR.dim;
}

function main() {
  const args = process.argv.slice(2);
  const opts = { redact: true, json: false };
  let target = '.';

  for (const a of args) {
    if (a === '--help' || a === '-h') return help();
    if (a === '--list-patterns') return listPatterns();
    if (a === '--json') { opts.json = true; continue; }
    if (a === '--no-redact') { opts.redact = false; continue; }
    if (a.startsWith('--')) {
      console.error(`unknown flag: ${a}`);
      process.exit(2);
    }
    target = a;
  }

  let findings;
  try {
    findings = scanPath(path.resolve(target), opts);
  } catch (ex) {
    console.error('secscan: ' + ex.message);
    process.exit(2);
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify({ findings, count: findings.length }, null, 2) + '\n');
    process.exit(findings.length ? 1 : 0);
  }

  if (findings.length === 0) {
    console.log(COLOR.dim('no secrets found.'));
    process.exit(0);
  }

  // Group by severity, descending
  findings.sort((a, b) => (SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]));
  const tally = {};
  for (const f of findings) {
    tally[f.severity] = (tally[f.severity] || 0) + 1;
    const sevLabel = severityColor(f.severity)(`[${f.severity}]`.padEnd(11));
    const loc = COLOR.dim(`${f.file}:${f.line}:${f.col}`);
    console.log(`${sevLabel} ${COLOR.bold(f.kind.padEnd(22))} ${f.preview}`);
    console.log(`            ${loc}`);
  }
  console.log('');
  const tallyParts = Object.entries(tally).map(([k, v]) => `${v} ${k}`);
  console.log(COLOR.bold(`${findings.length} finding${findings.length === 1 ? '' : 's'} (${tallyParts.join(', ')})`));
  process.exit(1);
}

main();
