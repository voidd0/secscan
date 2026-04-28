/* secscan — minimal smoke tests. Run via: node test.js */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanFile, scanPath, redactMid, PATTERNS } = require('./src/scanner');

let passed = 0;
let failed = 0;

function eq(label, actual, expected) {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    console.log(`  ok  ${label}`);
    passed++;
  } else {
    console.log(`  FAIL ${label}`);
    console.log(`     actual:   ${JSON.stringify(actual)}`);
    console.log(`     expected: ${JSON.stringify(expected)}`);
    failed++;
  }
}

function truthy(label, v) {
  if (v) { console.log(`  ok  ${label}`); passed++; }
  else { console.log(`  FAIL ${label}`); failed++; }
}

console.log('redactMid:');
eq('short string fully masked', redactMid('abc', 4, 4), '***');
// Build literal via concat for the same Push Protection reason.
eq('long string preserves prefix/suffix',
   redactMid('gh' + 'p_' + 'abcdef123456789012345678901234567890extra', 4, 4),
   'gh' + 'p_' + '...(37 chars)...xtra');

console.log('\nscanFile fixtures:');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-test-'));
const f = path.join(tmp, 'leak.txt');

// Build secret fixture strings via concat so the literal tokens never appear
// contiguous in source — keeps GitHub Push Protection from blocking our test
// file as if it contained real secrets. Our scanner's regex still matches at
// runtime once the concatenated string lands in the temp file.
const ghpFixture     = 'gh' + 'p_' + 'q4pOyqTel7nsouOTLqdB6xs74shoxn2WibHy123456';
const awsFixture     = 'AK' + 'IA' + 'IOSFODNN7EXAMPLE';
const stripeFixture  = 'sk' + '_live_' + 'FAKEFIXTUREONLY1234567890ABCDEFG';

fs.writeFileSync(f,
  'line one\n' +
  'GH_TOKEN=' + ghpFixture + '\n' +
  '# innocent code\n' +
  'AWS_KEY = "' + awsFixture + '"\n' +
  'STRIPE = ' + stripeFixture + '\n' +
  '\n');

const found = scanFile(f);
truthy('found at least 3 leaks',  found.length >= 3);
truthy('detected github_pat_classic', found.some(x => x.kind === 'github_pat_classic'));
truthy('detected aws_access_key',     found.some(x => x.kind === 'aws_access_key'));
truthy('detected stripe_live',         found.some(x => x.kind === 'stripe_live'));
truthy('preview is redacted by default', found[0].preview.includes('...'));

const noRedact = scanFile(f, { redact: false });
truthy('no-redact returns full match', noRedact[0].preview.startsWith('ghp_'));

console.log('\nscanPath ignores defaults:');
fs.mkdirSync(path.join(tmp, 'node_modules'), { recursive: true });
fs.writeFileSync(path.join(tmp, 'node_modules', 'leak.txt'),
  awsFixture + '\n');
const dirFindings = scanPath(tmp);
truthy('node_modules ignored by default',
  !dirFindings.some(x => x.file.includes('node_modules')));

console.log('\npattern coverage:');
truthy('at least 15 detectors registered', PATTERNS.length >= 15);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
