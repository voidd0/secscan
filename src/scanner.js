// secscan — find accidentally-committed credentials in source trees.
// Patterns tuned for high precision (we'd rather miss a weird custom format
// than yell about every base64 string in the codebase).

'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_IGNORES = new Set([
  '.git', 'node_modules', 'dist', 'build', '.venv', 'venv',
  '.next', '.nuxt', '.svelte-kit', 'coverage', '.cache',
  '.idea', '.vscode', 'target', '.gradle', '.mvn',
]);

const BINARY_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff',
  '.pdf', '.zip', '.gz', '.tar', '.bz2', '.7z', '.rar',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.mov',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.so', '.dll', '.dylib', '.exe', '.bin', '.class',
]);

function redactMid(s, keepStart = 4, keepEnd = 4) {
  if (s.length <= keepStart + keepEnd + 3) return s.replace(/./g, '*');
  return s.slice(0, keepStart) + '...(' + (s.length - keepStart - keepEnd) + ' chars)...' + s.slice(-keepEnd);
}

const PATTERNS = [
  { kind: 'github_pat_classic',  re: /\bghp_[A-Za-z0-9]{36,}\b/g,        severity: 'critical' },
  { kind: 'github_pat_fine',     re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, severity: 'critical' },
  { kind: 'github_oauth',        re: /\bgho_[A-Za-z0-9]{36,}\b/g,        severity: 'critical' },
  { kind: 'github_user_token',   re: /\bghu_[A-Za-z0-9]{36,}\b/g,        severity: 'critical' },
  { kind: 'github_server_token', re: /\bghs_[A-Za-z0-9]{36,}\b/g,        severity: 'critical' },
  { kind: 'github_refresh',      re: /\bghr_[A-Za-z0-9]{36,}\b/g,        severity: 'critical' },
  { kind: 'aws_access_key',      re: /\bAKIA[0-9A-Z]{16}\b/g,            severity: 'critical' },
  { kind: 'aws_temp_key',        re: /\bASIA[0-9A-Z]{16}\b/g,            severity: 'critical' },
  { kind: 'slack_bot_token',     re: /\bxoxb-[0-9A-Za-z\-]{20,}\b/g,     severity: 'high' },
  { kind: 'slack_user_token',    re: /\bxoxp-[0-9A-Za-z\-]{20,}\b/g,     severity: 'high' },
  { kind: 'slack_webhook',       re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g, severity: 'high' },
  { kind: 'stripe_live',         re: /\bsk_live_[A-Za-z0-9]{20,}\b/g,    severity: 'critical' },
  { kind: 'stripe_test',         re: /\bsk_test_[A-Za-z0-9]{20,}\b/g,    severity: 'medium' },
  { kind: 'stripe_publish',      re: /\bpk_live_[A-Za-z0-9]{20,}\b/g,    severity: 'low' },
  { kind: 'openai_key',          re: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/g, severity: 'critical' },
  { kind: 'openai_proj_key',     re: /\bsk-proj-[A-Za-z0-9_\-]{40,}\b/g, severity: 'critical' },
  { kind: 'anthropic_key',       re: /\bsk-ant-[A-Za-z0-9_\-]{40,}\b/g,  severity: 'critical' },
  { kind: 'google_api_key',      re: /\bAIza[A-Za-z0-9_\-]{35}\b/g,      severity: 'high' },
  { kind: 'jwt',                 re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g, severity: 'medium' },
  { kind: 'sendgrid',            re: /\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}\b/g, severity: 'high' },
  { kind: 'npm_token',           re: /\bnpm_[A-Za-z0-9]{36,}\b/g,        severity: 'critical' },
  { kind: 'pem_private_key',     re: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP |)PRIVATE KEY-----/g, severity: 'critical' },
];

function listFiles(root, ignores, depth, max_depth) {
  const out = [];
  if (depth > max_depth) return out;
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (_) { return out; }
  for (const entry of entries) {
    if (ignores.has(entry.name)) continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      out.push(...listFiles(full, ignores, depth + 1, max_depth));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (BINARY_EXTS.has(ext)) continue;
      try {
        const stat = fs.statSync(full);
        if (stat.size > 5 * 1024 * 1024) continue;
      } catch (_) { continue; }
      out.push(full);
    }
  }
  return out;
}

function scanFile(filepath, opts) {
  opts = opts || {};
  const findings = [];
  let content;
  try {
    content = fs.readFileSync(filepath, 'utf8');
  } catch (_) { return findings; }
  if (content.indexOf('\u0000') !== -1) return findings;

  const lines = content.split(/\r?\n/);
  for (const pat of PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      pat.re.lastIndex = 0;
      let m;
      while ((m = pat.re.exec(line)) !== null) {
        const match = m[0];
        findings.push({
          file: filepath,
          line: i + 1,
          col: m.index + 1,
          kind: pat.kind,
          severity: pat.severity,
          preview: opts.redact === false ? match : redactMid(match),
        });
      }
    }
  }
  return findings;
}

function scanPath(target, opts) {
  opts = opts || {};
  const ignores = opts.ignores
    ? new Set([...DEFAULT_IGNORES, ...opts.ignores])
    : DEFAULT_IGNORES;
  const stat = fs.statSync(target);
  if (stat.isFile()) return scanFile(target, opts);
  const files = listFiles(target, ignores, 0, 64);
  const findings = [];
  for (const f of files) findings.push(...scanFile(f, opts));
  return findings;
}

module.exports = { PATTERNS, scanFile, scanPath, redactMid, DEFAULT_IGNORES };
