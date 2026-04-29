# secscan

[![npm version](https://img.shields.io/npm/v/@v0idd0/secscan.svg?color=A0573A)](https://www.npmjs.com/package/@v0idd0/secscan)
[![npm downloads](https://img.shields.io/npm/dw/@v0idd0/secscan.svg?color=1F1A14)](https://www.npmjs.com/package/@v0idd0/secscan)
[![License: MIT](https://img.shields.io/badge/license-MIT-A0573A.svg)](LICENSE)
[![Node ≥14](https://img.shields.io/badge/node-%E2%89%A514-1F1A14)](package.json)

Find accidentally-committed credentials in any source tree. Zero deps, fast, redacts by default.

```
$ secscan
[critical]  github_pat_classic     ghp_...(32 chars)...ibHy
            ./scripts/deploy.sh:14:11
[critical]  aws_access_key         AKIA...(12 chars)...MPLE
            ./.env.example:5:9

2 findings (2 critical)
```

## Why secscan

You're about to commit. Your `.env.example` was supposed to have placeholders. Three minutes ago, in a hurry, you copy-pasted real values to test something and forgot to redact. The classic Friday-evening leak. secscan is a pre-commit guard that catches the high-confidence patterns (PATs, AWS keys, OpenAI keys, PEM blocks) and refuses the commit before the leak hits a remote.

## Install

```bash
npm install -g @v0idd0/secscan
```

## Usage

```bash
# Scan current directory
secscan

# Scan a specific path
secscan ./src

# JSON output for CI / programmatic use
secscan --json | jq '.findings[] | select(.severity=="critical")'

# Show full secret value (DANGEROUS, for one-off triage)
secscan --no-redact ./broken-checkout

# List all detectors this build ships with
secscan --list-patterns
```

## What it detects

| kind | severity |
|---|---|
| GitHub classic PAT (`ghp_…`) | critical |
| GitHub fine-grained PAT (`github_pat_…`) | critical |
| GitHub OAuth / app / refresh tokens | critical |
| AWS Access Key / Temporary Key (`AKIA…` / `ASIA…`) | critical |
| Stripe live secret key (`sk_live_…`) | critical |
| OpenAI API key (sk-…T3BlbkFJ…) | critical |
| OpenAI project key (`sk-proj-…`) | critical |
| Anthropic API key (`sk-ant-…`) | critical |
| npm publish token (`npm_…`) | critical |
| PEM private key blocks (RSA / OpenSSH / EC / DSA / PGP) | critical |
| Slack bot/user tokens, incoming webhooks | high |
| SendGrid API keys | high |
| Google API key (`AIza…`) | high |
| Generic JWT (3-segment base64url) | medium |
| Stripe test secret key (`sk_test_…`) | medium |
| Stripe publishable key (`pk_live_…`) | low |

Patterns are tuned for high precision — we'd rather miss a weird custom format than yell about every base64 string in the codebase.

## What it ignores

By default: `.git`, `node_modules`, `dist`, `build`, `.venv`, `venv`, `.next`, `.nuxt`, `.svelte-kit`, `coverage`, `.cache`, `.idea`, `.vscode`, `target`, `.gradle`, `.mvn`. Binary files (PNG/JPG/PDF/ZIP/MP3/etc.) are skipped automatically. Files larger than 5 MB are skipped (set a smaller limit by piping individual files).

## Compared to alternatives

| tool | install | precision (false positives) | speed on 1M LOC | runs offline |
|---|---|---|---|---|
| secscan | one npm install | high (curated patterns) | <2s | yes |
| `gitleaks` | go binary or docker | medium-high | seconds | yes |
| `trufflehog` | go binary | high (active verifier) | minutes (does HTTP) | partial |
| GitHub secret scanning | GitHub-only | very high (vendor partners) | server-side | no |

If you operate at scale and want active credential verification (does this stripe key still work?), `trufflehog` is the right pick. For a fast pre-commit / pre-push gate that just needs to refuse obvious leaks, secscan is faster typing and faster running.

## FAQ

**Will it catch a custom-format API key our backend issues?** Probably not — we don't pattern-match on entropy alone (too many false positives). If you want your custom format covered, send a PR with a regex and a test fixture.

**Why redact by default?** Because the typical use case is "scan and tell me if there's a problem", not "show me the secret". When you need the secret to investigate (which char position got pasted?), `--no-redact` exists; we just don't make it the default.

**False positive on `sk-...` short strings?** OpenAI key pattern is `^sk-` plus a known suffix substring (`T3BlbkFJ`) plus a length range. Short `sk-` strings (`sk-test_…` examples in test fixtures) don't match.

**Pre-commit hook?** See the snippet below.

## Pre-commit usage

```bash
# .git/hooks/pre-commit
#!/bin/bash
secscan --json . | jq -e '.count == 0' > /dev/null || {
  echo "secscan found credentials in your tree — fix before committing."
  secscan
  exit 1
}
```

Exit code is `1` if any findings, `0` if clean — wire it into pre-commit / CI directly.

## Programmatic API

```javascript
import { scanPath, scanFile, PATTERNS } from '@v0idd0/secscan';

const findings = scanPath('./my-repo');
for (const f of findings) {
  if (f.severity === 'critical') alertOps(f);
}
```

## More from the studio

This is one tool out of many — see [`from-the-studio.md`](from-the-studio.md) for the full lineup of vøiddo products (other CLI tools, browser extensions, the studio's flagship products and games).

## From the same studio

- **[@v0idd0/jsonyo](https://www.npmjs.com/package/@v0idd0/jsonyo)** — JSON swiss army knife, 18 commands, zero limits
- **[@v0idd0/envguard](https://www.npmjs.com/package/@v0idd0/envguard)** — stop shipping `.env` drift to staging
- **[@v0idd0/depcheck](https://www.npmjs.com/package/@v0idd0/depcheck)** — find unused dependencies in one command
- **[@v0idd0/gitstats](https://www.npmjs.com/package/@v0idd0/gitstats)** — git repo analytics, one command
- **[View all tools →](https://voiddo.com/tools/)**

## License

MIT.

---

Built by [vøiddo](https://voiddo.com/) — a small studio shipping AI-flavoured products, free dev tools, Chrome extensions and weird browser games.
