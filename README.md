# secscan

Find accidentally-committed credentials in any source tree. Zero deps, fast, redacts by default.

```
$ secscan
[critical]  github_pat_classic     ghp_...(32 chars)...ibHy
            ./scripts/deploy.sh:14:11
[critical]  aws_access_key         AKIA...(12 chars)...MPLE
            ./.env.example:5:9

2 findings (2 critical)
```

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

## License

MIT — part of the [vøiddo](https://voiddo.com) tools collection.

---

Built by [vøiddo](https://voiddo.com/) — a small studio shipping AI-flavoured products, free dev tools, Chrome extensions and weird browser games.
