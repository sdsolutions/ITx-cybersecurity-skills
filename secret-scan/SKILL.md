---
name: secret-scan
description: >
  Scan a local directory, glob, git repo, or URL for leaked credentials embedded in source code, config, logs, or dotfiles — AWS keys, GitHub tokens, Slack tokens, Anthropic/OpenAI/HuggingFace API keys, npm/PyPI/Docker Hub tokens, Atlassian/DataDog/Sentry/ngrok tokens, generic JWTs, PEM private keys, database URIs with credentials, and more (48+ patterns seeded from the Claude-OSINT regex catalog). Scan-only — never writes, edits, revokes, or reports the finding to the credential issuer. Complements /metadata-scan (which finds embedded metadata in binaries); /secret-scan finds credentials in text. Use when the user says "secret scan", "credential scan", "leaked keys check", "scan for API keys", "grep for tokens", "audit repo for credentials", or invokes "/secret-scan".
argument-hint: "<path-or-url-or-git-repo> [--recursive] [--include-hidden] [--include-history] [--severity-min low|medium|high|critical]"
license: Proprietary source-available
---

# Secret Scan (Scan-only)

Scan text-form sources for embedded credentials. **This skill never writes, edits, or revokes** — it only reports. Rotation is the human's decision (or a separate follow-up flow).

## Preflight

```bash
# ripgrep gives ~50x speedup vs pure Python; fall back to grep -RE if missing.
which rg >/dev/null 2>&1 && RG=rg || RG="grep -RE"
```

`ripgrep` (`brew install ripgrep`) is strongly recommended. Without it the skill falls back to `grep -RE` — works, just slower.

## Input handling

Accept one of:

- **Local path** — file, dir, or shell glob (e.g. `./src/**/*.{js,ts,py,env,yml}`).
- **git repo URL** — clone shallow to `/tmp/secret-scan-<hash>`, scan, delete on completion.
- **git repo URL + `--include-history`** — clone full history (`--no-single-branch`, no depth), then use `git log -p` to scan every commit's diff. Catches secrets that were committed and later reverted but still live in git history. Slow — hours for a big repo.
- **URL to a file** — `curl -sSf` into temp, scan, delete.

Skip binary files (`file --mime` says non-text), files > 20 MB by default, generated files with obvious `-lock.` / `.min.js` / `.bundle.js` / `dist/` / `build/` / `node_modules/` / `vendor/` / `venv/` / `.venv/` / `__pycache__/` markers unless `--include-hidden` is set (some real leaks *do* end up in lockfiles and minified bundles).

## Detection patterns

Seeded from the 48-pattern Claude-OSINT catalog at `wiki/sources/claude-osint/secret-regex-catalog.md` plus a small extension set. Categorized by service:

### AI / LLM
- Anthropic `sk-ant-api03-…` / `sk-ant-…`
- OpenAI `sk-[A-Za-z0-9]{32,}` / `sk-proj-…`
- Hugging Face `hf_[A-Za-z0-9]{34,}`
- Cohere / Replicate / Together / Groq keys

### Cloud
- AWS Access Key `AKIA[0-9A-Z]{16}` + secret `[A-Za-z0-9/+=]{40}`
- AWS Session Token `(?:AKIA|ASIA)[0-9A-Z]{16}`
- GCP Service Account JSON (detect by structure — `type: service_account`, `private_key`, `client_email`)
- Azure Storage `DefaultEndpointsProtocol=…;AccountKey=…`
- Cloudflare `[a-zA-Z0-9_-]{40}` API tokens (context-dependent — needs a nearby `cloudflare` keyword)
- DigitalOcean `dop_v1_…`

### Source control
- GitHub PAT: classic `ghp_[A-Za-z0-9]{36}`, fine-grained `github_pat_[A-Za-z0-9_]{82}`, OAuth `gho_…`, app `ghs_…`, refresh `ghr_…`
- GitLab PAT: `glpat-[A-Za-z0-9_-]{20,}`
- Bitbucket app password (context-dependent)

### Developer platforms
- npm publish `npm_[A-Za-z0-9]{36}`
- PyPI publish `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+`
- Docker Hub `dckr_pat_…`
- Atlassian API `ATATT3xFfGF0[A-Za-z0-9_-]+`

### Communication
- Slack `xox[baprs]-[A-Za-z0-9-]+`
- Slack webhook `https://hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]{24}`
- Discord webhook `https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`
- Twilio `SK[a-f0-9]{32}`, Account SID `AC[a-f0-9]{32}`
- SendGrid `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`

### Observability
- DataDog `dd_?[a-f0-9]{32}` (context-dependent)
- Sentry DSN `https://[a-f0-9]+@[a-z0-9.-]+/[0-9]+`
- New Relic `NRAK-[A-Z0-9]{27}`

### Tunneling / networking
- ngrok `[0-9]+_[A-Za-z0-9_]{40,}`
- Postman `PMAK-[a-f0-9]{24}-[a-f0-9]{34}`

### Generic
- JWT `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- Private keys `-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`
- SSH private key files: `id_rsa`, `id_ed25519`, `id_ecdsa` (as filenames)
- Database URIs: `(?:postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@` — captures credentials-in-URL
- HTTP basic auth in URL: `https?://[^:]+:[^@]+@`
- Bearer tokens after `Authorization:`

### High-entropy generic fallback
- 20+ char base64 / hex strings in code files, gated by proximity to keywords like `key`, `secret`, `token`, `password`, `credential`, `api` — this reduces false positives significantly.

## Scan pipeline

```bash
BATCH_ID="$(date -u +%Y-%m-%d-%H%M%S)-$(head -c 32 /dev/urandom | shasum | cut -c1-8)"
export VAULT=/tmp/itx-vault-secret-$$
gh auth setup-git
git clone --depth 5 https://github.com/sdsolutions/ITx-cybersecurity-vault.git "$VAULT"
cd "$VAULT"
mkdir -p ".raw/secret-scans/$BATCH_ID"
git config user.email "cybersecurity-manager+bot@sdsolutions.com.ph"
git config user.name "Cybersecurity Manager (Secret Scan)"
```

For each match:
1. Capture: file path, line number, matched pattern name, category, severity (see below).
2. **Redact the actual token value** — first 4 characters + `<redacted-<n>-chars>`.
3. Compute SHA-256 of the raw value (stored in the private artifact only, not the report).
4. Add 2 lines of surrounding context (also redacted for anything else that looks secret).

## Severity model

| Severity | Pattern classes |
|---|---|
| **critical** | Private keys (PEM `BEGIN…PRIVATE KEY-----`), AWS root `AKIA…` + secret pair on adjacent lines, ID/EDDSA/RSA SSH private key files, GCP service-account JSON with `private_key` |
| **high** | Cloud provider keys (AWS/GCP/Azure/Cloudflare/DO), source-control PATs (GitHub/GitLab), developer publishing tokens (npm/PyPI/Docker Hub/Atlassian), AI provider keys (Anthropic/OpenAI/HuggingFace), Slack bot tokens, database URIs with plaintext creds |
| **medium** | JWTs (may or may not be sensitive), API keys with generic patterns near secret-keywords, HTTP basic-auth URLs, webhook URLs (Slack/Discord/Sentry DSN) |
| **low** | High-entropy strings in comments, `TODO: rotate this` markers, generic bearer tokens in test fixtures |
| **info** | `.env.example`, `.env.sample`, config templates with `<REPLACE_ME>` or empty values — flagged so an operator can verify none accidentally hold real values |

## Output

### Report comment on trigger issue

```
### Secret scan: <input> — <N> secrets found

Scanned: <count> files, <total bytes> total
Skipped: <count> (binary / too large / gitignored)
Severity: critical <n>, high <n>, medium <n>, low <n>, info <n>
Clean files: <count>
Duration: <seconds>

#### Findings by severity

| File            | Line | Pattern              | Redacted value | Severity | Recommendation                              |
| src/config.py   |   34 | AWS access key       | AKIA…<redacted-16-chars> | critical | ROTATE NOW — remove from git history, revoke in AWS console, audit CloudTrail for use |
| .env.production |    3 | Anthropic API key    | sk-a…<redacted-91-chars>  | high     | Rotate in Anthropic console, delete from repo, add to .env.example instead |

Full artifact: .raw/secret-scans/<batch-id>/report.json in the ITx vault.
```

### Structured artifact

Write to `.raw/secret-scans/<batch-id>/report.json`:

```json
{
  "input": "<original arg>",
  "scanned_at": "<UTC>",
  "scanner_version": "secret-scan v1 / ripgrep <ver-or-null>",
  "files_scanned": <n>,
  "files_skipped": [{"path": "...", "reason": "..."}],
  "findings": [
    {"file": "<rel-path>", "line": 34, "pattern": "aws-access-key",
     "category": "cloud", "severity": "critical",
     "value_redacted": "AKIA…<redacted-16-chars>", "value_sha256": "…",
     "context_lines": ["…", "…"], "recommendation": "…"}
  ],
  "clean_files_count": <n>,
  "git_history_scanned": <bool>
}
```

Full raw values are NEVER written anywhere — only SHA-256 hashes. This means the report itself is safe to commit to the private vault; even if it were exfiltrated, the hashes can be verified but the credentials themselves are not present.

## Never do

- **Never** write the actual matched credential value to any file, log, comment, or the vault. Redact everywhere; the SHA-256 is the only preserved form.
- **Never** attempt to validate the credential by calling the service — even a read-only call (like AWS `GetCallerIdentity`) leaves an audit trail on the target account. If the operator wants to verify a finding is live, that's a separate manual step under explicit RoE.
- **Never** revoke, rotate, or otherwise touch the credential upstream. Only the human/system that owns the account can do that.
- **Never** modify the scanned files.
- **Never** send file bytes off-machine.
- **Never** scan directories outside the argument tree.
- **Never** scan system dirs (`/System`, `/Library`, `~/.ssh`, `~/.gnupg`, `~/Library/Keychains`, `/private/var`).

## Guardrails

- If the argument is a **remote git repo** with `--include-history`, warn the operator that this can take a long time and enumerate every historical version of every file. Get explicit confirmation before running for repos > 500 MB.
- **Rate-limit warnings** — if scanning a very large tree (>100k files), report progress in intervals rather than staying silent.
- **False positive tolerance** — the "high-entropy generic fallback" is deliberately gated by keyword proximity to keep false positives low, but expect some. Every finding carries a `confidence: high|medium|low` field so reviewers can prioritize.
- **`.env.example` / `.env.sample` / config templates** — flagged as `info` severity so an operator can verify none accidentally hold real values, but not as findings requiring action.

## Effect

Report lands as a comment; artifact lives in the vault. No files touched, no credentials rotated, no upstream services contacted. If findings warrant rotation, human decides and runs it manually (or a future `--rotate` mode we build later, gated behind explicit per-service RoE).

## Related

- Sibling skills: [`security-scan`](../security-scan/SKILL.md), [`metadata-scan`](../metadata-scan/SKILL.md), [`tech-register`](../tech-register/SKILL.md)
- Vault source: `wiki/sources/claude-osint/secret-regex-catalog.md` — the seed catalog
- Vault source: `wiki/sources/claude-osint/credential-validators.md` — read-only validator patterns (a future extension)
- Complements `/metadata-scan` — that finds embedded metadata in binaries (EXIF, DOCX properties); this finds credentials in text (code, config, logs, dotfiles).
