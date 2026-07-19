---
name: security-scan
description: >
  Run an authorized, defensively-framed security scan against a URL, hostname, IP, or CIDR and file the findings back to the current Multica issue (as comments + sub-issues) and the ITx-cybersecurity-vault. Auto-registers any newly-discovered technologies via the tech-register skill so the CVE feed backfills coverage. Use when the user says "scan example.com", "security scan", "security audit", "pentest [target]", "attack surface check", or invokes "/security-scan".
argument-hint: "<target> [--depth quick|standard|thorough] [--scope <spec>] [--auth <owner|consent-url>]"
license: Proprietary source-available
---

# Security Scan (Trigger)

You are running an authorized security scan on behalf of the invoking Multica user. This skill is the trigger — it orchestrates fingerprinting, header/TLS/deps checks, defensively-framed vulnerability probes, filing findings, and registering discovered tech.

## Read order at invocation

1. Confirm the target and authorization from the invoking prompt.
2. Load `wiki/sources/cve-feed/scope-policy.md` from `sdsolutions/ITx-cybersecurity-vault` for scope/severity conventions.
3. Load `wiki/sources/cve-feed/scan-request-template.md` for the finding structure.
4. Look up prior scans for the same asset in `.raw/scans/<hostname>/` before starting.

## Authorization gate

Do NOT proceed with active probes unless ONE of the following is explicit:

- Invoker states they own the asset.
- Invoker links a written authorization / rules-of-engagement (RoE) doc.
- Target is a lab domain (`example.com`, `test.local`, `*.internal`, `localhost`, RFC-1918).

If unclear, fall back to **defensive-only** mode: passive DNS/certs, public HTTP surface reads, no active probes, no fuzzing, no auth attempts. Say so at the top of the report.

## Depth ladder

### quick (~5 min)
- crt.sh subject certificate transparency lookup
- DNS records (A, AAAA, MX, TXT, CAA, SPF, DMARC, DKIM)
- Passive tech fingerprint from HTTP response (Server, X-Powered-By, cookies, meta generator, `<script src>` bundles)
- HTTP security headers audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP)
- TLS quick check (`openssl s_client` — protocols supported, cert chain, cert expiry, weak-cipher detection)
- Well-known paths (`/robots.txt`, `/security.txt`, `/.well-known/security.txt`, `/sitemap.xml`)
- Cookie flag audit (Secure, HttpOnly, SameSite, `__Host-` prefix)

### standard (~30 min)
- All of quick, plus:
- Subdomain enumeration (crt.sh + hackertarget passive DNS API)
- JS bundle enumeration + retire.js analysis (if `retire` is on PATH; else parse response HTML and match against a hard-coded shortlist of known-vulnerable frontend libs)
- Nuclei against fingerprinted stack (if `nuclei` is on PATH — templates limited to `-tags cve,tech,exposure -severity high,critical`)
- CORS policy probe (`Origin: https://evil.example` on API endpoints — read-only, defensive)
- Third-party script inventory (integrity attribute + origin check)

### thorough (~1–2 h)
- All of standard, plus:
- Full nuclei `cve,exposure,misconfiguration,tech` scan
- Extended TLS analysis (`testssl.sh` if installed; else openssl loop over cipher list)
- Content-Security-Policy structural analysis (source-list unpacking, nonce/hash usage, unsafe-* keywords)
- Auth surface enumeration (auth endpoints, password-reset flow existence — NO credential guessing)
- SSRF-adjacent parameter fingerprint (spot obvious url/host/path params without probing them)

## Never do

- Credential guessing / brute-force / password spraying
- Exploitation payloads (only detect existence, don't demonstrate)
- Rate that could trip a WAF or hurt production
- Traffic to third-party owned assets discovered in scope (e.g. an embedded Stripe iframe — don't probe stripe.com)
- Any action outside the stated scope
- Store scan output outside `.raw/scans/` in the ITx vault

## Pipeline

Preflight:

```bash
export VAULT=/tmp/itx-vault-$$
gh auth setup-git
git clone --depth 5 https://github.com/sdsolutions/ITx-cybersecurity-vault.git "$VAULT"
cd "$VAULT"
git config user.email "cybersecurity-manager+bot@sdsolutions.com.ph"
git config user.name "Cybersecurity Manager (Scan)"
```

Run the checks per depth. Each check writes its raw output to `/tmp/scan-<hostname>-<check>.json` and a normalized-finding record to an in-memory list.

Findings normalized shape:

```json
{
  "id": "FIND-<hostname>-<n>",
  "title": "…",
  "severity": "info|low|medium|high|critical",
  "affected": ["<host>[:<port>][/<path>]"],
  "evidence": "<short repro / observation>",
  "impact": "<business + technical>",
  "recommendation": "<remediation>",
  "references": ["<CVE|OWASP|CWE|doc URL>"],
  "check": "<tls-headers|csp|dep|cve|…>",
  "confidence": "high|medium|low"
}
```

Discovered-tech normalized shape (fed to tech-register):

```json
{
  "name": "nginx",
  "version": "1.24.0",
  "cpe_prefixes": ["cpe:2.3:a:nginx:nginx"],
  "keyword_patterns": ["nginx"],
  "source": "http-response-header|meta-generator|js-bundle|nuclei|manual",
  "discovered_at": "2026-07-19T…Z"
}
```

## Output

1. **One executive-summary comment** on the trigger Multica issue with:
   - Target, depth, mode (authorized vs defensive-only), start/end timestamps
   - Findings count by severity (info/low/medium/high/critical)
   - Discovered tech count (with the top 5)
   - Link to the raw scan artifact path in the vault

2. **One sub-issue per finding at high or critical** if the requester ticked "auto-open sub-issues":
   ```bash
   multica issue create --parent <trigger-issue-id> \
     --title "[<severity>] <finding-title> on <host>" \
     --description-file ./finding.md \
     --priority urgent|high|medium
   ```
   Use `--priority urgent` for critical, `high` for high, `medium` for medium if the user asked.

3. **Persist discovered tech.** Invoke the `tech-register` skill with the discovered-tech list. Do NOT edit `references/tracked-tech.json` yourself — always route through tech-register (it dedupes + classifies).

4. **Persist raw scan artifacts** to `.raw/scans/<hostname>/<UTC-timestamp>.json` (gzip if >1 MB). Include:
   - Command lines that were run
   - Raw tool output
   - Normalized finding list
   - Discovered-tech list
   - Environment (runtime hostname redacted)

5. **Commit + push** to `origin/main`:
   ```
   scan: <hostname> <depth> — <N> findings (<critical>/<high>/<medium>), <M> tech discovered
   ```
   Rebase-retry once on conflict.

## Guardrails

- **Never mutate `references/tracked-tech.json` directly.** Always call `tech-register`.
- **Never mutate `references/source-ledger.json` from this skill** (autopilots own that).
- **Never touch upstream `AI-Marketing-Hub/cybersecurity-brain`.** Reference-only.
- **Never store credentials** in vault artifacts. Redact `Cookie:` / `Authorization:` headers from evidence.
- **Redact IPs of any customer's third-party dependency** (e.g. Stripe IPs).
- **On tool absence** (`nuclei`, `retire`, `testssl.sh` not installed), degrade gracefully — note the skipped check in the report; don't fail the whole scan.
- **HTTP error handling:** retry `5xx` up to 3× with exponential backoff. On `429`, back off aggressively and log. Never retry through a WAF block.

## Related

- `wiki/sources/cve-feed/scan-request-template.md` — request format
- `wiki/sources/cve-feed/scope-policy.md` — how discovered tech feeds the CVE feed
- `wiki/sources/cve-feed/runbook.md` — ops guide
- Sibling skill `tech-register` — dedupe + classify + append discovered tech
