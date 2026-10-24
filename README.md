# ITx Cybersecurity Skills

Public thin mirror of the Multica-installable agent skills used by the ITx cybersecurity engagement. This repo exists to be `multica skill import`-friendly; the operational vault (`sdsolutions/ITx-cybersecurity-vault`) stays private.

## Skills

### `/security-scan`

The **trigger**. Runs an authorized, defensively-framed security scan against a URL, hostname, IP, or CIDR. Files findings back to the invoking Multica issue (as comments + severity-graded sub-issues) and persists raw artifacts to `.raw/scans/` in the private ops vault.

Depth ladder:
- `quick` (~5 min) — DNS, certs, HTTP fingerprint, security headers, TLS quick check
- `standard` (~30 min) — quick + subdomain enum + JS dep scan + nuclei against fingerprinted stack + CORS probe
- `thorough` (~1–2 h) — standard + extended nuclei + testssl + CSP structural + auth-surface enumeration

Authorization gate: falls back to defensive-only if not explicit.

Usage:

```
/security-scan example.com --depth quick --auth "I own this"
/security-scan acme-client.com --depth standard --auth "SOW-2026-14" --scope "*.acme-client.com"
```

### `/metadata-scan`

Scan-only auditor for embedded metadata that could leak personal or company data. Wraps ExifTool (~50 formats) and optionally mat2 (Office/PDF tracked-changes) to inspect:

- **Images** — EXIF GPS coords, camera serial, phone model, author, edit history, embedded thumbnails
- **PDFs** — Author, Creator, LastModifiedBy, hidden content, embedded JS/XFA
- **Office (DOCX/XLSX/PPTX)** — creator, comments, tracked changes, hidden slides/rows/columns, embedded thumbnails
- **SVG** — absolute source paths (Illustrator/Sketch), `<dc:creator>`, editor comments
- **Video/Audio** — GPS, device model, ID3 author/comment fields
- **Web bundles** — source-map dev-machine paths, `@author` JSDoc, inline comments
- **Hidden sidecars** — `.DS_Store`, `Thumbs.db`, `~$*`, `.git`, `.env`, `.idea`, `.vscode`, SSH keys, history files

**Never writes.** Reports severity-classified findings on the trigger issue; full raw + SHA-256 stored in the private ops vault. Personal paths, names, and GPS coordinates are redacted in the report body.

Requires `exiftool` (`brew install exiftool`). `mat2` optional (`pipx install mat2`).

Usage:

```
/metadata-scan ./assets/marketing/
/metadata-scan https://example.com/brochure.pdf
/metadata-scan ./assets/**/*.{jpg,pdf,docx} --recursive
```

### `/secret-scan`

Scan a local directory, glob, git repo, or URL for leaked credentials in text form (source code, config, logs, dotfiles). Complements `/metadata-scan` (which finds embedded metadata in binaries) — `/secret-scan` finds credentials in text.

- **Detects 48+ patterns** — cloud (AWS/GCP/Azure/Cloudflare/DO), source control (GitHub/GitLab PATs), dev platforms (npm/PyPI/Docker Hub/Atlassian), communication (Slack/Discord/Twilio/SendGrid), AI providers (Anthropic/OpenAI/HuggingFace), observability (DataDog/Sentry/New Relic), tunneling (ngrok/Postman)
- Also catches generic JWTs, PEM private keys, database URIs with plaintext creds, HTTP basic-auth URLs, and a keyword-gated high-entropy fallback
- **Never writes, revokes, or validates** — findings are redacted (first 4 chars + `<redacted-N-chars>`), only SHA-256 hashes stored in the private ops vault
- `--include-history` mode scans full git log — hours for a big repo, catches secrets that were reverted but still live in history
- Requires `ripgrep` for ~50x speedup (`brew install ripgrep`), falls back to `grep -RE` if missing

Usage:

```
/secret-scan ./src/
/secret-scan https://github.com/some/repo.git
/secret-scan ./src/**/*.{py,js,env} --recursive
/secret-scan https://github.com/some/repo.git --include-history
```

### `/dep-scan`

Software composition analysis (SCA). Scans a project directory, git repo, lockfile, SBOM, or container image for open-source dependencies with known vulnerabilities using Google's [`osv-scanner`](https://github.com/google/osv-scanner) over [OSV.dev](https://osv.dev) (GHSA, PyPI, Go, RustSec, npm, Maven, NuGet, Packagist, RubyGems, crates.io, Debian/Ubuntu/Alpine, …).

- **Prioritized** — cross-checks every CVE alias against the CISA KEV snapshot in the ops vault (actively-exploited floor = high), adds EPSS, sorts KEV-first
- **Remediation-ready** — fixed versions per advisory + per-package upgrade targets
- **Honest severity** — scanner-derived severity ships as `triage_status: unconfirmed`; the analyst confirms reachability and exposure before reporting
- **Offline mode for client code** — local OSV databases, no package names leave the machine
- **Never modifies the target** — no upgrades, no lockfile edits, no PRs
- Hands vulnerable packages (with OSV package keys + PURLs) to `/tech-register` so the CVE feed's OSV package sweep keeps watching them
- Evidence for OWASP ASVS v5 V15 (dependencies)

Requires `osv-scanner` (`brew install osv-scanner`; otherwise the skill downloads a checksum-verified release) and `python3` (stdlib only — `scripts/normalize.py`).

Usage:

```
/dep-scan ./
/dep-scan https://github.com/some/repo.git
/dep-scan ./client-app --offline --register none
/dep-scan ./bom.cdx.json
/dep-scan ghcr.io/acme/api:1.4.2
```

### `/tech-register`

The **skill**. Persists newly-discovered technologies to the CVE feed's dynamic scope registry (`references/tracked-tech.json` in the private ops vault). Consumes discovered-tech JSON (including `/dep-scan` output with OSV package keys), Wappalyzer output, Nmap XML, or CycloneDX / SPDX SBOMs.

Auto-classifies pillar, CPE prefixes, and keyword patterns. Dedupes on `osv_packages` and case-insensitively against `name` + `aliases`. Never removes entries.

Effect: new registered tech triggers a 90-day CVE backfill on the next daily NVD sweep by the `CVE Feed: NVD Delta Daily Sweep` autopilot in the ITx workspace.

Usage:

```
/tech-register /path/to/discovered-tech.json
/tech-register --name nginx --pillar 1 --cpe cpe:2.3:a:nginx:nginx --keyword nginx
```

## Installation into Multica

```bash
multica skill import --url github.com/sdsolutions/ITx-cybersecurity-skills/tree/main/security-scan --output json
multica skill import --url github.com/sdsolutions/ITx-cybersecurity-skills/tree/main/tech-register --output json
multica skill import --url github.com/sdsolutions/ITx-cybersecurity-skills/tree/main/dep-scan --output json

# Bind to Cybersecurity Manager
multica agent skills add 70893587-172c-4a4a-a5a1-847614784b3a --skill-ids <security-scan-id>
multica agent skills add 70893587-172c-4a4a-a5a1-847614784b3a --skill-ids <tech-register-id>
multica agent skills add 70893587-172c-4a4a-a5a1-847614784b3a --skill-ids <dep-scan-id>
```

## Why public

The SKILL.md files here are pure orchestration prompts — no client data, no credentials, no scan results, no CVE inventory. All state (`references/tracked-tech.json`, scan artifacts, curated CVEs, findings) lives in the private ops vault `sdsolutions/ITx-cybersecurity-vault` and never touches this repo.

## License

Apache-2.0.
