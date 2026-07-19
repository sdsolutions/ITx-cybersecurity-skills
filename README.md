# ITx Cybersecurity Skills

Public thin mirror of two Multica-installable agent skills used by the ITx cybersecurity engagement. This repo exists to be `multica skill import`-friendly; the operational vault (`sdsolutions/ITx-cybersecurity-vault`) stays private.

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

### `/tech-register`

The **skill**. Persists newly-discovered technologies to the CVE feed's dynamic scope registry (`references/tracked-tech.json` in the private ops vault). Consumes discovered-tech JSON, Wappalyzer output, Nmap XML, or CycloneDX / SPDX SBOMs.

Auto-classifies pillar, CPE prefixes, and keyword patterns. Dedupes case-insensitively against `name` + `aliases`. Never removes entries.

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

# Bind to Cybersecurity Manager
multica agent skills add 70893587-172c-4a4a-a5a1-847614784b3a --skill-ids <security-scan-id>
multica agent skills add 70893587-172c-4a4a-a5a1-847614784b3a --skill-ids <tech-register-id>
```

## Why public

The SKILL.md files here are pure orchestration prompts — no client data, no credentials, no scan results, no CVE inventory. All state (`references/tracked-tech.json`, scan artifacts, curated CVEs, findings) lives in the private ops vault `sdsolutions/ITx-cybersecurity-vault` and never touches this repo.

## License

Apache-2.0.
