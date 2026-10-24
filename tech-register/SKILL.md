---
name: tech-register
description: >
  Append newly-discovered technologies to references/tracked-tech.json in the sdsolutions/ITx-cybersecurity-vault ops repo. Consumes structured discovered-tech JSON (including /dep-scan output with OSV package keys), Wappalyzer output, Nmap XML, or a CycloneDX/SPDX SBOM. Auto-classifies pillar (web/product/hosting/compliance), CPE prefixes, and keyword patterns. Dedupes against existing registry entries. Commits + pushes. Triggers the CVE feed backfill on the next NVD sweep. Use when the user says "register [tech]", "add [tech] to tracked tech", "update registry", or when the security-scan skill needs to persist discoveries.
argument-hint: "<discovered-tech-json-path> | <wappalyzer-json> | <nmap-xml> | <sbom> | manual --name X [--pillar 1|2|3|4] [--cpe cpe:2.3:...] [--keyword pattern]"
license: Proprietary source-available
---

# Tech Register (Skill)

Persists newly-discovered technologies to the CVE feed's dynamic scope registry. Runs against `sdsolutions/ITx-cybersecurity-vault`.

## Preflight

```bash
export VAULT=/tmp/itx-vault-tech-$$
gh auth setup-git
git clone --depth 5 https://github.com/sdsolutions/ITx-cybersecurity-vault.git "$VAULT"
cd "$VAULT"
git config user.email "cybersecurity-manager+bot@sdsolutions.com.ph"
git config user.name "Cybersecurity Manager (Tech-Register)"
```

Load `references/tracked-tech.json` and `references/tracked-tech.schema.md`.

## Input formats

Accept ONE of:

1. **Discovered-tech JSON array** (native format from `security-scan`):
   ```json
   [
     {"name": "nginx", "version": "1.24.0", "cpe_prefixes": ["cpe:2.3:a:nginx:nginx"], "keyword_patterns": ["nginx"], "source": "http-response-header", "discovered_at": "2026-07-19T00:00:00Z"}
   ]
   ```

   `/dep-scan` emits the same format with three extra fields — `ecosystem`, `purl`, `osv_packages` (`["<Ecosystem>:<name>"]`) — plus `pillar_hint` and `source: "dep-scan"`. Carry `osv_packages` and `purl` (into `purls[]`) through to the entry; use `pillar_hint` as the pillar guess.

2. **Wappalyzer output JSON** — parse `technologies[]` array (each has `name`, `slug`, `categories`, `version`).

3. **Nmap XML** — parse `//service[@name and @product]`; assemble as `{name: service.product, version: service.version, source: "nmap"}`.

4. **CycloneDX 1.5 / SPDX 2.3 SBOM** — parse `components[]` / `packages[]`. Preserve PURL and CPE if present. Derive `osv_packages` from the PURL type (`npm`→`npm`, `pypi`→`PyPI`, `golang`→`Go`, `maven`→`Maven` with `group:artifact`, `cargo`→`crates.io`, `gem`→`RubyGems`, `nuget`→`NuGet`, `composer`→`Packagist`). Source: `sbom-cyclonedx` or `sbom-spdx`.

5. **Manual CLI** — `--name X --pillar N --cpe cpe:2.3:... --keyword pattern` (repeat `--keyword` as needed).

## Classification

For each incoming entry that doesn't already exist:

1. **Normalize** — lowercase name, strip version and vendor prefix, kebab-case (e.g. "Microsoft IIS 10.0" → `iis`).
2. **Dedup** — match `osv_packages` exactly, or case-insensitively match `name` or any of `aliases`, against every existing entry (including `retired_at != null`). If a retired entry matches, update `retired_at: null` and `last_confirmed: today` — DO NOT create a duplicate.
3. **Pillar classification heuristic** (fill best guess; a human can correct later):
   - `pillar 1 (web-app)`: web frameworks, HTTP servers, WAFs, CDNs, frontend libs, JS runtimes exposing HTTP, CMS platforms.
   - `pillar 2 (product-saas)`: SDKs, API platforms, mobile frameworks, auth-as-a-service, payment processors, embedded SaaS.
   - `pillar 3 (hosting-infra)`: OSs, containers, orchestrators, cloud primitives, databases, message queues, load balancers, VPN/firewall gear.
   - `pillar 4 (compliance)`: SIEM, GRC platforms, DLP, backup, IAM/PAM tooling, monitoring.
4. **CPE prefix** — if the input carries a CPE, extract vendor+product prefix (`cpe:2.3:a:<vendor>:<product>`). If unknown, best-effort from the normalized name; if still uncertain, leave `cpe_prefixes: []` and rely on `keyword_patterns` alone.
5. **Keyword patterns** — the normalized name plus any obvious variants (e.g. `iis` → `["iis", "microsoft-iis", "internet information services"]`). All case-insensitive substring matches.

## Persist

Append per new entry to `entries[]`:

```json
{
  "id": "<kebab-slug>",
  "name": "<Human-readable Name>",
  "aliases": ["<other-known-names>"],
  "pillar": <1|2|3|4>,
  "cpe_prefixes": ["cpe:2.3:a:vendor:product"],
  "keyword_patterns": ["pattern1", "pattern2"],
  "osv_packages": ["<Ecosystem>:<name>"],
  "purls": ["pkg:<type>/<name>@<version>"],
  "severity_min": null,
  "first_seen": "<YYYY-MM-DD today>",
  "last_confirmed": "<YYYY-MM-DD today>",
  "sources": [{"type": "<scan|manual|wappalyzer|nmap|sbom|dep-scan>", "ref": "<scan-id or path>", "date": "<YYYY-MM-DD>"}],
  "owner": null,
  "notes": null,
  "retired_at": null
}
```

Update `updated_at` at the top of the file to today's date.

For entries that dedupe against an existing one, only mutate:
- `last_confirmed: today`
- Append to `sources[]` (do not overwrite)
- Union new aliases into `aliases[]`
- Union new keyword_patterns into `keyword_patterns[]`
- Union new `osv_packages[]` and `purls[]`
- Clear `retired_at` if the entry was retired but is confirmed present again

## Commit + push

```bash
git pull --rebase
git add references/tracked-tech.json
git commit -m "tech-register: +<N> new, +<M> reconfirmed (source: <source-type>)"
git push origin main
```

Rebase-retry once on conflict; second failure returns error to caller.

## Output

Return a summary to the caller:

```json
{
  "added": [{"id": "...", "name": "...", "pillar": N}],
  "reconfirmed": [{"id": "...", "name": "..."}],
  "skipped_duplicates": [{"name": "...", "matched_id": "..."}],
  "commit": "<sha>",
  "next_backfill_at": "<next Autopilot B run — approx tomorrow 06:00 UTC>"
}
```

## Guardrails

- **Never remove entries** — only append or update `last_confirmed`. Retiring an entry requires human sign-off (set `retired_at` manually).
- **Never overwrite `owner` or `notes`** — those are human-managed.
- **Never write secrets** to the registry. If an input carries a secret-like field, refuse the entry with an error.
- **Never touch upstream** `AI-Marketing-Hub/cybersecurity-brain`.
- **Idempotent** — running twice against the same input must yield zero additions on the second run.

## Effect

Once committed, the next daily Autopilot B run (06:00 UTC) automatically performs a **90-day CVE backfill** for each newly-added entry (per `wiki/sources/cve-feed/scope-policy.md`). Autopilot A picks up any KEV matches on its next hourly poll.

## Related

- `references/tracked-tech.schema.md` — full schema
- `wiki/sources/cve-feed/scope-policy.md` — how the registry is consumed
- Sibling skill `security-scan` — the primary source of discovered-tech inputs
- Sibling skill `dep-scan` — source of package-level entries with `osv_packages` (OSV package sweep)
