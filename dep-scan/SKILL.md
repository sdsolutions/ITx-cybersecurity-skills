---
name: dep-scan
description: >
  Software composition analysis (SCA) — scan a local project directory, git repo, SBOM, lockfile, or container image for open-source dependencies with known vulnerabilities, using Google's osv-scanner against the OSV.dev database (GHSA, PyPI, Go, RustSec, npm, Maven, NuGet, Packagist, RubyGems, crates.io, Debian/Ubuntu/Alpine and more). Cross-checks every CVE alias against our CISA KEV snapshot, adds EPSS, proposes upgrade targets, and hands vulnerable packages to /tech-register so the CVE feed keeps watching them. Scan-only — never upgrades, patches, or opens PRs. Covers OWASP ASVS v5 V15 (dependencies). Use when the user says "dependency scan", "SCA", "scan dependencies", "check packages for CVEs", "vulnerable libraries", "osv scan", "SBOM scan", "scan lockfile", or invokes "/dep-scan".
argument-hint: "<path | git-url | sbom-file | lockfile | image:tag> [--offline] [--no-resolve] [--call-analysis go|rust] [--register vulnerable|all|none] [--no-epss]"
license: Proprietary source-available
---

# Dep Scan (Scan-only SCA)

Find vulnerable open-source dependencies. **This skill never modifies the target** — no upgrades, no lockfile edits, no PRs. It reports; the owning team remediates.

Engine: [`google/osv-scanner`](https://github.com/google/osv-scanner) v2 (Apache-2.0) over the [OSV.dev](https://osv.dev) database. Vault reference: `wiki/sources/osv/_index.md`.

## Authorization gate

Scanning manifests is passive, but the **target code is confidential**. Before running against anything that is not SDSolutions-owned:

- Confirm the requester is authorized to hand us the code/image (client engagement, signed scope, or our own repo).
- Client code defaults to **`--offline`** (see Data egress) unless the client has agreed to online lookups.
- Private git URLs are cloned with the operator's `gh` credentials — never ask for or store a client token.

## Preflight

```bash
# Prefer an installed binary; otherwise use a checksum-verified release in a scratch dir.
if command -v osv-scanner >/dev/null 2>&1; then
  OSV=osv-scanner
else
  OSV_DIR=/tmp/osv-scanner-$$ && mkdir -p "$OSV_DIR" && cd "$OSV_DIR"
  ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); OS=$(uname -s | tr A-Z a-z)
  gh release download -R google/osv-scanner -p "osv-scanner_${OS}_${ARCH}" -p osv-scanner_SHA256SUMS
  grep " osv-scanner_${OS}_${ARCH}\$" osv-scanner_SHA256SUMS | shasum -a 256 -c - || { echo "checksum mismatch — abort"; exit 1; }
  chmod +x "osv-scanner_${OS}_${ARCH}" && OSV="$OSV_DIR/osv-scanner_${OS}_${ARCH}"
  cd - >/dev/null
fi
$OSV --version
```

Install permanently with `brew install osv-scanner` (macOS) or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`. **Never** run an unverified binary — abort on checksum mismatch.

Normalizer: `scripts/normalize.py` next to this file (stdlib Python, no deps). If the skill was imported without supporting files, fetch it from the public mirror: `https://raw.githubusercontent.com/sdsolutions/ITx-cybersecurity-skills/main/dep-scan/scripts/normalize.py` into the scratch dir. Run it with `python3 -I`.

## Input handling

| Argument | Command |
|---|---|
| Local directory | `$OSV scan source -r <dir>` |
| Git URL | `git clone --depth 1 <url> /tmp/dep-scan-<hash>` → scan dir → delete clone on completion |
| Lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `pom.xml`, `gradle.lockfile`, `packages.lock.json`, `pubspec.lock`, `mix.lock`, …) | `$OSV scan source -L <file>` |
| SBOM (CycloneDX / SPDX JSON) | `$OSV scan source -L <file>` (file name must follow the spec, e.g. `*.cdx.json`, `*.spdx.json`) |
| Container image `image:tag` | `$OSV scan image <image:tag>` (needs Docker/Podman; pulls if absent) |

Always add `--format json --output-file "$WORK/osv.json"`. Exit codes: `0` clean, `1` vulnerabilities found (**not** an error), `128` no packages found, anything else = real failure.

Skip `node_modules/`, `vendor/`, `.venv/`, `dist/`, `build/` — osv-scanner reads lockfiles, not installed trees; it already honours `.gitignore` (pass `--no-ignore` only if the operator asks).

## Data egress — online vs offline

| Mode | What leaves the machine | When |
|---|---|---|
| **online** (default for SDSolutions-owned code) | Package **names + versions** to `api.osv.dev`; manifest-only ecosystems (e.g. `requirements.txt`, `pom.xml`) also resolve transitive deps via `deps.dev`. **No source code ever.** | Our own projects, OSS repos |
| **`--offline`** (default for client code) | Nothing about the target. Only a one-time download of per-ecosystem OSV databases (npm+PyPI ≈ 250 MB) | Client engagements, private/internal package names |

Offline invocation:

```bash
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$HOME/.cache/osv-scanner"   # reuse across scans
$OSV scan source -r <dir> --offline-vulnerabilities --download-offline-databases --no-resolve \
  --format json --output-file "$WORK/osv.json"
```

`--no-resolve` stops transitive resolution (which needs deps.dev). Consequence: for manifest-only projects without a lockfile, offline mode sees **direct deps only** — say so in the report's limitations. Offline DBs may trail the live API by hours; record `mode: offline` in the report.

`--no-epss` skips the EPSS lookup (CVE IDs to `api.first.org`). Use it when even CVE identifiers associated with a client should not leave the machine.

## Call analysis (reachability)

`--call-analysis go` / `rust` tells you whether vulnerable functions are actually reachable. **Rust call analysis runs build scripts** — only enable it on code we trust, in a disposable environment. Other ecosystems: reachability is manual analyst triage.

## Scan pipeline

```bash
BATCH_ID="$(date -u +%Y-%m-%d-%H%M%S)-$(head -c 32 /dev/urandom | shasum | cut -c1-8)"
WORK=/tmp/dep-scan-$$ && mkdir -p "$WORK"
export VAULT=/tmp/itx-vault-dep-$$
gh auth setup-git
git clone --depth 5 https://github.com/sdsolutions/ITx-cybersecurity-vault.git "$VAULT"
git -C "$VAULT" config user.email "cybersecurity-manager+bot@sdsolutions.com.ph"
git -C "$VAULT" config user.name "Cybersecurity Manager (Dep Scan)"

# 1. Scan (pick the command from Input handling; online or offline per Data egress)
$OSV scan source -r "$TARGET" --format json --output-file "$WORK/osv.json"; rc=$?
[ "$rc" -le 1 ] || [ "$rc" -eq 128 ] || { echo "osv-scanner failed ($rc)"; exit "$rc"; }

# 2. Normalize — KEV cross-check uses the newest vault snapshot; no network unless EPSS on
KEV=$(ls "$VAULT"/.raw/cve/kev/[0-9]*.json 2>/dev/null | tail -1)
python3 -I "$SKILL_DIR/scripts/normalize.py" "$WORK/osv.json" \
  --out-dir "$VAULT/.raw/dep-scans/$BATCH_ID" --input-label "<original argument>" \
  --scan-root "$TARGET" ${KEV:+--kev "$KEV"} --epss \
  --mode online --register vulnerable --scanner-version "$($OSV --version | head -1)"

# 3. Keep the raw scanner output alongside (gzip — can be large)
gzip -c "$WORK/osv.json" > "$VAULT/.raw/dep-scans/$BATCH_ID/osv-scanner.json.gz"
```

Drop `--epss` when `--no-epss` was passed; set `--mode offline` for offline runs. `--register` follows the skill flag (default `vulnerable`).

## Severity model (scanner-derived — always unconfirmed)

| Severity | Rule |
|---|---|
| **critical** | Max CVSS of the alias group ≥ 9.0 |
| **high** | ≥ 7.0 — **or** any CVE alias is in CISA KEV (actively-exploited floor) |
| **medium** | ≥ 4.0 |
| **low** | > 0 |
| **unrated** | OSV entry carries no CVSS (common for ecosystem-only advisories) — analyst must rate |

OSV groups aliases (GHSA ↔ PYSEC ↔ CVE) so one real vulnerability counts once per package. Findings sort KEV-first, then severity, then CVSS.

Per agent rules, **never report scanner severity as final**. Every finding ships `triage_status: unconfirmed`. Before it goes into a client deliverable the analyst confirms:

1. **Reachability** — is the vulnerable function/path used? (Go/Rust: call analysis; others: code review)
2. **Exposure** — runtime vs dev/test-only dependency; internet-facing or internal
3. **Exploit signal** — KEV, EPSS, public exploit
4. **Fix feasibility** — `fixed_in` exists? major-version jump? (upgrade targets are a heuristic)
5. Then assign final severity using the Standard Finding Structure (business impact, compensating controls)

## Output

### Report comment on trigger issue

Post `report.md` from the batch dir (it already contains the summary + table + upgrade targets), then append:

```
Full artifact: .raw/dep-scans/<batch-id>/report.json in the ITx vault.
Limitations: <offline/no-resolve direct-deps-only | no lockfile found | image layers not scanned | …>
Next: analyst triage (reachability, exposure) before any finding is marked confirmed.
```

If there are more than 40 findings, post only KEV + critical + high rows in the comment and point to the artifact for the rest.

### Structured artifact

`.raw/dep-scans/<batch-id>/report.json` — `input`, `scanned_at`, `scanner_version`, `mode`, `manifests[]`, `packages_scanned`, `vulnerable_packages`, `severity_counts`, `kev_matches`, `upgrade_targets[]`, and `findings[]` with `ecosystem`, `package`, `version`, `source` (relative manifest path), `primary_id`, `ids`, `aliases`, `cves`, `summary`, `cvss_max`, `epss`, `epss_percentile`, `severity`, `severity_source`, `kev[]`, `fixed_in`, `references`, `osv_urls`, `triage_status`.

Also in the batch dir: `osv-scanner.json.gz` (raw), `discovered-tech.json` (tech-register hand-off).

### Tech registry hand-off

Run `/tech-register "$VAULT/.raw/dep-scans/$BATCH_ID/discovered-tech.json"`. Each entry carries `osv_packages` (`<Ecosystem>:<name>`) and a `purl`, so the NVD autopilot's OSV step can match future advisories — including GHSA/PYSEC/GO-only ones with no CVE — to these packages. Default `--register vulnerable` keeps the registry to packages that have shown risk; `all` is for our own core stack, `none` for one-off client scans we should not track.

### Commit

```bash
cd "$VAULT"
git add ".raw/dep-scans/$BATCH_ID"
git commit -m "dep-scan: <input> — <N> advisory groups in <M> packages (<critical>/<high>, KEV <k>)"
git pull --rebase && git push origin main
```

Delete `$WORK` and any temporary clone afterwards.

## Never do

- **Never** modify the scanned project — no `npm audit fix`, no lockfile edits, no upgrade PRs.
- **Never** copy source files into the vault — only the normalized report, raw scanner JSON, and the tech hand-off.
- **Never** run the scanner online against client code without the client's agreement; default to `--offline`.
- **Never** enable `--call-analysis rust` on untrusted code outside a disposable sandbox (it executes build scripts).
- **Never** present scanner severity as a confirmed finding.
- **Never** write absolute runtime paths into reports — `--scan-root` keeps manifest paths relative.
- **Never** scan system dirs (`/System`, `/Library`, `~/.ssh`, `~/.gnupg`, `/private/var`).

## Guardrails

- Exit code `128` (no packages) is a valid result — report "no supported manifests found" with the list of what was looked for, not a failure.
- Large monorepos: report progress; if > 50 manifests, summarize per manifest in the comment.
- Image scans pull from registries — confirm the image reference with the operator and do not push anything.
- Respect osv.dev — no tight retry loops; one retry with backoff on 429/5xx, then fall back to `--offline`.

## Effect

Report lands as a comment; artifacts live in the vault under `.raw/dep-scans/`; vulnerable packages join `references/tracked-tech.json` so the CVE feed keeps watching them. Nothing in the target changes.

## Related

- Sibling skills: [`security-scan`](../security-scan/SKILL.md) (external surface + front-end JS via `retire`), [`secret-scan`](../secret-scan/SKILL.md), [`metadata-scan`](../metadata-scan/SKILL.md), [`tech-register`](../tech-register/SKILL.md)
- Vault source: `wiki/sources/osv/_index.md` — OSV.dev API, data sources, egress notes
- Vault entity: `wiki/entities/OWASP ASVS v5.md` — V15 dependency requirements this skill evidences
- CVE feed: `wiki/sources/cve-feed/scope-policy.md` — how `osv_packages` matching works
