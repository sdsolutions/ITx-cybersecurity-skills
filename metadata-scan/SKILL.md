---
name: metadata-scan
description: >
  Scan files, images, documents, or a URL for embedded metadata that could leak personal or company information — EXIF/IPTC/XMP on images, author + tracked-changes + hidden content on Office/PDF docs, editor absolute paths in SVGs, sourcemap dev-machine paths on web bundles, and hidden sidecars like .DS_Store / Thumbs.db / ~$*. Scan-only — never writes, edits, or scrubs the originals. Use when the user says "metadata scan", "check for embedded metadata", "scan assets for PII", "audit exif", "check for hidden data", or invokes "/metadata-scan".
argument-hint: "<path-or-url-or-glob> [--recursive] [--include-hidden] [--severity-min low|medium|high|critical]"
license: Proprietary source-available
---

# Metadata Scan (Scan-only)

You are auditing files for embedded metadata that could leak personal or company data. **This skill never writes, edits, or scrubs the target.** It only reports. Scrubbing is the human's decision, done separately.

## Preflight

Verify the primary tool is available:

```bash
which exiftool >/dev/null 2>&1 || {
  echo "exiftool not installed — install with: brew install exiftool"
  exit 1
}
which mat2 >/dev/null 2>&1 && MAT2_AVAILABLE=1 || MAT2_AVAILABLE=0
```

If `exiftool` isn't present, tell the user how to install it (`brew install exiftool`) and exit cleanly. `mat2` is optional — used only for tracked-changes and Office/PDF-specific hidden content that ExifTool doesn't cover; if missing, note it in the report but proceed.

## Input handling

Accept one of:

- **Single file** — scan just that file.
- **Directory** — scan every supported file inside. Default depth is 1; pass `--recursive` for full descent.
- **Glob** — e.g. `./assets/**/*.{jpg,png,pdf,docx}` — shell-expand.
- **URL** — `curl -sSf` the file into a temp dir, scan, delete the temp copy. Never cache remote content in the vault.

Skip files > 100 MB by default; log the skip. Skip binary formats ExifTool doesn't recognize.

## What to check

### Images (JPEG, HEIC, TIFF, PNG, WebP, RAW, CR2, NEF, DNG, ARW)

Run `exiftool -j -a -u -G0 <file>` and inspect these tag groups:

| Severity | Fields |
|---|---|
| **critical** | GPS:GPSLatitude, GPS:GPSLongitude, GPS:GPSPosition, EXIF:GPSInfo |
| **high** | EXIF:SerialNumber, EXIF:LensSerialNumber, EXIF:OwnerName, XMP-photoshop:AuthorsPosition, IPTC:By-line, XMP-dc:Creator, XMP:CreatorTool with a personal path (`/Users/<name>/…`, `C:\Users\<name>\…`) |
| **medium** | EXIF:Software with version, EXIF:CameraModelName+Make together with EXIF:SerialNumber absent, XMP:Rights + Marked, IPTC:Copyright with a personal name |
| **low** | EXIF:DateTimeOriginal, EXIF:ModifyDate, EXIF:CreateDate, XMP:CreatorTool with generic software name (Photoshop, GIMP, etc.) |
| **info** | File:FileType, File:ImageWidth/Height, EXIF:Orientation |

Also check for **embedded thumbnails** (EXIF:ThumbnailImage present) — flag as low unless GPS is also present, then bump to critical.

### PNG-specific

- `PNG:Software` chunk
- `PNG:tEXt` and `PNG:zTXt` chunks with author/comment fields
- `PNG:CreationTime`
- Non-standard ancillary chunks with content ExifTool can't parse — flag as medium ("unknown chunk with N bytes")

### PDF

Run `exiftool -j -PDF:all <file>`:

| Severity | Fields |
|---|---|
| **high** | PDF:Author, PDF:Creator with a personal name/path, PDF:Producer with version, PDF:Company (if present), PDF:LastModifiedBy |
| **medium** | PDF:CreatorTool version, PDF:Subject, PDF:Keywords with internal codes |
| **low** | PDF:CreateDate, PDF:ModifyDate |

If `mat2` is available: additionally run `mat2 --show <file>` and surface any **hidden content**, **JavaScript**, **embedded files**, **form data**, or **XFA content**. Flag hidden text as high.

### Office (DOCX, XLSX, PPTX, ODT, ODS, ODP)

Extract the ZIP and read `docProps/core.xml` and `docProps/app.xml`:

| Severity | Fields |
|---|---|
| **high** | `cp:lastModifiedBy`, `dc:creator`, `Company`, `Manager`, tracked-changes present (`w:ins` / `w:del`), comments present (`w:comment` / `<comments>`) |
| **medium** | Hidden slides (PPTX `show="0"`), hidden rows/columns (XLSX `hidden="1"`), embedded thumbnails, `Application` name+version |
| **low** | `dcterms:created`, `dcterms:modified`, `TotalTime`, `Revision` count |

If `mat2` is available, additionally run `mat2 --show <file>` and merge findings.

### SVG

Read as text; scan for:

| Severity | Pattern |
|---|---|
| **critical** | `/Users/<name>/…`, `C:\Users\<name>\…`, `/home/<name>/…` — absolute source paths |
| **high** | `<dc:creator>`, `<dc:rights>`, Adobe Illustrator `<i:pgf-i:pgfInfo>`, Sketch `<sketch:originalFile>` |
| **medium** | Editor comments (`<!-- Generator: Adobe Illustrator … -->`) with version |
| **low** | Unicode BOM, editor artifact whitespace |

### Video (MP4, MOV, M4V, AVI)

Run `exiftool -j -Video:all -Quicktime:all -MakerNotes:all <file>`:

| Severity | Fields |
|---|---|
| **critical** | GPSCoordinates, GPSLatitude, GPSLongitude |
| **high** | Make + Model + SerialNumber, LensID+SerialNumber |
| **medium** | CreationTool with version, WritingApplication |
| **low** | CreateDate, ModifyDate, Duration |

### Audio (MP3, FLAC, WAV, M4A, OGG)

Run `exiftool -j -Audio:all -ID3:all <file>`:

| Severity | Fields |
|---|---|
| **high** | ID3:Artist / ID3:Author, ID3:Comment with personal content, iTunes:Owner |
| **medium** | ID3:EncodedBy, ID3:Publisher, ID3:Copyright with personal name |
| **low** | ID3:Year, ID3:Genre |

### Web bundles (JS, CSS, HTML, source maps)

Grep for:

| Severity | Pattern |
|---|---|
| **critical** | `sourceMappingURL=` referencing an absolute local path (`/Users/`, `C:\Users\`, `/home/`) |
| **high** | Absolute source paths inside inline source maps (`"sources":["/Users/…"]`) |
| **medium** | Author comments with names/emails, `// TODO: <name>`, `@author` JSDoc tags with personal names |
| **low** | Build-tool version comments, generator meta tags |

### Font files (WOFF/WOFF2/TTF/OTF)

`exiftool -j <file>`:

| Severity | Fields |
|---|---|
| **medium** | Font:CopyrightNotice, Font:License, Font:Trademark with company info |
| **low** | Font:Designer, Font:Vendor |

### Hidden sidecars (only when scanning a directory)

Flag as **high** if any of these exist in the scanned dir:

- `.DS_Store`
- `Thumbs.db`, `desktop.ini`
- `~$*` shadow copies
- `.idea/`, `.vscode/`, `.vs/`, `.settings/`, `nbproject/`
- `.git/`, `.svn/`, `.hg/`
- `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `known_hosts`
- `.bash_history`, `.zsh_history`, `.python_history`
- `Thumbs*`, `._*` (macOS resource fork stubs)

By default, exclude these from the "assets to scan" list but list them in a `## Hidden Sidecars` section of the report. Skip with `--include-hidden` to also scan their metadata.

## Redaction on report

When surfacing GPS coordinates: report degree-level truncation only (e.g. "GPS present within ~1° of 37°N, 122°W") — do NOT include full lat/long in the report body. This prevents the audit report itself from becoming a PII leak.

Similarly, redact personal path segments (`/Users/eumir/…` → `/Users/<redacted>/…`), personal names in author fields (first character + asterisks), and full serial numbers (show first 3 chars).

The RAW finding is stored in the artifact JSON with full detail; only the human-readable comment redacts.

## Output

### Executive-summary comment

Post ONE comment on the trigger issue:

```
### Metadata scan: <input> — <N> files, <severity summary>

Scanned: <count> files, <total bytes> total
Skipped: <count> (too large / unrecognized)
Severity: critical <n>, high <n>, medium <n>, low <n>, info <n>
Clean: <count>
Duration: <seconds>

#### Top findings

<table: file | severity | class | field | value (redacted) | recommendation>

Full artifact: `.raw/metadata-scans/<batch-id>/report.json` in the ITx vault.
```

### Structured artifact

Write to `.raw/metadata-scans/<UTC-timestamp>-<hash>/report.json`:

```json
{
  "input": "<original arg>",
  "scanned_at": "<UTC timestamp>",
  "scanner_version": "exiftool <ver> / mat2 <ver or null>",
  "files_scanned": <n>,
  "files_skipped": [{"path": "...", "reason": "..."}],
  "findings": [
    {"file": "<rel-path>", "class": "image|pdf|office|svg|video|audio|web|font|sidecar",
     "severity": "critical|high|medium|low|info",
     "field": "GPS:GPSLatitude", "value_redacted": "37°N", "value_raw_hash": "sha256:...",
     "recommendation": "Strip with `exiftool -gps:all= <file>`"}
  ],
  "clean_files": ["<rel-path>", ...]
}
```

Include `value_raw_hash` (SHA-256 of the raw value) for later verification without preserving the value itself.

### No writes to originals

- Never modify a target file.
- Never delete a target file.
- Never move a target file.
- Never suggest running `exiftool -all=` inline in a way the user could accidentally paste and run without review — always show the command as `exiftool -all= <file>` in a code block, not a copy-paste `--yes` construct.

## Pipeline

```bash
BATCH_ID="$(date -u +%Y-%m-%d-%H%M%S)-$(head -c 32 /dev/urandom | shasum | cut -c1-8)"
export VAULT=/tmp/itx-vault-meta-$$
gh auth setup-git
git clone --depth 5 https://github.com/sdsolutions/ITx-cybersecurity-vault.git "$VAULT"
cd "$VAULT"
mkdir -p ".raw/metadata-scans/$BATCH_ID"
git config user.email "cybersecurity-manager+bot@sdsolutions.com.ph"
git config user.name "Cybersecurity Manager (Metadata Scan)"
```

Enumerate targets, run the class-appropriate checks, build findings list, redact, write `report.json`, post comment, commit + push:

```
metadata-scan: <input-name> — <N> files, <sev summary>
```

Rebase-retry once on conflict.

## Guardrails

- **Scan-only.** No modifications, no scrubbing, no `exiftool -overwrite_original`, no `mat2` (with mat2, use `--show` only, never bare `mat2`).
- **Never store raw PII in the report comment.** Redact per §Redaction. Full raw is only in the artifact JSON, which lives in the private ITx vault.
- **Never send file bytes off-machine.** ExifTool and mat2 are fully local. If input is a URL, fetch, scan, delete the temp copy. Don't POST the file anywhere.
- **Respect scope.** Only scan files under the argument path. Never traverse outside the argument's tree.
- **Never scan** system dirs (`/System`, `/private/var`, `/Library`, `~/.ssh`, `~/.gnupg`, `~/Library/Keychains`). If the argument path resolves into any of these, refuse with a clear error.
- **Handle password-protected files gracefully** — log the failure, move on, don't attempt cracking.
- **Handle enormous binaries gracefully** — 100 MB default cap.

## Effect

Report lands as a comment; artifact lives in the vault. No target files modified. If findings warrant scrubbing, the human decides and runs it manually (or a future `--scrub` mode we build later).

## Related

- Sibling skills: `security-scan`, `tech-register`
- Runbook: `wiki/sources/cve-feed/runbook.md`
- ExifTool docs: https://exiftool.org/TagNames/
- mat2 docs: https://0xacab.org/jvoisin/mat2
