#!/usr/bin/env python3
"""Normalize osv-scanner JSON into ITx dep-scan findings.

Reads `osv-scanner scan ... --format json` output and writes:
  report.json          normalized findings (one per package x alias-group)
  report.md            comment-ready summary table
  discovered-tech.json input for /tech-register (native discovered-tech format)

Severity here is a SCANNER-DERIVED starting point (max CVSS of the alias
group, bumped for CISA KEV). Every finding carries triage_status
"unconfirmed" — an analyst confirms reachability, exposure and business
impact before anything is reported as a confirmed finding.

Stdlib only. Network use is limited to the optional --epss lookup
(api.first.org, CVE IDs only — never package names or source).
"""

import argparse
import gzip
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unrated"]

# PURL types per OSV ecosystem, used for tech-register hand-off.
PURL_TYPE = {
    "npm": "npm", "PyPI": "pypi", "Go": "golang", "Maven": "maven",
    "crates.io": "cargo", "RubyGems": "gem", "NuGet": "nuget",
    "Packagist": "composer", "Pub": "pub", "Hex": "hex",
    "Debian": "deb", "Ubuntu": "deb", "Alpine": "apk",
}

# tech-register pillar guess per ecosystem: OS packages are hosting/infra (3),
# language packages default to web-app (1). A human can correct later.
OS_ECOSYSTEMS = {"Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux",
                 "AlmaLinux", "SUSE", "openSUSE", "Wolfi", "Chainguard"}


def version_key(v):
    """Ecosystem-agnostic ordering heuristic: numeric parts compare as ints,
    alpha parts sort before numbers so 1.0rc1 < 1.0."""
    key = []
    for part in re.findall(r"\d+|[A-Za-z]+", v or ""):
        key.append((1, int(part), "") if part.isdigit() else (0, 0, part.lower()))
    return key


def band(score):
    if score is None:
        return "unrated"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unrated"


def parse_score(raw):
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def load_kev(path):
    if not path:
        return {}
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def fetch_epss(cves):
    """Batch EPSS lookup. Returns {cve: (epss, percentile)}; empty on failure."""
    out = {}
    cves = sorted(cves)
    for i in range(0, len(cves), 100):
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 100])
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                for row in json.load(resp).get("data", []):
                    out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
        except Exception as exc:  # best-effort enrichment
            print(f"warn: EPSS lookup failed: {exc}", file=sys.stderr)
            return out
    return out


def fixed_version(vuln, eco, name, current):
    """Smallest fixed version above `current` for this package, or None."""
    candidates = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != eco.split(":")[0] or pkg.get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                fx = ev.get("fixed")
                if fx and version_key(fx) > version_key(current):
                    candidates.append(fx)
    return min(candidates, key=version_key) if candidates else None


def rel(path, root):
    try:
        return os.path.relpath(path, root) if root else path
    except ValueError:
        return path


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scan_json", help="osv-scanner --format json output")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--input-label", required=True, help="original /dep-scan argument, for the report")
    ap.add_argument("--scan-root", help="strip this prefix from source paths")
    ap.add_argument("--kev", help="CISA KEV snapshot (.json or .json.gz) for actively-exploited cross-check")
    ap.add_argument("--epss", action="store_true", help="look up EPSS for CVE aliases (api.first.org)")
    ap.add_argument("--mode", default="online", help="online | offline (recorded in report)")
    ap.add_argument("--register", choices=["vulnerable", "all", "none"], default="vulnerable",
                    help="which packages to emit for /tech-register")
    ap.add_argument("--scanner-version", default="osv-scanner (unknown version)")
    args = ap.parse_args()

    with open(args.scan_json, encoding="utf-8") as fh:
        scan = json.load(fh)
    kev = load_kev(args.kev)

    # Never leak runtime-local absolute paths into reports: default the root
    # to the common directory of every manifest.
    if not args.scan_root:
        dirs = [os.path.dirname(r.get("source", {}).get("path", "")) for r in scan.get("results") or []]
        dirs = [d for d in dirs if os.path.isabs(d)]
        args.scan_root = os.path.commonpath(dirs) if dirs else None

    findings, all_packages, sources = [], {}, set()
    for result in scan.get("results") or []:
        src = rel(result.get("source", {}).get("path", "?"), args.scan_root)
        sources.add(src)
        for pkg in result.get("packages") or []:
            p = pkg["package"]
            eco, name, ver = p.get("ecosystem", "?"), p.get("name", "?"), p.get("version", "")
            all_packages[(eco, name, ver)] = {"ecosystem": eco, "name": name, "version": ver, "source": src}
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities") or []}
            groups = pkg.get("groups") or [{"ids": [i], "aliases": [i]} for i in vulns]
            for g in groups:
                ids = g.get("ids", [])
                aliases = sorted(set(g.get("aliases", [])) | set(ids))
                cves = sorted(a for a in aliases if a.startswith("CVE-"))
                score = parse_score(g.get("max_severity"))
                member = [vulns[i] for i in ids if i in vulns]
                fixes = [f for f in (fixed_version(v, eco, name, ver) for v in member) if f]
                summary = next((v.get("summary") for v in member if v.get("summary")), "")
                refs = []
                for v in member:
                    for r in v.get("references", []):
                        if r.get("type") in ("ADVISORY", "FIX", "WEB") and r["url"] not in refs:
                            refs.append(r["url"])
                kev_hits = [kev[c] for c in cves if c in kev]
                sev = band(score)
                if kev_hits and SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index("high"):
                    sev = "high"  # actively exploited floor; analyst may raise further
                findings.append({
                    "ecosystem": eco, "package": name, "version": ver, "source": src,
                    "primary_id": ids[0] if ids else aliases[0],
                    "ids": ids, "aliases": aliases, "cves": cves,
                    "summary": summary,
                    "cvss_max": score,
                    "severity": sev,
                    "severity_source": "scanner: max CVSS of alias group" + (" + KEV floor" if kev_hits else ""),
                    "kev": [{"cve": k["cveID"], "date_added": k.get("dateAdded"), "due_date": k.get("dueDate"),
                             "ransomware": k.get("knownRansomwareCampaignUse")} for k in kev_hits],
                    "fixed_in": max(fixes, key=version_key) if fixes else None,
                    "references": refs[:5],
                    "osv_urls": [f"https://osv.dev/vulnerability/{i}" for i in ids],
                    "triage_status": "unconfirmed",
                })

    if args.epss:
        epss = fetch_epss({c for f in findings for c in f["cves"]})
        for f in findings:
            scores = [epss[c] for c in f["cves"] if c in epss]
            f["epss"] = max(scores)[0] if scores else None
            f["epss_percentile"] = max(scores)[1] if scores else None

    def sort_key(f):
        return (0 if f["kev"] else 1, SEVERITY_ORDER.index(f["severity"]),
                -(f["cvss_max"] or 0), f["package"])
    findings.sort(key=sort_key)

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    vuln_pkgs = {(f["ecosystem"], f["package"], f["version"]) for f in findings}

    # Per-package upgrade target that clears every group with a known fix.
    upgrades = {}
    for f in findings:
        k = (f["ecosystem"], f["package"], f["version"])
        if f["fixed_in"] and (k not in upgrades or version_key(f["fixed_in"]) > version_key(upgrades[k])):
            upgrades[k] = f["fixed_in"]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "input": args.input_label,
        "scanned_at": now,
        "scanner_version": args.scanner_version,
        "mode": args.mode,
        "manifests": sorted(sources),
        "packages_scanned": len(all_packages),
        "vulnerable_packages": len(vuln_pkgs),
        "severity_counts": counts,
        "kev_matches": sum(1 for f in findings if f["kev"]),
        "upgrade_targets": [{"ecosystem": e, "package": n, "version": v, "upgrade_to": u}
                            for (e, n, v), u in sorted(upgrades.items())],
        "findings": findings,
    }
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # discovered-tech hand-off (tech-register native format + osv_packages/purl)
    reg = {"none": set(), "vulnerable": vuln_pkgs, "all": set(all_packages)}[args.register]
    tech = []
    for (eco, name, ver) in sorted(reg):
        ptype = PURL_TYPE.get(eco.split(":")[0])
        tech.append({
            "name": name, "version": ver,
            "ecosystem": eco,
            "purl": f"pkg:{ptype}/{name.replace(':', '/') if ptype == 'maven' else name}@{ver}" if ptype else None,
            "osv_packages": [f"{eco}:{name}"],
            "cpe_prefixes": [], "keyword_patterns": [name.lower()],
            "pillar_hint": 3 if eco.split(":")[0] in OS_ECOSYSTEMS else 1,
            "source": "dep-scan", "discovered_at": now,
        })
    with open(os.path.join(args.out_dir, "discovered-tech.json"), "w", encoding="utf-8") as fh:
        json.dump(tech, fh, indent=2)

    # Comment-ready markdown
    lines = [
        f"### Dependency scan: {args.input_label} — {len(findings)} advisory groups in {len(vuln_pkgs)} packages",
        "",
        f"Mode: {args.mode} · Scanner: {args.scanner_version} · Manifests: {len(sources)} · Packages: {len(all_packages)}",
        "Severity (scanner-derived, **unconfirmed**): " + ", ".join(f"{s} {counts[s]}" for s in SEVERITY_ORDER),
        f"CISA KEV matches: {report['kev_matches']}",
        "",
        "| Package | Version | Advisory | CVE | CVSS max | EPSS | Severity | KEV | Fixed in | Manifest |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append("| {eco}/{pkg} | {ver} | [{pid}]({url}) | {cve} | {cvss} | {epss} | {sev} | {kev} | {fix} | `{src}` |".format(
            eco=f["ecosystem"], pkg=f["package"], ver=f["version"], pid=f["primary_id"], url=f["osv_urls"][0],
            cve=", ".join(f["cves"][:2]) + (" …" if len(f["cves"]) > 2 else "") or "—",
            cvss=f["cvss_max"] if f["cvss_max"] is not None else "—",
            epss=f"{f['epss']:.3f}" if f.get("epss") is not None else "—", sev=f["severity"],
            kev="**YES**" if f["kev"] else "", fix=f["fixed_in"] or "no fix", src=f["source"]))
    if upgrades:
        lines += ["", "#### Upgrade targets (clears every advisory with a published fix)", "",
                  "_Heuristic — may cross a major version; check the changelog before upgrading._", ""]
        for t in report["upgrade_targets"]:
            lines.append(f"- {t['ecosystem']}/{t['package']} {t['version']} → **{t['upgrade_to']}**")
    with open(os.path.join(args.out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(json.dumps({"findings": len(findings), "vulnerable_packages": len(vuln_pkgs),
                      "packages": len(all_packages), "severity_counts": counts,
                      "kev_matches": report["kev_matches"], "registered": len(tech)}))


if __name__ == "__main__":
    main()
