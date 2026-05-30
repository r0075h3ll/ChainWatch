#!/usr/bin/env python3
"""
ChainWatch
----------
Scans all repositories in a GitHub organization for specific compromised package
versions using the GitHub Dependency Graph SBOM API (via `gh` CLI).

Usage:
    python3 chainwatch.py --csv compromised.csv --org MY_ORG
    python3 chainwatch.py --csv compromised.csv --org MY_ORG --output report.json
    python3 chainwatch.py --csv compromised.csv --org MY_ORG --html-report report.html
    python3 chainwatch.py --csv compromised.csv --org MY_ORG --skip-archived --concurrency 8
"""

import argparse
import csv
import html as html_module
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class CompromisedPackage:
    ecosystem: str       # e.g. "npm", "pypi", "maven"
    name: str
    versions: list[str]  # exact versions to match


@dataclass
class Finding:
    org: str
    repo: str
    package_name: str
    matched_version: str
    ecosystem: str
    purl: str = ""


@dataclass
class ScanResult:
    repos_scanned: int = 0
    repos_skipped: int = 0          # no SBOM / dependency graph disabled
    repos_errored: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped_repos: list[str] = field(default_factory=list)
    scanned_repos: list[str] = field(default_factory=list)


# ── CSV parsing ────────────────────────────────────────────────────────────────

def load_compromised_csv(path: str) -> list[CompromisedPackage]:
    """
    Accepts two CSV formats. Ecosystem is required in both.

    Format A — aggregated:
      Ecosystem,Package,Compromised Versions
      npm,timeago.js,"4.1.2, 4.2.2"
      pypi,requests,2.28.0

    Format B — per-row (OSV/safedep export):
      Ecosystem,Namespace,Name,Version,Artifact,Published,Detected
      npm,,timeago.js,4.2.2,...
      npm,@openclaw-cn,feishu,0.2.11,...   → package name = @openclaw-cn/feishu

    Rows with the same (ecosystem, name) are merged; duplicates are deduplicated.
    Rows missing ecosystem or name are skipped with a warning.
    """
    # key: (ecosystem_lower, name) → set of versions
    packages: dict[tuple[str, str], set[str]] = {}
    skipped = 0

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []

        if "Name" in headers and "Version" in headers:
            # Format B
            for i, row in enumerate(reader, start=2):
                ecosystem = row.get("Ecosystem", "").strip().lower()
                namespace = row.get("Namespace", "").strip()
                name = row.get("Name", "").strip()
                version = row.get("Version", "").strip()
                if not ecosystem:
                    print(f"  ⚠️  Row {i}: missing Ecosystem — skipped", file=sys.stderr)
                    skipped += 1
                    continue
                if not name or not version:
                    continue
                full_name = f"{namespace}/{name}" if namespace else name
                packages.setdefault((ecosystem, full_name), set()).add(version)
        else:
            # Format A — requires Ecosystem column
            if "Ecosystem" not in headers:
                print(
                    "ERROR: Format A CSV must have an 'Ecosystem' column.\n"
                    "Expected header: Ecosystem,Package,Compromised Versions",
                    file=sys.stderr,
                )
                sys.exit(1)
            for i, row in enumerate(reader, start=2):
                ecosystem = row.get("Ecosystem", "").strip().lower()
                name = row.get("Package", "").strip().strip('"')
                versions_raw = row.get("Compromised Versions", "").strip().strip('"')
                if not ecosystem:
                    print(f"  ⚠️  Row {i}: missing Ecosystem — skipped", file=sys.stderr)
                    skipped += 1
                    continue
                if not name or not versions_raw:
                    continue
                for v in versions_raw.split(","):
                    v = v.strip()
                    if v:
                        packages.setdefault((ecosystem, name), set()).add(v)

    if skipped:
        print(f"  ⚠️  {skipped} row(s) skipped due to missing ecosystem.", file=sys.stderr)

    return [
        CompromisedPackage(ecosystem=eco, name=n, versions=sorted(vs))
        for (eco, n), vs in packages.items()
    ]


# ── GitHub helpers (via gh CLI) ────────────────────────────────────────────────

def run_gh(args: list[str], timeout: int = 30) -> tuple[bool, str, str]:
    """Run a gh CLI command. Returns (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            ["gh"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except FileNotFoundError:
        print("ERROR: `gh` CLI not found. Install from https://cli.github.com/", file=sys.stderr)
        sys.exit(1)


def list_org_repos(org: str, skip_archived: bool = False) -> list[str]:
    """
    Returns a list of repo names (without org prefix) for the given org.
    Uses `gh repo list` with --limit 10000 to handle large orgs.
    Both public and private repos are included (requires appropriate token scope).
    """
    print(f"📋 Listing repositories for org: {org} ...")
    args = [
        "repo", "list", org,
        "--limit", "10000",
        "--json", "name,isArchived",
    ]
    ok, stdout, stderr = run_gh(args, timeout=120)
    if not ok:
        print(f"ERROR listing repos: {stderr}", file=sys.stderr)
        sys.exit(1)

    repos_data = json.loads(stdout)
    repos = []
    for r in repos_data:
        if skip_archived and r.get("isArchived", False):
            continue
        repos.append(r["name"])

    print(f"   Found {len(repos)} repositories.")
    return repos


def fetch_sbom(org: str, repo: str) -> Optional[dict]:
    """
    Fetch SPDX SBOM for a repo via GitHub REST API.
    Returns parsed JSON dict or None if unavailable.
    """
    endpoint = f"/repos/{org}/{repo}/dependency-graph/sbom"
    ok, stdout, stderr = run_gh(["api", endpoint], timeout=30)
    if not ok:
        # 404 = dependency graph not enabled or no manifest; silently skip
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


# ── Core matching logic ────────────────────────────────────────────────────────

def build_lookup(packages: list[CompromisedPackage]) -> dict[tuple[str, str], set[str]]:
    """Build a fast lookup: (ecosystem_lower, name_lower) -> set of compromised versions."""
    lookup: dict[tuple[str, str], set[str]] = {}
    for pkg in packages:
        key = (pkg.ecosystem.lower(), pkg.name.lower())
        lookup.setdefault(key, set()).update(pkg.versions)
    return lookup


def check_sbom(sbom_json: dict, lookup: dict[tuple[str, str], set[str]], org: str, repo: str) -> list[Finding]:
    """
    Walk the SBOM packages list and return any findings.
    Matching is ecosystem-aware: a CSV entry for npm/lodash will NOT match pypi/lodash.
    SBOM packages look like:
      { "name": "lodash", "versionInfo": "4.17.20",
        "externalRefs": [{"referenceLocator": "pkg:npm/lodash@4.17.20", ...}] }
    """
    findings = []
    sbom = sbom_json.get("sbom", {})
    packages = sbom.get("packages", [])

    for pkg in packages:
        name = pkg.get("name", "").strip()
        version = pkg.get("versionInfo", "").strip()
        if not name or not version:
            continue

        # Extract ecosystem from PURL before matching — required for ecosystem-aware lookup
        purl = ""
        ecosystem = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                # purl format: pkg:ECOSYSTEM/[namespace/]name@version
                if purl.startswith("pkg:"):
                    ecosystem = purl[4:].split("/")[0].lower()
                break

        if not ecosystem:
            continue  # can't determine ecosystem; skip to avoid false positives

        compromised_versions = lookup.get((ecosystem, name.lower()))
        if not compromised_versions:
            continue

        if version in compromised_versions:
            findings.append(Finding(
                org=org,
                repo=f"{org}/{repo}",
                package_name=name,
                matched_version=version,
                ecosystem=ecosystem,
                purl=purl,
            ))

    return findings


# ── Scan worker ────────────────────────────────────────────────────────────────

def scan_repo(org: str, repo: str, lookup: dict[str, set[str]]) -> tuple[str, str, list[Finding]]:
    """
    Worker function: fetch SBOM for one repo and return findings.
    Returns (repo, status, findings) where status is 'ok'|'skipped'|'error'.
    """
    sbom = fetch_sbom(org, repo)
    if sbom is None:
        return repo, "skipped", []

    findings = check_sbom(sbom, lookup, org, repo)
    return repo, "ok", findings


# ── Output formatting ──────────────────────────────────────────────────────────

def print_results(result: ScanResult, org: str):
    total = result.repos_scanned + result.repos_skipped + result.repos_errored
    print()
    print("=" * 65)
    print("           COMPROMISED PACKAGE SCAN REPORT")
    print("=" * 65)
    print(f"  Org         : {org}")
    print(f"  Total repos : {total}")
    print(f"  Scanned     : {result.repos_scanned}  |  Skipped (no SBOM): {result.repos_skipped}  |  Errors: {result.repos_errored}")
    print(f"  Findings    : {len(result.findings)}")
    print("=" * 65)

    if not result.findings:
        print("\n✅ No compromised packages found.")
        return

    print(f"\n🚨 HITS FOUND ({len(result.findings)}):\n")
    col_repo  = max(len(f.repo) for f in result.findings) + 2
    col_pkg   = max(len(f.package_name) for f in result.findings) + 2
    col_ver   = max(len(f.matched_version) for f in result.findings) + 2
    col_eco   = max(len(f.ecosystem) for f in result.findings) + 2

    header = (
        f"{'Repository':<{col_repo}} "
        f"{'Package':<{col_pkg}} "
        f"{'Version':<{col_ver}} "
        f"{'Ecosystem':<{col_eco}}"
    )
    print(header)
    print("-" * len(header))
    for f in result.findings:
        print(
            f"{f.repo:<{col_repo}} "
            f"{f.package_name:<{col_pkg}} "
            f"{f.matched_version:<{col_ver}} "
            f"{f.ecosystem:<{col_eco}}"
        )
    print()
    print("⚠️  Remediation: Update affected packages immediately.")
    print("   If packages are confirmed malware, report to Slack #ask-security.")


def write_report(result: ScanResult, org: str, output_path: str):
    report = {
        "org": org,
        "summary": {
            "repos_scanned": result.repos_scanned,
            "repos_skipped": result.repos_skipped,
            "repos_errored": result.repos_errored,
            "total_findings": len(result.findings),
        },
        "findings": [asdict(f) for f in result.findings],
        "scanned_repos": sorted(result.scanned_repos),
        "skipped_repos": sorted(result.skipped_repos),
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n📄 Full report written to: {output_path}")


# ── HTML Report ───────────────────────────────────────────────────────────────

def write_html_report(result: ScanResult, org: str, packages: list[CompromisedPackage], output_path: str):
    """Generate a self-contained HTML security report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_repos = result.repos_scanned + result.repos_skipped + result.repos_errored
    num_findings = len(result.findings)
    severity_class = "critical" if num_findings > 0 else "clean"
    severity_label = f"🚨 {num_findings} FINDING{'S' if num_findings != 1 else ''} — IMMEDIATE ACTION REQUIRED" if num_findings > 0 else "✅ No Compromised Packages Found"

    # Build findings rows
    findings_rows = ""
    if result.findings:
        for f in result.findings:
            repo_url = f"https://github.com/{f.repo}"
            purl_cell = f'<code class="purl">{html_module.escape(f.purl)}</code>' if f.purl else "—"
            findings_rows += f"""
            <tr>
              <td><a href="{html_module.escape(repo_url)}" target="_blank">{html_module.escape(f.repo)}</a></td>
              <td><span class="pkg-name">{html_module.escape(f.package_name)}</span></td>
              <td><span class="version-badge">{html_module.escape(f.matched_version)}</span></td>
              <td><span class="eco-badge eco-{html_module.escape(f.ecosystem)}">{html_module.escape(f.ecosystem)}</span></td>
              <td>{purl_cell}</td>
            </tr>"""
    else:
        findings_rows = '<tr><td colspan="5" class="no-findings">No compromised packages detected.</td></tr>'

    # Build scanned repos table rows
    scanned_repos_rows = "".join(
        f'<tr><td><a href="https://github.com/{html_module.escape(org)}/{html_module.escape(r)}" target="_blank">'
        f'{html_module.escape(r)}</a></td></tr>'
        for r in sorted(result.scanned_repos)
    ) or '<tr><td class="no-findings">No repositories were scanned.</td></tr>'

    # Build scanned packages list
    pkg_list_items = "".join(
        f'<li>'
        f'<span class="eco-badge eco-{html_module.escape(p.ecosystem)}">{html_module.escape(p.ecosystem)}</span> '
        f'<code>{html_module.escape(p.name)}</code> — '
        f'{", ".join(f"<span class=\'version-badge\'>{html_module.escape(v)}</span>" for v in p.versions)}'
        f'</li>'
        for p in packages
    )

    # Group findings by repo for the summary sidebar
    repos_hit = sorted({f.repo for f in result.findings})
    repos_hit_html = "".join(
        f'<li><a href="https://github.com/{html_module.escape(r)}" target="_blank">{html_module.escape(r)}</a></li>'
        for r in repos_hit
    ) or "<li>None</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Security Scan Report — {html_module.escape(org)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      min-height: 100vh;
    }}

    /* ── Header ── */
    .header {{
      background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
      border-bottom: 1px solid #30363d;
      padding: 2rem 2.5rem;
      display: flex;
      align-items: center;
      gap: 1.5rem;
    }}
    .header-icon {{ font-size: 2.5rem; }}
    .header-title {{ font-size: 1.5rem; font-weight: 700; color: #f0f6fc; }}
    .header-sub {{ font-size: 0.875rem; color: #8b949e; margin-top: 0.2rem; }}

    /* ── Banner ── */
    .banner {{
      padding: 1rem 2.5rem;
      font-weight: 600;
      font-size: 1rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .banner.critical {{ background: #3d1a1a; border-left: 4px solid #f85149; color: #ffa198; }}
    .banner.clean    {{ background: #0f2d1c; border-left: 4px solid #3fb950; color: #56d364; }}

    /* ── Layout ── */
    .container {{ max-width: 1280px; margin: 0 auto; padding: 2rem 2.5rem; }}
    .grid {{ display: grid; grid-template-columns: 1fr 300px; gap: 1.5rem; align-items: start; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}

    /* ── Cards ── */
    .card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }}
    .card-header {{
      background: #1c2128;
      padding: 0.85rem 1.25rem;
      font-weight: 600;
      font-size: 0.9rem;
      color: #f0f6fc;
      border-bottom: 1px solid #30363d;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .card-body {{ padding: 1.25rem; }}

    /* ── Stat boxes ── */
    .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }}
    @media (max-width: 700px) {{ .stats {{ grid-template-columns: repeat(2, 1fr); }} }}
    .stat {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 1rem 1.25rem;
      text-align: center;
    }}
    .stat-value {{ font-size: 2rem; font-weight: 700; color: #f0f6fc; }}
    .stat-value.danger {{ color: #f85149; }}
    .stat-value.ok     {{ color: #3fb950; }}
    .stat-label {{ font-size: 0.75rem; color: #8b949e; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }}

    /* ── Table ── */
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th {{
      background: #1c2128;
      color: #8b949e;
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.65rem 1rem;
      text-align: left;
      border-bottom: 1px solid #30363d;
    }}
    td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #21262d; vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #1c2128; }}
    a {{ color: #58a6ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    /* ── Badges ── */
    .version-badge {{
      background: #3d1a1a;
      color: #ffa198;
      border: 1px solid #6e2020;
      border-radius: 4px;
      padding: 0.15rem 0.5rem;
      font-size: 0.8rem;
      font-family: monospace;
      white-space: nowrap;
    }}
    .pkg-name {{ font-family: monospace; color: #e3b341; font-weight: 600; }}
    .eco-badge {{
      border-radius: 12px;
      padding: 0.15rem 0.6rem;
      font-size: 0.75rem;
      font-weight: 600;
      background: #1f3347;
      color: #58a6ff;
      border: 1px solid #1f6feb;
    }}
    .eco-badge.eco-npm    {{ background: #1e2d1e; color: #3fb950; border-color: #238636; }}
    .eco-badge.eco-pypi   {{ background: #2d2416; color: #e3b341; border-color: #9e6a03; }}
    .eco-badge.eco-rubygems {{ background: #3d1a1a; color: #ffa198; border-color: #6e2020; }}
    .eco-badge.eco-maven  {{ background: #1a1f3d; color: #a5d6ff; border-color: #1f6feb; }}
    .eco-badge.eco-unknown {{ background: #21262d; color: #8b949e; border-color: #30363d; }}

    .purl {{ font-size: 0.75rem; color: #8b949e; word-break: break-all; }}
    .no-findings {{ text-align: center; padding: 2rem; color: #56d364; font-weight: 600; }}

    /* ── Sidebar ── */
    .sidebar .card {{ margin-bottom: 1rem; }}
    .sidebar ul {{ list-style: none; padding: 0; }}
    .sidebar li {{ padding: 0.4rem 0; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
    .sidebar li:last-child {{ border-bottom: none; }}
    .sidebar code {{
      background: #21262d;
      border-radius: 3px;
      padding: 0.1rem 0.35rem;
      font-size: 0.8rem;
      color: #e3b341;
    }}
    .sidebar .version-badge {{ font-size: 0.72rem; }}

    /* ── Scrollable repo list ── */
    .repo-table-wrap {{
      max-height: 400px;
      overflow-y: auto;
      border-radius: 0 0 8px 8px;
    }}
    .repo-table-wrap table {{ font-size: 0.85rem; }}
    .repo-table-wrap td {{ padding: 0.5rem 1rem; }}

    /* ── Footer ── */
    .footer {{
      text-align: center;
      color: #484f58;
      font-size: 0.8rem;
      padding: 2rem;
      border-top: 1px solid #21262d;
      margin-top: 2rem;
    }}

    /* ── Remediation box ── */
    .remediation {{
      background: #2d1f00;
      border: 1px solid #9e6a03;
      border-radius: 8px;
      padding: 1rem 1.25rem;
      margin-top: 1.5rem;
      font-size: 0.875rem;
      color: #e3b341;
    }}
    .remediation strong {{ color: #f0f6fc; }}
    .remediation ul {{ margin-top: 0.5rem; padding-left: 1.25rem; line-height: 1.8; }}
  </style>
</head>
<body>

<div class="header">
  <div class="header-icon">🔐</div>
  <div>
    <div class="header-title">Security Scan Report — {html_module.escape(org)}</div>
    <div class="header-sub">GitHub Dependency Graph · Compromised Package Audit · Generated {ts}</div>
  </div>
</div>

<div class="banner {severity_class}">{severity_label}</div>

<div class="container">

  <!-- Stats row -->
  <div class="stats">
    <div class="stat">
      <div class="stat-value">{total_repos}</div>
      <div class="stat-label">Repos Processed</div>
    </div>
    <div class="stat">
      <div class="stat-value">{result.repos_scanned}</div>
      <div class="stat-label">Repos Scanned</div>
    </div>
    <div class="stat">
      <div class="stat-value">{len(packages)}</div>
      <div class="stat-label">Packages Checked</div>
    </div>
    <div class="stat">
      <div class="stat-value {'danger' if num_findings > 0 else 'ok'}">{num_findings}</div>
      <div class="stat-label">Findings</div>
    </div>
  </div>

  <div class="grid">
    <!-- Main content -->
    <div class="main">
      <div class="card">
        <div class="card-header">⚠️ Findings</div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Repository</th>
                <th>Package</th>
                <th>Version</th>
                <th>Ecosystem</th>
                <th>PURL</th>
              </tr>
            </thead>
            <tbody>{findings_rows}</tbody>
          </table>
        </div>
      </div>

      {"" if num_findings == 0 else '''
      <div class="remediation">
        <strong>⚡ Recommended Actions</strong>
        <ul>
          <li>Update or remove each affected package immediately.</li>
          <li>Audit <code>package-lock.json</code> / <code>yarn.lock</code> / <code>requirements.txt</code> in impacted repos.</li>
          <li>If packages are confirmed malware, report to Slack <code>#ask-security</code> right away.</li>
          <li>Consider adding these package names to your dependency review policy to block future installs.</li>
        </ul>
      </div>
      '''}

      <div class="card">
        <div class="card-header">✅ Scanned Repositories ({result.repos_scanned})</div>
        <div class="repo-table-wrap">
          <table>
            <thead><tr><th>Repository</th></tr></thead>
            <tbody>{scanned_repos_rows}</tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Sidebar -->
    <div class="sidebar">
      <div class="card">
        <div class="card-header">📊 Scan Summary</div>
        <div class="card-body">
          <ul>
            <li>Org: <strong>{html_module.escape(org)}</strong></li>
            <li>Total repos: <strong>{total_repos}</strong></li>
            <li>Scanned: <strong>{result.repos_scanned}</strong></li>
            <li>Skipped (no SBOM): <strong>{result.repos_skipped}</strong></li>
            <li>Errors: <strong>{result.repos_errored}</strong></li>
            <li>Repos with hits: <strong>{len(repos_hit)}</strong></li>
          </ul>
        </div>
      </div>

      {"" if num_findings == 0 else f"""
      <div class="card">
        <div class="card-header">🎯 Affected Repos</div>
        <div class="card-body">
          <ul>{repos_hit_html}</ul>
        </div>
      </div>
      """}

      <div class="card">
        <div class="card-header">🔍 Packages Audited</div>
        <div class="card-body">
          <ul>{pkg_list_items}</ul>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="footer">
  Generated by ChainWatch · {ts} · GitHub Dependency Graph SBOM API
</div>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"\n🌐 HTML report written to: {output_path}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan a GitHub org's repos for compromised package versions."
    )
    parser.add_argument("--csv", required=True, help="Path to CSV file (Package, Compromised Versions)")
    parser.add_argument("--org", required=True, help="GitHub organization slug")
    parser.add_argument("--output", default="", help="Optional: write JSON report to this file")
    parser.add_argument("--html-report", default="", metavar="FILE", help="Optional: write HTML security report to this file")
    parser.add_argument("--skip-archived", action="store_true", help="Skip archived repositories")
    parser.add_argument("--concurrency", type=int, default=5, help="Parallel workers (default: 5, max: 10)")
    args = parser.parse_args()

    # Validate inputs
    if not Path(args.csv).exists():
        print(f"ERROR: CSV file not found: {args.csv}", file=sys.stderr)
        sys.exit(1)

    concurrency = max(1, min(args.concurrency, 10))

    # Load compromised packages
    packages = load_compromised_csv(args.csv)
    if not packages:
        print("ERROR: No packages loaded from CSV.", file=sys.stderr)
        sys.exit(1)
    print(f"🔍 Loaded {len(packages)} compromised package(s) from {args.csv}")
    for p in packages:
        print(f"   - [{p.ecosystem}] {p.name}: {', '.join(p.versions)}")

    lookup = build_lookup(packages)

    # List all org repos
    repos = list_org_repos(args.org, skip_archived=args.skip_archived)
    if not repos:
        print("No repositories found. Check org name and token permissions.")
        sys.exit(0)

    # Scan repos in parallel
    result = ScanResult()
    total = len(repos)
    done = 0

    print(f"\n🔎 Scanning {total} repos with {concurrency} workers ...\n")

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(scan_repo, args.org, repo, lookup): repo
            for repo in repos
        }
        for future in as_completed(futures):
            repo_name, status, findings = future.result()
            done += 1
            bar_done = int(40 * done / total)
            bar = "█" * bar_done + "░" * (40 - bar_done)
            status_icon = {"ok": "✓", "skipped": "–", "error": "✗"}.get(status, "?")
            print(f"\r  [{bar}] {done}/{total} {status_icon} {repo_name[:40]:<40}", end="", flush=True)

            if status == "ok":
                result.repos_scanned += 1
                result.findings.extend(findings)
                result.scanned_repos.append(repo_name)
            elif status == "skipped":
                result.repos_skipped += 1
                result.skipped_repos.append(repo_name)
            else:
                result.repos_errored += 1

            # Gentle rate-limit throttle: pause briefly every 50 repos
            if done % 50 == 0:
                time.sleep(1)

    print()  # newline after progress bar

    # Print results
    print_results(result, args.org)

    # Write JSON report if requested
    if args.output:
        write_report(result, args.org, args.output)

    # Write HTML report if requested
    if args.html_report:
        write_html_report(result, args.org, packages, args.html_report)

    # Exit code: 1 if findings, 0 if clean (useful for CI)
    sys.exit(1 if result.findings else 0)


if __name__ == "__main__":
    main()
