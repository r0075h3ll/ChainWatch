# ChainWatch

A supply chain security CLI that scans every repository in a GitHub organization for compromised, malicious, or vulnerable package versions using the GitHub Dependency Graph SBOM API.

Provide a CSV of known-bad packages and versions; ChainWatch walks every repo's SBOM (via `gh` CLI), performs ecosystem-aware matching, and surfaces any hits — with optional JSON and HTML reports.


## Prerequisites

- Python 3.11+
- [GitHub CLI](https://cli.github.com/) installed and authenticated (`gh auth login`)
- Dependency graph enabled on target repos (Settings → Security & analysis → Dependency graph)


## Usage

```bash
# Basic scan — print findings to stdout
python chainwatch.py --csv compromised.csv --org MY_ORG

# Write a JSON report
python chainwatch.py --csv compromised.csv --org MY_ORG --output report.json

# Write a self-contained HTML security report
python chainwatch.py --csv compromised.csv --org MY_ORG --html-report report.html

# Skip archived repos and increase parallelism
python chainwatch.py --csv compromised.csv --org MY_ORG --skip-archived --concurrency 8
```


## CSV Format

ChainWatch accepts two CSV formats. Both require an `Ecosystem` column.

### Format A — Aggregated

```
Ecosystem,Package,Compromised Versions
npm,timeago.js,"4.1.2, 4.2.2"
pypi,requests,2.28.0
maven,log4j-core,"2.14.0, 2.14.1"
```

### Format B — Per-row (OSV / safedep export)

```
Ecosystem,Namespace,Name,Version,Artifact,Published,Detected
npm,,timeago.js,4.2.2,...
npm,@openclaw-cn,feishu,0.2.11,...
```

In Format B, a non-empty `Namespace` is combined with `Name` as `namespace/name` (e.g. `@openclaw-cn/feishu`).

Rows sharing the same `(ecosystem, name)` pair are merged; duplicate versions are deduplicated automatically. Rows missing `Ecosystem` are skipped with a warning.


## Options

| Flag              | Default | Description                                                       |
|-------------------|---------|-------------------------------------------------------------------|
| `--csv`           | required | Path to the compromised packages CSV                             |
| `--org`           | required | GitHub organization slug                                          |
| `--output`        | —       | Write a JSON report to this path                                  |
| `--html-report`   | —       | Write a self-contained HTML security report to this path          |
| `--skip-archived` | false   | Skip archived repositories                                        |
| `--concurrency`   | 5       | Parallel workers (1–10)                                           |


## How It Works

1. **Load** the compromised packages CSV into an in-memory lookup keyed on `(ecosystem, package_name)`.
2. **List** all repositories in the org via `gh repo list` (up to 10,000 repos; public and private).
3. **Fetch** each repo's SPDX SBOM from the GitHub Dependency Graph API (`GET /repos/{org}/{repo}/dependency-graph/sbom`).
4. **Match** — for each SBOM package, the ecosystem is extracted from its PURL before lookup. A `pypi/requests` entry in the CSV will never match an `npm/requests` dependency.
5. **Report** findings to stdout (and optionally to JSON / HTML).

Repos without an SBOM (dependency graph disabled, no manifests) are silently skipped and counted separately.


## Output

### Stdout

```
--------------------------------------------------------------
           COMPROMISED PACKAGE SCAN REPORT
--------------------------------------------------------------
  Org         : my-org
  Total repos : 120
  Scanned     : 98  |  Skipped (no SBOM): 22  |  Errors: 0
  Findings    : 3
--------------------------------------------------------------

🚨 HITS FOUND (3):

Repository                   Package       Version   Ecosystem
------------------------------------------------------------
my-org/frontend              timeago.js    4.2.2     npm
my-org/data-pipeline         requests      2.28.0    pypi
my-org/legacy-api            log4j-core    2.14.1    maven
```

### JSON report (`--output`)

```json
{
  "org": "my-org",
  "summary": {
    "repos_scanned": 98,
    "repos_skipped": 22,
    "repos_errored": 0,
    "total_findings": 3
  },
  "findings": [
    {
      "org": "my-org",
      "repo": "my-org/frontend",
      "package_name": "timeago.js",
      "matched_version": "4.2.2",
      "ecosystem": "npm",
      "purl": "pkg:npm/timeago.js@4.2.2"
    }
  ],
  "scanned_repos": ["..."],
  "skipped_repos": ["..."]
}
```

### HTML report (`--html-report`)

A self-contained dark-themed HTML file with a summary dashboard, a findings table (with repo links and PURLs), a per-ecosystem color-coded badge system, a scrollable scanned-repos list, and a remediation checklist. No external dependencies — open it in any browser.


## Exit Codes

| Code | Meaning              |
|------|----------------------|
| `0`  | Scan complete, no findings |
| `1`  | One or more compromised packages found |

The non-zero exit on findings makes ChainWatch suitable for use as a CI gate.


## Incident Response

```bash
# 1. Build a watchlist CSV from known-bad packages
echo "Ecosystem,Package,Compromised Versions" > watchlist.csv
echo "npm,malicious-pkg,3.1.4" >> watchlist.csv

# 2. Scan the org
python chainwatch.py \
  --csv watchlist.csv \
  --org my-org \
  --html-report ./incident-$(date +%F).html \
  --output ./incident-$(date +%F).json

# 3. Review — affected repos appear in stdout and in the report files
#    If malware is confirmed, report to Slack #ask-security
```


## Limitations

- Matching is exact on version string. Semver ranges are not evaluated.
- Only dependencies detected by GitHub's Dependency Graph are visible. Vendored code, non-standard manifests, and repos with the dependency graph disabled will not appear.
- `gh repo list` caps at 10,000 repos per call. Organizations larger than that are not currently supported.
- The SBOM ecosystem field is derived from the PURL; packages without a PURL `externalRef` are skipped to avoid false positives.
