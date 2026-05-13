# ChainWatch

A supply chain security CLI that collects SBOMs from GitHub repositories and searches them for compromised, malicious, or vulnerable package versions.

---

## Prerequisites

- Python 3.11+
- [GitHub CLI](https://cli.github.com/) installed and authenticated (`gh auth login`)
- Dependency graph enabled on target repos (Settings → Security & analysis → Dependency graph)

---

## Usage

**Collect SBOMs** for specific repos or an entire org:

```bash
python chainwatch.py --org my-org --repos repo1 repo2
python chainwatch.py --org my-org --repos all
```

**Hunt for a compromised package** inline or from a watchlist file:

```bash
python chainwatch.py --org my-org --repos all --search lodash@4.17.21
python chainwatch.py --org my-org --repos all --search "pkg:npm/lodash@4.17.21"
python chainwatch.py --org my-org --repos all --search-file watchlist.txt
```

**Filter by ecosystem** to reduce noise:

```bash
python chainwatch.py --org my-org --repos all --keep npm pypi
python chainwatch.py --org my-org --repos all --exclude npm
```

### Watchlist file format

One term per line — either `name@version` or a full PURL. Blank lines and `#` comments are ignored:

```
# CVE-2024-XXXXX — short form
malicious-pkg@3.1.4

# full PURL form
pkg:npm/lodash@4.17.21
pkg:pypi/requests@2.28.0
```

---

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--org` | `-o` | required | GitHub organisation name |
| `--repos` | `-r` | required | Repo names, or `all` |
| `--output-dir` | `-d` | `./sboms` | Output directory |
| `--delay` | | `15s` | Delay between API calls (applied when > 5 repos) |
| `--keep` | | — | Keep only packages from these ecosystems (`npm`, `pypi`) |
| `--exclude` | | — | Exclude packages from these ecosystems |
| `--search` | `-s` | — | One or more `name@version` or PURL terms to search |
| `--search-file` | `-S` | — | Path to a watchlist `.txt` file (`name@version` or PURL, one per line) |

`--keep` and `--exclude` are mutually exclusive. `--search` and `--search-file` can be combined; duplicates are removed automatically.

---

## Output

Each repo produces a `<repo>_sbom.json` (or `<repo>_sbom_filtered.json` when filtering):

```json
{
  "repo_name": "finance-ai",
  "packages": [
    "pkg:npm/lodash@4.17.21",
    "pkg:pypi/requests@2.28.0"
  ]
}
```

A `_summary.json` audit log is always written, including search hits per term:

```json
{
  "org": "my-org",
  "timestamp": "2024-07-15T10:32:01+00:00",
  "search": {
    "terms": ["requests@2.28.0"],
    "hits": { "requests@2.28.0": ["finance-ai", "data-pipeline"] }
  },
  "succeeded": ["finance-ai", "data-pipeline"],
  "failed": ["legacy-monolith"]
}
```

---

## Incident Response

```bash
# 1. Add compromised versions to a watchlist
echo "malicious-pkg@3.1.4" >> watchlist.txt

# 2. Scan the org
python chainwatch.py --org my-org --repos all \
  --search-file watchlist.txt \
  --output-dir ./incident-2024-07-15

# 3. Review — affected repos are listed per term in stdout and _summary.json
```

---

## Limitations

- Search is a plain substring match on raw SBOM JSON — intentional, to ensure exact version precision.
- Only dependencies detected by GitHub's dependency graph are visible. Vendored code and non-standard manifests may not appear.
- Repos with the dependency graph disabled are skipped and recorded in `failed`.
