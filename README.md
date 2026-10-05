# GitHub Pull Request Miner

Downloads GitHub PR data (JSON, diffs, reviews, comments) with automatic
token rotation when rate limits are hit.

Usage:
```
    python pr-miner.py [options] <repo1> [<repo2> ...]
```

Environment:
```
    GH_TOKEN_LIST  Comma-delimited list of GitHub personal access tokens.
                   Set this in a .env file (see .env.example).
```

Data is stored under `data/<owner>/<repo>/<pr_id>/`:
```
    <pr_id>.json          Pull request metadata
    <pr_id>.diff          Unified diff of the PR
    reviews/
        comments.json     Review comments as a JSON array (only with --reviews)
        <review_id>.json  Review objects (only with --reviews)
    comments.json         PR review comments as a JSON array (only with --comments)
    timeline.json         PR issue timeline as a JSON array (only with --timeline)
    commits/
        <sha>.json        Commit metadata (only with --commits)
        <sha>.diff        Commit diff (only with --commits)
```

## Usage

```
usage: pr-miner.py [-h] [--languages LANG [LANG ...]] [--min-participants N] [--keywords KW [KW ...]] [--opened-before ISO_DATE] [--no-language-filter]
                [--reviews] [--comments] [--timeline] [--commits] [--data-dir DIR] [--verbose]
                [owner/repo ...]

positional arguments:
  owner/repo            Repositories to scrape (e.g. torvalds/linux). Not required when --reviews, --comments, --timeline, or --commits is used alone
                        to backfill existing data.

options:
  -h, --help            show this help message and exit
  --data-dir DIR        Root directory for downloaded data (default: data).
  --verbose, -v         Enable debug logging.

filtering:
  --languages LANG [LANG ...]
                        Only include repos written in these languages (default: ['Java', 'Python', 'C', 'C++']). Pass an empty string to disable
                        language filtering.
  --min-participants N  Minimum number of unique participants (default: 2).
  --keywords KW [KW ...]
                        Keywords to search for in PR title/body (default: ['CWE-', 'CVE-']).
  --opened-before ISO_DATE
                        Only include PRs opened before this date (default: 2026-08-12T00:00:00+00:00).
  --no-language-filter  Disable language filtering entirely.

modes:
  --diffs               Download (or backfill) PR diffs.
  --reviews             Download (or backfill) PR reviews.
  --comments            Download (or backfill) PR review comments.
  --timeline            Backfill PR issue timeline data (stored as timeline.json).
  --commits             Backfill PR commit metadata and diffs (stored in commits/).
```

# CWE Catalog Miner

Downloads the full Common Weakness Enumeration (CWE) catalog from MITRE's
public REST API (`cwe-api.mitre.org`) — no XML parsing, no credentials
required.

Usage:
```
    python cwe-miner.py [options]
```

Data is stored under `cwes/<type>/cwe-<id>.json` (or `--data-dir`):
```
    weakness/cwe-<id>.json   One file per CWE weakness entry
    category/cwe-<id>.json   One file per CWE category entry
    view/cwe-<id>.json       One file per CWE view entry
```

## Usage

```
usage: cwe-miner.py [-h] [--start START] [--end END]
                    [--types {category,view,weakness} [{category,view,weakness} ...]]
                    [--data-dir DATA_DIR] [--force] [--verbose]

options:
  -h, --help            show this help message and exit
  --start START         Only write entries with CWE ID >= START.
  --end END             Only write entries with CWE ID <= END.
  --types {category,view,weakness} [{category,view,weakness} ...]
                        Which CWE entry types to download (default: all).
  --data-dir DATA_DIR   Root directory for downloaded data (default: cwes).
  --force               Re-fetch from the API and overwrite existing files.
  --verbose, -v         Enable debug logging.
```

Reruns are safe: existing `cwe-<id>.json` files are skipped unless
`--force` is passed.

# CVE Downloader

Downloads a single CVE's metadata and change history from NVD's public
REST API (`services.nvd.nist.gov`), given its ID.

Usage:
```
    python cve-downloader.py CVE-2021-44228 [options]
```

Environment:
```
    NVD_API_KEY  Optional. Raises the rate limit from 5 req/30s to 50
                 req/30s. Set this in a .env file (see .env.example).
```

Data is stored under `cves/<id>/` (or `--data-dir`), as the full,
unmodified NVD API response for each endpoint:
```
    <id>.json      Raw response from the CVE metadata endpoint
    history.json   Raw response from the CVE history endpoint
                   (cveChanges merged across pages if there was more than one)
```

## Usage

```
usage: cve-downloader.py [-h] [--data-dir DATA_DIR] [--force] [--skip-history]
                         [--verbose]
                         cve_id

positional arguments:
  cve_id               CVE ID to download, e.g. CVE-2021-44228

options:
  -h, --help           show this help message and exit
  --data-dir DATA_DIR  Root directory for downloaded data (default: cves).
  --force              Re-fetch from the API and overwrite existing files.
  --skip-history       Only fetch metadata, skip the (slow) history scan.
  --verbose, -v        Enable debug logging.
```

Reruns are safe: existing files are skipped unless `--force` is passed.

# Find CVEs in PRs

Scans every mined PR under `data/` for CVE ID mentions, then invokes
`cve-downloader.py` for each distinct CVE found so its metadata gets
downloaded. Every file in a PR's directory is scanned as plain text
(not schema-aware JSON parsing) except `*.diff` files, which are excluded
since they include unchanged surrounding context lines that can produce
false matches unrelated to that PR.

Requires `cve-downloader.py` to be present alongside this script.

Usage:
```
    python find-cves-in-prs.py [options]
```

## Usage

usage: find-cves-in-prs.py [-h] [--data-dir DATA_DIR]
                           [--cve-data-dir CVE_DATA_DIR] [--force]
                           [--skip-history] [--verbose]

options:
  -h, --help            show this help message and exit
  --data-dir DATA_DIR   Root directory of mined PR data (default: data).
  --cve-data-dir CVE_DATA_DIR
                        Root directory passed to cve-downloader.py for
                        downloaded CVE data (default: cves).
  --force               Pass --force through to cve-downloader.py to
                        re-fetch and overwrite existing files.
  --skip-history        Pass --skip-history through to cve-downloader.py.
  --verbose, -v         Enable debug logging.
```

# Filtering PRs

We moved any PRs from Dependabot using `move-dependabot.py` and then filter
any PRs that don't change a source file using `filter-prs.py`.
