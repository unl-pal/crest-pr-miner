#!/usr/bin/env python3
"""
Find CVEs in PRs

Scans every mined PR under data/ for CVE ID mentions and builds a single
aggregate index. Every file in a PR's directory is scanned as plain text
(regardless of its actual format - PR metadata, comments, reviews, timeline,
commit metadata are all JSON, but this searches text rather than parsing
each file's schema) except *.diff files, which are excluded: they include
unchanged surrounding context lines, so a CVE mentioned elsewhere in a file
would show up in a diff even when unrelated to that PR.

Output is a single JSON file mapping each distinct CVE ID to every PR
directory (data/<owner>/<repo>/<pr_id>) it was found in:
    {
      "CVE-2021-44228": ["data/apache/log4j-core/456", "data/torvalds/linux/123"],
      "CVE-2019-1010218": ["data/some/repo/789"]
    }

Usage:
    python find-cves-in-prs.py [--data-dir DIR] [--output PATH] [--verbose]
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

DATA_ROOT = Path("data")
DEFAULT_OUTPUT = DATA_ROOT / "cve_index.json"
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _pr_dir_for(file_path: Path, data_dir: Path) -> Path | None:
    """Return the owning PR directory (data/<owner>/<repo>/<pr_id>) for a
    file under data_dir, or None if it's not deep enough to belong to one."""
    rel_parts = file_path.relative_to(data_dir).parts
    if len(rel_parts) < 3:
        return None
    return data_dir / rel_parts[0] / rel_parts[1] / rel_parts[2]


def build_cve_index(data_dir: Path) -> dict:
    """Scan every non-.diff file under data_dir and return {cve_id: [pr_dir, ...]}."""
    index: dict[str, set[str]] = {}
    files_scanned = 0
    files_skipped = 0

    for file_path in sorted(data_dir.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.suffix == ".diff":
            files_skipped += 1
            continue

        pr_dir = _pr_dir_for(file_path, data_dir)
        if pr_dir is None:
            continue

        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("Could not read %s: %s", file_path, exc)
            continue

        files_scanned += 1
        for match in CVE_ID_RE.findall(text):
            cve_id = match.upper()
            index.setdefault(cve_id, set()).add(pr_dir.as_posix())

    logger.info("Scanned %d files (%d .diff files skipped)", files_scanned, files_skipped)
    return {cve_id: sorted(prs) for cve_id, prs in sorted(index.items())}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build an index of CVE mentions across mined PRs.")
    parser.add_argument("--data-dir", type=Path, default=DATA_ROOT, help=f"Root directory of mined PR data (default: {DATA_ROOT}).")
    parser.add_argument("--output", type=Path, default=None, help=f"Output path for the index (default: <data-dir>/cve_index.json).")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    args = parser.parse_args(argv)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.data_dir.exists():
        logger.error("Data directory %s does not exist", args.data_dir)
        return 1

    output_path = args.output or (args.data_dir / "cve_index.json")

    index = build_cve_index(args.data_dir)
    output_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")

    total_prs = len({pr for prs in index.values() for pr in prs})
    logger.info("Found %d distinct CVEs across %d PRs. Saved %s", len(index), total_prs, output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
