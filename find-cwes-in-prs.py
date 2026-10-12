#!/usr/bin/env python3
"""
Find CWEs in PRs

For every mined PR under data/ (the tree pr-miner.py produces:
data/<owner>/<repo>/<pr_id>/..., optionally with reviews/ and commits/
subdirectories), collects CWE IDs from two sources and writes them to
a per-PR cwes.json, keyed by CWE ID, recording where each one came from:

    {
      "CWE-20":  {"mentioned": true,  "via_cves": ["CVE-2021-44228"]},
      "CWE-400": {"mentioned": false, "via_cves": ["CVE-2021-44228"]},
      "CWE-79":  {"mentioned": true,  "via_cves": []}
    }

    "mentioned" is true if the CWE ID appears in the PR's own files
    (source 1 below); "via_cves" lists the CVEs whose metadata mentions
    it (source 2 below). A CWE found both ways has both set.

    1. Direct CWE ID mentions in the PR's own JSON files (scanned as
       plain text, recursively). *.diff files are excluded, as are the
       per-PR output files cves.json and cwes.json.

    2. CWE IDs mentioned in the downloaded NVD metadata
       (cves/<id>/<id>.json, see cve-downloader.py) of every CVE listed
       in the PR's cves.json. cves.json is produced by
       find-cves-in-prs.py, which must be run first; this script only
       reads it. The metadata is scanned as plain text, so CWEs in the
       "weaknesses" field as well as ones mentioned in descriptions are
       picked up. NVD placeholder values like NVD-CWE-noinfo aren't
       real CWE IDs and don't match.

CWE IDs are normalized (e.g. CWE-01 -> CWE-1), and only CWEs that exist,
i.e. have metadata downloaded by cwe-miner.py under cwes/weakness/,
cwes/category/ or cwes/view/, are kept; the rest are dropped.

Usage:
    python find-cwes-in-prs.py [--data-dir DIR] [--cve-data-dir DIR] [--cwe-data-dir DIR] [--verbose]
"""

import argparse
import json
import logging
import os
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
SKIPPED_DATA_ROOT = Path("skipped")
CVE_DATA_ROOT = Path("cves")
CWE_DATA_ROOT = Path("cwes")
CWE_TYPES = ("weakness", "category", "view")
CWE_ID_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

OUTPUT_FILENAMES = {"cwes.json", "cves.json"}


def find_pr_dirs(data_dir: Path):
    """Yield every mined PR directory under data_dir (data/<owner>/<repo>/<pr_id>)."""
    for owner_dir in sorted(p for p in data_dir.iterdir() if p.is_dir()):
        for repo_dir in sorted(p for p in owner_dir.iterdir() if p.is_dir()):
            for pr_dir in sorted(p for p in repo_dir.iterdir() if p.is_dir()):
                yield pr_dir


def normalize_cwe_id(number: str) -> str:
    """Return the canonical CWE ID for a CWE number, e.g. "01" -> "CWE-1"."""
    return f"CWE-{int(number)}"


def is_valid_cwe(cwe_id: str, cwe_data_dir: Path) -> bool:
    """Return True if cwe_id (normalized, e.g. "CWE-79") has downloaded
    metadata under any of the cwe-miner.py subdirectories of cwe_data_dir."""
    filename = f"{cwe_id.lower()}.json"
    return any((cwe_data_dir / cwe_type / filename).is_file() for cwe_type in CWE_TYPES)


def find_cwe_ids(text: str) -> set[str]:
    return {normalize_cwe_id(number) for number in CWE_ID_RE.findall(text)}


def cwes_in_pr_files(pr_dir: Path) -> set[str]:
    """Return CWE IDs mentioned in the PR's own JSON files (recursively,
    including reviews/ and commits/), skipping the per-PR output files."""
    cwe_ids = set()
    for file_path in pr_dir.rglob("*.json"):
        if not file_path.is_file() or file_path.name in OUTPUT_FILENAMES:
            continue
        try:
            cwe_ids |= find_cwe_ids(file_path.read_text(encoding="utf-8", errors="ignore"))
        except OSError as exc:
            logger.warning("Could not read %s: %s", file_path, exc)
    return cwe_ids


def load_pr_cves(pr_dir: Path) -> list[str]:
    """Return the CVE IDs listed in the PR's cves.json (written by
    find-cves-in-prs.py), or [] if it's missing or not in that format."""
    cves_path = pr_dir / "cves.json"
    if not cves_path.exists():
        return []
    try:
        return json.loads(cves_path.read_text(encoding="utf-8"))["cves"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logger.warning("Could not read CVE list from %s: %s", cves_path, exc)
        return []


def cwes_in_cve_metadata(cve_id: str, cve_data_dir: Path) -> set[str]:
    """Return CWE IDs mentioned in cve_id's downloaded NVD metadata, or an
    empty set if it isn't downloaded locally."""
    metadata_path = cve_data_dir / cve_id / f"{cve_id}.json"
    if not metadata_path.exists():
        logger.warning("%s: no local metadata at %s, skipping", cve_id, metadata_path)
        return set()
    return find_cwe_ids(metadata_path.read_text(encoding="utf-8", errors="ignore"))


def move_pr(pr_dir: Path):
    parts = [p for p in pr_dir.parts]
    parts[0] = SKIPPED_DATA_ROOT
    dst_dir = Path(*parts)

    logger.info("MOVE: %s -> %s", pr_dir, dst_dir)
    dst_dir.parent.mkdir(parents=True, exist_ok=True)
    os.rename(pr_dir, dst_dir)

    pr_dir = pr_dir.parent
    if not sum(1 for item in pr_dir.iterdir()):
        pr_dir.rmdir()

        pr_dir = pr_dir.parent
        if not sum(1 for item in pr_dir.iterdir()):
            pr_dir.rmdir()


def process_pr(pr_dir: Path, cve_data_dir: Path, cwe_data_dir: Path) -> int:
    """Write cwes.json for pr_dir. Returns the number of distinct valid CWEs found."""
    mentioned = cwes_in_pr_files(pr_dir)
    via_cves: dict[str, set[str]] = {}
    for cve_id in load_pr_cves(pr_dir):
        for cwe_id in cwes_in_cve_metadata(cve_id, cve_data_dir):
            via_cves.setdefault(cwe_id, set()).add(cve_id)

    cwes_out = {}
    for cwe_id in sorted(mentioned | via_cves.keys()):
        if not is_valid_cwe(cwe_id, cwe_data_dir):
            logger.debug("%s: dropping %s, no metadata in %s", pr_dir, cwe_id, cwe_data_dir)
            continue
        cwes_out[cwe_id] = {"mentioned": cwe_id in mentioned, "via_cves": sorted(via_cves.get(cwe_id, ()))}
    (pr_dir / "cwes.json").write_text(json.dumps(cwes_out, indent=2), encoding="utf-8")

    if not cwes_out:
        logger.warning("No valid CWEs found for PR: %s", pr_dir)
        move_pr(pr_dir)

    return len(cwes_out)


def main(argv=None):
    global SKIPPED_DATA_ROOT

    parser = argparse.ArgumentParser(description="Find CWE mentions in each mined PR and in the metadata of the CVEs it mentions.")
    parser.add_argument("--data-dir", type=Path, default=DATA_ROOT, help=f"Root directory of mined PR data (default: {DATA_ROOT}).")
    parser.add_argument("--skipped-dir", type=Path, default=SKIPPED_DATA_ROOT, help=f"Root directory of skipped/filtered data (default: {SKIPPED_DATA_ROOT}).")
    parser.add_argument("--cve-data-dir", type=Path, default=CVE_DATA_ROOT, help=f"Root directory of downloaded CVE metadata, see cve-downloader.py (default: {CVE_DATA_ROOT}).")
    parser.add_argument("--cwe-data-dir", type=Path, default=CWE_DATA_ROOT, help=f"Root directory of downloaded CWE metadata, see cwe-miner.py (default: {CWE_DATA_ROOT}).")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    args = parser.parse_args(argv)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.data_dir.exists():
        logger.error("Data directory %s does not exist", args.data_dir)
        return 1

    if not args.cwe_data_dir.exists():
        logger.error("CWE data directory %s does not exist, run cwe-miner.py first", args.cwe_data_dir)
        return 1

    SKIPPED_DATA_ROOT = Path(args.skipped_dir)

    pr_dirs = list(find_pr_dirs(args.data_dir))
    logger.info("Found %d PR directories", len(pr_dirs))

    total_cwes = 0
    for pr_dir in pr_dirs:
        n_cwes = process_pr(pr_dir, args.cve_data_dir, args.cwe_data_dir)
        logger.debug("%s: %d CWE(s)", pr_dir, n_cwes)
        total_cwes += n_cwes

    logger.info("Done. %d PRs processed, %d total CWEs.", len(pr_dirs), total_cwes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
