#!/usr/bin/env python3
"""
Filters mined PRs to remove ones possibly not fixing vulnerabilities.

This is done by looking at the diff to see if at least one source file was modified.
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


def find_pr_dirs(data_dir: Path):
    """Yield every mined PR directory under data_dir (data/<owner>/<repo>/<pr_id>)."""
    for owner_dir in sorted(p for p in data_dir.iterdir() if p.is_dir()):
        for repo_dir in sorted(p for p in owner_dir.iterdir() if p.is_dir()):
            for pr_dir in sorted(p for p in repo_dir.iterdir() if p.is_dir()):
                yield pr_dir


def move_pr(pr_dir: Path, args):
    parts = [p for p in pr_dir.parts]
    parts[0] = SKIPPED_DATA_ROOT
    dst_dir = Path(*parts)

    logger.info("MOVE: %s -> %s", pr_dir, dst_dir)
    if not args.dry_run:
        dst_dir.parent.mkdir(parents=True, exist_ok=True)
        os.rename(pr_dir, dst_dir)

        pr_dir = pr_dir.parent
        if not sum(1 for item in pr_dir.iterdir()):
            pr_dir.rmdir()

            pr_dir = pr_dir.parent
            if not sum(1 for item in pr_dir.iterdir()):
                pr_dir.rmdir()


def process_pr(pr_dir: Path, args):
    """Tests if this PR needs to be filtered and moved to the skipped directory."""
    pr_num = pr_dir.name
    diff = pr_dir / (pr_num + ".diff")

    if not diff.exists():
        logger.warning("PR is missing diff: %s", pr_dir)
        move_pr(pr_dir, args)
        return "nodiff"

    with open(diff, 'r', encoding='utf-8', errors='ignore') as f:
        try:
            diff_data = f.readlines()
        except KeyboardInterrupt as e:
            raise e
        except:
            # ignore errors, just filter it
            diff_data = []

    diff_data = [l.strip() for l in diff_data if l.startswith('diff --git a/')]
    has_source = False
    for l in diff_data:
        if l.split('.')[-1] in ['java', 'py', 'c', 'h', 'cpp', 'hpp', 'sql']:
            has_source = True

    diff2 = [l for l in diff_data if '/test/' in l or '/tests/' in l]
    if len(diff2) == len(diff_data):
        logger.warning("PR diff contains only test files: %s", pr_dir)
        move_pr(pr_dir, args)
        return "test"
    if has_source:
        return None

    logger.warning("PR has no source files: %s", diff_data)
    move_pr(pr_dir, args)

    return "nosource"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filters mined pull requests.")
    parser.add_argument("--data-dir", type=Path, default=DATA_ROOT, help=f"Root directory of mined PR data (default: {DATA_ROOT}).")
    parser.add_argument("--skipped-dir", type=Path, default=SKIPPED_DATA_ROOT, help=f"Root directory of skipped/filtered data (default: {SKIPPED_DATA_ROOT}).")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually move any files.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    args = parser.parse_args(sys.argv[1:])

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.data_dir.exists():
        logger.error("Data directory %s does not exist", args.data_dir)
        sys.exit(1)

    SKIPPED_DATA_ROOT = Path(args.skipped_dir)

    pr_dirs = list(find_pr_dirs(args.data_dir))
    logger.info("Found %d PR directories", len(pr_dirs))

    bad = 0
    moved = 0
    tests = 0
    for pr_dir in pr_dirs:
        res = process_pr(pr_dir, args)
        if res == "nodiff":
            bad += 1
        elif res == "nosource":
            moved += 1
        elif res == "test":
            tests += 1

    logger.info("Done. %d PRs processed. Missing diff: %s. Filtered: %s. Only Tests: %s.", len(pr_dirs), bad, moved, tests)
