#!/usr/bin/env python3
"""Symlink PRs with a security judgment into a filtered dataset."""

import argparse
import json
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent


def security_prs(responses_dir: Path) -> set[Path]:
    if not responses_dir.is_dir():
        raise ValueError(f"Response directory does not exist: {responses_dir}")
    response_files = sorted(responses_dir.rglob("*_response.json"))
    if not response_files:
        raise ValueError(f"No response files found in {responses_dir}")
    selected = set()
    for path in response_files:
        saved = json.loads(path.read_text(encoding="utf-8"))
        if '"classification":"security"' not in saved["response"]:
            if '"classification":"not_security"' not in saved["response"]:
                if '"classification":"uncertain"' not in saved["response"]:
                    try:
                        response = json.loads(saved["response"])
                        classification = response["classification"]
                        print('failed:', classification, path)
                    except:
                        print('bad json', path)
            continue
        parts = saved["PR"].split("/")
        if (len(parts) != 3 or any(part in {"", ".", ".."} for part in parts)
                or not parts[2].isdigit()):
            raise ValueError("expected PR as owner/project/number")
        selected.add(Path(*parts))
    return selected


def build_dataset(responses_dir: Path, source_dir: Path, output_dir: Path) -> None:
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    if not source_dir.is_dir():
        raise ValueError(f"Source directory does not exist: {source_dir}")
    if output_dir == source_dir or source_dir in output_dir.parents or output_dir in source_dir.parents:
        raise ValueError("Source and output directories must not overlap")
    selected = security_prs(responses_dir)
    # Validate all selected PRs before creating any links.
    for pr in sorted(selected):
        source = source_dir / pr
        destination = output_dir / pr
        if not source.is_dir():
            raise ValueError(f"PR directory does not exist: {source}")
        if destination.is_symlink() and destination.resolve() == source.resolve():
            continue
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"Output path already exists: {destination}")
    output_dir.mkdir(parents=True, exist_ok=True)
    created = 0
    for pr in sorted(selected):
        destination = output_dir / pr
        if destination.is_symlink():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(source_dir / pr, target_is_directory=True)
        created += 1
    print(f"Selected {len(selected)} security PRs; created {created} symlinks in {output_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, default=Path("data"),
                        help="Output directory (default: data).")
    parser.add_argument("--responses-dir", type=Path, default=SCRIPT_DIR / "responses",
                        help="Responses to search recursively; may select one model's folder.")
    parser.add_argument("--source-dir", type=Path, default=SCRIPT_DIR.parent / "data",
                        help="Original PR dataset (default: ../data beside this script).")
    args = parser.parse_args()
    try:
        build_dataset(args.responses_dir, args.source_dir, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: error: {exc}\n")


if __name__ == "__main__":
    main()
