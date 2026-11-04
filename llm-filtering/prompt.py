#!/usr/bin/env python3
"""Build and print an LLM filtering prompt from locally mined PR data."""

import argparse
import json
import re
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"


def pr_reference(value: str) -> str:
    """Validate an owner/repository/number reference without allowing paths."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/[0-9]+", value):
        raise argparse.ArgumentTypeError("expected user/project/num")
    owner, project, number = value.split("/")
    if project in {".", ".."} or int(number) < 1:
        raise argparse.ArgumentTypeError("expected user/project/num with a positive PR number")
    return value


def read_json(path: Path):
    """Load JSON, retaining the filename in any parse error."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def optional_json(path: Path):
    """Represent unavailable optional data explicitly as null."""
    return read_json(path) if path.exists() else None


# also strips anything ending in "_url"
stripped_keys = [
    '_links',
    'url',
    'gravatar_id',
    'user_view_type',
    'site_admin',
    'node_id',
    'head',
    'base',
    'reactions',
    'additions',
    'deletions',
    'changed_files',
    'maintainer_can_modify',
    'review_comments',
    'pull_request_review_id',
    'commit_id',
    'original_commit_id',
]

def cleaned_json(json):
    if not json:
        return json

    if type(json) == list:
        json2 = []
        for item in json:
            json2.append(cleaned_json(item))
        return json2

    if type(json) == dict:
        json2 = {}
        for key, val in json.items():
            if not key.endswith('_url') and key not in stripped_keys:
                json2[key] = cleaned_json(val)
        return json2

    return json


def build_prompt(reference: str, data_dir: Path = DATA_DIR) -> str:
    """Fill the template with the schema and all available PR evidence."""
    pr_dir = data_dir / reference
    number = reference.rsplit("/", 1)[1]
    metadata = cleaned_json(read_json(pr_dir / f"{number}.json"))
    reviews_dir = pr_dir / "reviews"
    reviews = [
        cleaned_json(read_json(path))
        for path in sorted(reviews_dir.glob("*.json"))
        if path.name != "comments.json"
    ]
    commits = [
        read_json(path)['commit']['message'] for path in sorted((pr_dir / "commits").glob("*.json"))
    ]
    diff_path = pr_dir / f"{number}.diff"
    diff_data = None
    if diff_path.exists():
        # Extract only file names from diff, not the actual diff content
        diff_content = diff_path.read_text(encoding="utf-8", errors="replace")
        changed_files = []
        for line in diff_content.split('\n'):
            if line.startswith('diff --git'):
                # Extract file path from "diff --git a/path/to/file b/path/to/file"
                parts = line.split()
                if len(parts) >= 4:
                    # parts[2] is "a/path", parts[3] is "b/path"
                    # Remove the "a/" and "b/" prefixes
                    file_a = parts[2][2:] if parts[2].startswith('a/') else parts[2]
                    file_b = parts[3][2:] if parts[3].startswith('b/') else parts[3]
                    # Use the "b/" version as it shows the new filename
                    if file_b not in changed_files:
                        changed_files.append(file_b)
        if changed_files:
            diff_data = "\n".join(changed_files)
    values = {
        "pr-metadata.json": json.dumps(metadata, ensure_ascii=False, indent=2),
        "pr-comments.json": json.dumps(cleaned_json(optional_json(pr_dir / "comments.json")), ensure_ascii=False, indent=2),
        "pr-review-comments.json": json.dumps({
            "reviews": reviews if reviews_dir.is_dir() else None,
            "comments": cleaned_json(optional_json(reviews_dir / "comments.json")),
        }, ensure_ascii=False, indent=2),
        "pr-commits.json": json.dumps(commits if (pr_dir / "commits").is_dir() else None, ensure_ascii=False, indent=2),
        "pr.diff": diff_data,
    }
    template = (SCRIPT_DIR / "prompt-template.md").read_text(encoding="utf-8", errors="replace")
    # Substitute once so placeholder-like text within PR content stays intact.
    return re.sub(
        r"<<([^<>]+)>>",
        lambda match: values[match.group(1)],
        template,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pr", type=pr_reference, metavar="user/project/num")
    parser.add_argument(
        "--data-dir", type=Path, default=DATA_DIR,
        help="Root directory for mined PR data (default: repository data/).",
    )
    args = parser.parse_args()
    try:
        prompt = build_prompt(args.pr, args.data_dir)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"{parser.prog}: error: {exc}\n")
    return prompt


if __name__ == "__main__":
    print(main())
