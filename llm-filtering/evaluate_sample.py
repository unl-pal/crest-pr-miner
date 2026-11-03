#!/usr/bin/env python3
"""Compare each model's saved PR classifications with human judgments."""

import argparse
import csv
import json
from pathlib import Path

from sklearn.metrics import classification_report


SCRIPT_DIR = Path(__file__).resolve().parent
LABELS = ["SecurityRelated", "NotSecurityRelated"]


def read_judgments(path: Path) -> dict[str, str]:
    judgments = {}
    with path.open(encoding="utf-8-sig", newline="") as source:
        for line, row in enumerate(csv.reader(source), start=1):
            if not row or not any(cell.strip() for cell in row):
                continue
            if line == 1 and [cell.strip() for cell in row[:2]] == ["PR", "Judgment"]:
                continue
            if len(row) < 2 or row[1].strip() not in LABELS:
                raise ValueError(f"{path}:{line}: expected PR and a valid human judgment")
            pr, judgment = (cell.strip() for cell in row[:2])
            parts = pr.split("/")
            if len(parts) != 3 or any(part in {"", ".", ".."} for part in parts) or not parts[2].isdigit():
                raise ValueError(f"{path}:{line}: expected PR as user/project/num")
            if pr in judgments:
                raise ValueError(f"{path}:{line}: duplicate PR {pr}")
            judgments[pr] = judgment
    if not judgments:
        raise ValueError(f"{path}: no human judgments found")
    return judgments


def evaluate_model(model_dir: Path, judgments: dict[str, str], name: str) -> None:
    human_labels = []
    model_labels = []
    mismatches = []
    for pr, judgment in judgments.items():
        response_path = model_dir / (pr.replace("/", "_") + "_response.json")
        if not response_path.is_file():
            continue
        try:
            saved = json.loads(response_path.read_text(encoding="utf-8"))
            if saved.get("PR", pr) != pr:
                raise ValueError(f"PR metadata does not match {pr}")
            response = json.loads(saved["response"])
            classification = response["classification"]
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"{response_path}: invalid response: {exc}") from exc
        human_labels.append(judgment)
        model_judgment = "SecurityRelated" if classification == "security" else "NotSecurityRelated"
        model_labels.append(model_judgment)
        if judgment != model_judgment:
            mismatches.append((pr, judgment, model_judgment, response_path))

    print(f"Model: {name}")
    print(f"Matched {len(human_labels)}/{len(judgments)} PRs; "
          f"missing {len(judgments) - len(human_labels)} responses.")
    print(f"Mismatched judgments: {len(mismatches)}")
    for pr, human_judgment, model_judgment, response_path in mismatches:
        print(f"  PR: {pr}")
        print(f"    Human: {human_judgment}; Model: {model_judgment}")
        print(f"    Response file: {response_path}")
    if human_labels:
        print(classification_report(
            human_labels, model_labels, labels=LABELS, zero_division=0,
        ))
    else:
        print("No matching responses to evaluate.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--judgments", type=Path,
        default=SCRIPT_DIR.parent / "sample-judgments-human.csv",
        help="Human judgment CSV (default: repository sample-judgments-human.csv).",
    )
    parser.add_argument(
        "--responses-dir", type=Path, default=SCRIPT_DIR / "responses",
        help="Response root containing llm/model directories (default: script's responses/).",
    )
    args = parser.parse_args()
    try:
        judgments = read_judgments(args.judgments)
        if not args.responses_dir.is_dir():
            raise ValueError(f"Response directory does not exist: {args.responses_dir}")
        model_dirs = sorted(path for path in args.responses_dir.glob("*/*") if path.is_dir())
        if not model_dirs:
            raise ValueError(f"No model directories found in {args.responses_dir}")
        for model_dir in model_dirs:
            evaluate_model(model_dir, judgments, model_dir.relative_to(args.responses_dir).as_posix())
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: error: {exc}\n")


if __name__ == "__main__":
    main()
