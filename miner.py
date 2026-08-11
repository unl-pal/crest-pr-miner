#!/usr/bin/env python3
"""
GitHub Pull Request Miner

Downloads GitHub PR data (JSON, diffs, reviews, comments) with automatic
token rotation when rate limits are hit.

Usage:
    python miner.py [options] <repo1> [<repo2> ...]

Environment:
    GH_TOKEN_LIST  Comma-delimited list of GitHub personal access tokens.
                   Set this in a .env file (see .env.example).

Data is stored under data/<owner>/<repo>/<pr_id>/:
    <pr_id>.json          Pull request metadata
    <pr_id>.diff          Unified diff of the PR
    reviews/
        <review_id>.json  Review objects (only with --reviews)
    comments/
        <comment_id>.json PR review comments (only with --comments)
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from github import Github, RateLimitExceededException, GithubException

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_LANGUAGES = {"Java", "C", "C++", "Python"}
DEFAULT_MIN_PARTICIPANTS = 2
DEFAULT_KEYWORDS = ["CWE-", "CVE-"]
DEFAULT_OPENED_BEFORE = datetime(2026, 8, 12, tzinfo=timezone.utc)
DATA_ROOT = Path("data")


# ---------------------------------------------------------------------------
# Token / rate-limit management
# ---------------------------------------------------------------------------
class TokenPool:
    """Round-robin token pool that respects per-token rate-limit resets."""

    def __init__(self, tokens: list[str]):
        if not tokens:
            raise ValueError("At least one GitHub token is required.")
        # Each entry: {"token": str, "client": Github, "reset_at": datetime|None}
        self._pool = [
            {"token": t, "client": Github(t), "reset_at": None} for t in tokens
        ]
        self._current = 0

    def get(self) -> Github:
        """Return the best available GitHub client, sleeping if necessary."""
        # Pick the entry whose reset_at is earliest (None counts as now)
        now = datetime.now(tz=timezone.utc)

        def reset_key(entry):
            ra = entry["reset_at"]
            return ra if ra is not None else now

        best = min(self._pool, key=reset_key)
        ra = best["reset_at"]
        if ra is not None and ra > now:
            wait = (ra - now).total_seconds() + 5
            logger.warning(
                "All tokens rate-limited; sleeping %.0f seconds until %s",
                wait,
                ra.isoformat(),
            )
            time.sleep(wait)
        return best["client"]

    def get_token(self, client: Github) -> str | None:
        """Return the raw token string associated with a client."""
        for entry in self._pool:
            if entry["client"] is client:
                return entry["token"]
        return None

    def mark_rate_limited(self, client: Github):
        """Record the reset time for a client that just hit a rate limit."""
        for entry in self._pool:
            if entry["client"] is client:
                try:
                    reset_ts = client.get_rate_limit().core.reset
                    entry["reset_at"] = reset_ts.replace(tzinfo=timezone.utc)
                except Exception:
                    entry["reset_at"] = datetime.now(tz=timezone.utc) + timedelta(hours=1)
                logger.info("Token rate-limited; reset at %s", entry["reset_at"])
                break


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _call_with_retry(pool: TokenPool, fn, *args, **kwargs):
    """Call fn(client, *args, **kwargs), rotating tokens on rate limits."""
    while True:
        client = pool.get()
        try:
            return fn(client, *args, **kwargs)
        except RateLimitExceededException:
            pool.mark_rate_limited(client)


def _participants(pr) -> list:
    """Return unique non-None participants for a PR."""
    seen: set[str] = set()
    people = []
    for user in [pr.user, pr.merged_by]:
        if user and user.login not in seen:
            seen.add(user.login)
            people.append(user)
    try:
        for review in pr.get_reviews():
            if review.user and review.user.login not in seen:
                seen.add(review.user.login)
                people.append(review.user)
    except GithubException:
        pass
    try:
        for comment in pr.get_issue_comments():
            if comment.user and comment.user.login not in seen:
                seen.add(comment.user.login)
                people.append(comment.user)
    except GithubException:
        pass
    return people


def _pr_matches(pr, args) -> bool:
    """Return True if pr passes all configured filters."""
    # Date filter
    if args.opened_before and pr.created_at.replace(tzinfo=timezone.utc) > args.opened_before:
        return False

    # Keyword filter
    text = " ".join(filter(None, [pr.title, pr.body or ""]))
    if not any(kw.lower() in text.lower() for kw in args.keywords):
        return False

    # Participant filters
    participants = _participants(pr)
    if len(participants) < args.min_participants:
        return False
    if not any(not (p.login.endswith("[bot]") or getattr(p, "type", "") == "Bot")
               for p in participants):
        return False

    return True


# ---------------------------------------------------------------------------
# Download functions
# ---------------------------------------------------------------------------
def _pr_to_dict(pr) -> dict:
    """Serialize a PullRequest object to a plain dict (JSON-serialisable)."""
    def _user(u):
        if u is None:
            return None
        return {"login": u.login, "id": u.id, "type": getattr(u, "type", None)}

    def _label(lb):
        return {"name": lb.name, "color": lb.color}

    return {
        "id": pr.id,
        "number": pr.number,
        "state": pr.state,
        "title": pr.title,
        "body": pr.body,
        "html_url": pr.html_url,
        "diff_url": pr.diff_url,
        "patch_url": pr.patch_url,
        "created_at": pr.created_at.isoformat() if pr.created_at else None,
        "updated_at": pr.updated_at.isoformat() if pr.updated_at else None,
        "closed_at": pr.closed_at.isoformat() if pr.closed_at else None,
        "merged_at": pr.merged_at.isoformat() if pr.merged_at else None,
        "merge_commit_sha": pr.merge_commit_sha,
        "user": _user(pr.user),
        "merged_by": _user(pr.merged_by),
        "assignees": [_user(a) for a in pr.assignees],
        "labels": [_label(lb) for lb in pr.labels],
        "draft": pr.draft,
        "merged": pr.merged,
        "mergeable": pr.mergeable,
        "additions": pr.additions,
        "deletions": pr.deletions,
        "changed_files": pr.changed_files,
        "comments": pr.comments,
        "review_comments": pr.review_comments,
        "commits": pr.commits,
        "head": {
            "sha": pr.head.sha,
            "ref": pr.head.ref,
            "label": pr.head.label,
        },
        "base": {
            "sha": pr.base.sha,
            "ref": pr.base.ref,
            "label": pr.base.label,
        },
    }


def download_pr(pool: TokenPool, repo_full_name: str, pr, pr_dir: Path):
    """Download PR JSON and diff into pr_dir."""
    pr_dir.mkdir(parents=True, exist_ok=True)
    pr_id = pr.number

    json_path = pr_dir / f"{pr_id}.json"
    diff_path = pr_dir / f"{pr_id}.diff"

    if not json_path.exists():
        data = _pr_to_dict(pr)
        json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Saved %s", json_path)

    if not diff_path.exists():
        import urllib.request

        diff_url = pr.diff_url
        try:
            req = urllib.request.Request(diff_url)
            # Add auth if token available (avoids anonymous rate limits)
            client = pool.get()
            token = pool.get_token(client)
            if token:
                req.add_header("Authorization", f"token {token}")
            with urllib.request.urlopen(req, timeout=30) as resp:
                diff_path.write_bytes(resp.read())
            logger.info("Saved %s", diff_path)
        except Exception as exc:
            logger.warning("Could not download diff for PR %s: %s", pr_id, exc)


def download_reviews(pool: TokenPool, pr, reviews_dir: Path):
    """Download all reviews for a PR into reviews_dir."""
    reviews_dir.mkdir(parents=True, exist_ok=True)
    while True:
        client = pool.get()
        try:
            reviews = list(pr.get_reviews())
            break
        except RateLimitExceededException:
            pool.mark_rate_limited(client)

    for review in reviews:
        review_path = reviews_dir / f"{review.id}.json"
        if review_path.exists():
            continue
        data = {
            "id": review.id,
            "user": {"login": review.user.login, "id": review.user.id} if review.user else None,
            "body": review.body,
            "state": review.state,
            "submitted_at": review.submitted_at.isoformat() if review.submitted_at else None,
            "commit_id": review.commit_id,
            "html_url": review.html_url,
        }
        review_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Saved %s", review_path)


def download_comments(pool: TokenPool, pr, comments_dir: Path):
    """Download all review comments for a PR into comments_dir."""
    comments_dir.mkdir(parents=True, exist_ok=True)
    while True:
        client = pool.get()
        try:
            comments = list(pr.get_comments())
            break
        except RateLimitExceededException:
            pool.mark_rate_limited(client)

    for comment in comments:
        comment_path = comments_dir / f"{comment.id}.json"
        if comment_path.exists():
            continue
        data = {
            "id": comment.id,
            "user": {"login": comment.user.login, "id": comment.user.id} if comment.user else None,
            "body": comment.body,
            "created_at": comment.created_at.isoformat() if comment.created_at else None,
            "updated_at": comment.updated_at.isoformat() if comment.updated_at else None,
            "html_url": comment.html_url,
            "path": comment.path,
            "position": comment.position,
            "original_position": comment.original_position,
            "commit_id": comment.commit_id,
            "original_commit_id": comment.original_commit_id,
            "diff_hunk": comment.diff_hunk,
            "pull_request_review_id": comment.pull_request_review_id,
        }
        comment_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Saved %s", comment_path)


# ---------------------------------------------------------------------------
# Backfill reviews / comments from existing JSON files
# ---------------------------------------------------------------------------
def backfill_reviews(pool: TokenPool, args):
    """Walk existing PR JSON files and download missing reviews."""
    for json_path in sorted(DATA_ROOT.rglob("*.json")):
        # Skip files already inside reviews/ or comments/
        if json_path.parent.name in ("reviews", "comments"):
            continue
        pr_dir = json_path.parent
        reviews_dir = pr_dir / "reviews"
        try:
            pr_data = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        pr_number = pr_data.get("number")
        if pr_number is None:
            continue
        # Derive repo from path: data/<owner>/<repo>/<pr_id>/
        parts = pr_dir.relative_to(DATA_ROOT).parts
        if len(parts) < 3:
            continue
        repo_full_name = f"{parts[0]}/{parts[1]}"
        logger.info("Backfilling reviews for %s PR #%s", repo_full_name, pr_number)
        try:
            def _get_pr(client, rfn, pn):
                return client.get_repo(rfn).get_pull(pn)
            pr = _call_with_retry(pool, _get_pr, repo_full_name, pr_number)
            download_reviews(pool, pr, reviews_dir)
        except GithubException as exc:
            logger.warning("Could not fetch PR %s#%s: %s", repo_full_name, pr_number, exc)


def backfill_comments(pool: TokenPool, args):
    """Walk existing PR JSON files and download missing review comments."""
    for json_path in sorted(DATA_ROOT.rglob("*.json")):
        if json_path.parent.name in ("reviews", "comments"):
            continue
        pr_dir = json_path.parent
        comments_dir = pr_dir / "comments"
        try:
            pr_data = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        pr_number = pr_data.get("number")
        if pr_number is None:
            continue
        parts = pr_dir.relative_to(DATA_ROOT).parts
        if len(parts) < 3:
            continue
        repo_full_name = f"{parts[0]}/{parts[1]}"
        logger.info("Backfilling comments for %s PR #%s", repo_full_name, pr_number)
        try:
            def _get_pr(client, rfn, pn):
                return client.get_repo(rfn).get_pull(pn)
            pr = _call_with_retry(pool, _get_pr, repo_full_name, pr_number)
            download_comments(pool, pr, comments_dir)
        except GithubException as exc:
            logger.warning("Could not fetch PR %s#%s: %s", repo_full_name, pr_number, exc)


# ---------------------------------------------------------------------------
# Main scraping loop
# ---------------------------------------------------------------------------
def scrape_repos(pool: TokenPool, repos: list[str], args):
    """Scrape PRs from a list of repositories."""
    for repo_full_name in repos:
        logger.info("Scraping repository: %s", repo_full_name)
        owner, _, repo_name = repo_full_name.partition("/")
        if not repo_name:
            logger.error("Invalid repository format '%s'; expected owner/repo", repo_full_name)
            continue

        # Check language filter
        if args.languages:
            def _get_repo(client, rfn):
                return client.get_repo(rfn)
            try:
                repo_obj = _call_with_retry(pool, _get_repo, repo_full_name)
                repo_lang = repo_obj.language or ""
                if repo_lang not in args.languages:
                    logger.info(
                        "Skipping %s (language=%s, not in %s)",
                        repo_full_name, repo_lang, args.languages,
                    )
                    continue
            except GithubException as exc:
                logger.warning("Could not fetch repo info for %s: %s", repo_full_name, exc)
                continue

        def _list_prs(client, rfn):
            return client.get_repo(rfn).get_pulls(
                state="all", sort="created", direction="desc"
            )

        try:
            pulls = _call_with_retry(pool, _list_prs, repo_full_name)
        except GithubException as exc:
            logger.warning("Could not list PRs for %s: %s", repo_full_name, exc)
            continue

        for pr in pulls:
            # Stop early if PR is too new (PRs are sorted desc by creation)
            if args.opened_before and pr.created_at.replace(tzinfo=timezone.utc) > args.opened_before:
                continue

            pr_dir = DATA_ROOT / owner / repo_name / str(pr.number)

            # Skip if already fully scraped (JSON exists)
            json_path = pr_dir / f"{pr.number}.json"
            if not json_path.exists():
                if not _pr_matches(pr, args):
                    continue
                download_pr(pool, repo_full_name, pr, pr_dir)
            else:
                logger.debug("PR %s#%s already downloaded, skipping", repo_full_name, pr.number)

            if args.reviews:
                reviews_dir = pr_dir / "reviews"
                if not reviews_dir.exists():
                    download_reviews(pool, pr, reviews_dir)

            if args.comments:
                comments_dir = pr_dir / "comments"
                if not comments_dir.exists():
                    download_comments(pool, pr, comments_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Mine GitHub pull request data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "repos",
        nargs="*",
        metavar="owner/repo",
        help="Repositories to scrape (e.g. torvalds/linux). Not required when "
             "--reviews or --comments is used alone to backfill existing data.",
    )

    # Filtering
    filter_group = parser.add_argument_group("filtering")
    filter_group.add_argument(
        "--languages",
        nargs="+",
        default=list(DEFAULT_LANGUAGES),
        metavar="LANG",
        help="Only include repos written in these languages (default: %(default)s). "
             "Pass an empty string to disable language filtering.",
    )
    filter_group.add_argument(
        "--min-participants",
        type=int,
        default=DEFAULT_MIN_PARTICIPANTS,
        dest="min_participants",
        metavar="N",
        help="Minimum number of unique participants (default: %(default)s).",
    )
    filter_group.add_argument(
        "--keywords",
        nargs="+",
        default=DEFAULT_KEYWORDS,
        metavar="KW",
        help="Keywords to search for in PR title/body (default: %(default)s).",
    )
    filter_group.add_argument(
        "--opened-before",
        default=DEFAULT_OPENED_BEFORE.isoformat(),
        dest="opened_before_str",
        metavar="ISO_DATE",
        help="Only include PRs opened before this date (default: %(default)s).",
    )
    filter_group.add_argument(
        "--no-language-filter",
        action="store_true",
        dest="no_language_filter",
        help="Disable language filtering entirely.",
    )

    # Modes
    mode_group = parser.add_argument_group("modes")
    mode_group.add_argument(
        "--reviews",
        action="store_true",
        help="Download (or backfill) PR reviews.",
    )
    mode_group.add_argument(
        "--comments",
        action="store_true",
        help="Download (or backfill) PR review comments.",
    )

    # Output
    parser.add_argument(
        "--data-dir",
        default=str(DATA_ROOT),
        dest="data_dir",
        metavar="DIR",
        help="Root directory for downloaded data (default: %(default)s).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging.",
    )

    args = parser.parse_args(argv)

    # Post-process
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Parse opened_before
    try:
        dt = datetime.fromisoformat(args.opened_before_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        args.opened_before = dt
    except ValueError as exc:
        parser.error(f"Invalid --opened-before date: {exc}")

    # Language set (empty string disables filtering)
    if args.no_language_filter or args.languages == [""]:
        args.languages = set()
    else:
        args.languages = set(args.languages)

    return args


def main(argv=None):
    args = parse_args(argv)

    global DATA_ROOT
    DATA_ROOT = Path(args.data_dir)

    # Load tokens
    raw = os.environ.get("GH_TOKEN_LIST", "")
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    if not tokens:
        logger.error(
            "No GitHub tokens found. Set GH_TOKEN_LIST in your environment or .env file."
        )
        sys.exit(1)

    pool = TokenPool(tokens)

    backfill_only = not args.repos

    if backfill_only:
        if not args.reviews and not args.comments:
            logger.error("No repositories specified and no backfill flag provided.")
            sys.exit(1)
        if args.reviews:
            backfill_reviews(pool, args)
        if args.comments:
            backfill_comments(pool, args)
    else:
        scrape_repos(pool, args.repos, args)
        # Also do backfill if flags are set
        if args.reviews:
            backfill_reviews(pool, args)
        if args.comments:
            backfill_comments(pool, args)


if __name__ == "__main__":
    main()
