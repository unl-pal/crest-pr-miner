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
    comments.json         PR review comments as a JSON array (only with --comments)
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from github import Auth, Github, RateLimitExceededException, GithubException

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
            {"token": t, "client": Github(auth=Auth.Token(t), user_agent="CREST-PR-Miner/1.0.0 (https://github.com/unl-pal/crest-pr-miner)"), "reset_at": None} for t in tokens
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
    if not any(not (p.login.endswith("[bot]") or getattr(p, "type", "") == "Bot") for p in participants):
        return False

    return True


# ---------------------------------------------------------------------------
# Download functions
# ---------------------------------------------------------------------------
def download_pr(pool: TokenPool, repo_full_name: str, pr, pr_dir: Path):
    """Download PR JSON and diff into pr_dir."""
    pr_dir.mkdir(parents=True, exist_ok=True)
    pr_id = pr.number

    json_path = pr_dir / f"{pr_id}.json"
    diff_path = pr_dir / f"{pr_id}.diff"

    if not json_path.exists():
        json_path.write_text(json.dumps(pr.raw_data, indent=2, ensure_ascii=False), encoding="utf-8")
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
        review_path.write_text(json.dumps(review.raw_data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Saved %s", review_path)


def download_comments(pool: TokenPool, pr, pr_dir: Path):
    """Download all review comments for a PR into a single comments.json file."""
    comments_path = pr_dir / "comments.json"
    if comments_path.exists():
        return
    pr_dir.mkdir(parents=True, exist_ok=True)
    while True:
        client = pool.get()
        try:
            comments = list(pr.get_review_comments())
            break
        except RateLimitExceededException:
            pool.mark_rate_limited(client)

    comments_path.write_text(
        json.dumps([c.raw_data for c in comments], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Saved %s (%d comments)", comments_path, len(comments))


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
        if json_path.name == "comments.json" or json_path.parent.name == "reviews":
            continue
        pr_dir = json_path.parent
        if (pr_dir / "comments.json").exists():
            continue
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
            download_comments(pool, pr, pr_dir)
        except GithubException as exc:
            logger.warning("Could not fetch PR %s#%s: %s", repo_full_name, pr_number, exc)


# ---------------------------------------------------------------------------
# Search-based scraping (no explicit repos given)
# ---------------------------------------------------------------------------
def scrape_via_search(pool: TokenPool, args):
    """Use the GitHub search API to find PRs matching the configured filters."""
    # Build search query
    query_parts = ["is:pr"]

    # Keyword filter: search for any keyword in the title/body
    keyword_clause = " OR ".join(f'"{kw}"' for kw in args.keywords)
    query_parts.append(f"({keyword_clause})")

    # Date filter
    if args.opened_before:
        date_str = args.opened_before.strftime("%Y-%m-%d")
        query_parts.append(f"created:<={date_str}")

    # Language filter: issue a separate search per language (the GitHub search
    # API does not support OR for the language: qualifier) and merge results
    # by (repo, pr_number) to avoid duplicates.
    languages_to_search = sorted(args.languages) if args.languages else [None]

    seen: set[tuple[str, int]] = set()

    for lang in languages_to_search:
        parts = list(query_parts)
        if lang is not None:
            parts.append(f"language:{lang}")
        query = " ".join(parts)
        logger.info("Searching GitHub with query: %s", query)

        def _search(client, q):
            return client.search_issues(query=q, sort="created", order="desc")

        try:
            results = _call_with_retry(pool, _search, query)
        except GithubException as exc:
            logger.error("Search failed: %s", exc)
            continue

        for issue in results:
            if issue.pull_request is None:
                continue

            repo_full_name = issue.repository.full_name
            owner, _, repo_name = repo_full_name.partition("/")
            pr_number = issue.number

            key = (repo_full_name, pr_number)
            if key in seen:
                continue
            seen.add(key)

            pr_dir = DATA_ROOT / owner / repo_name / str(pr_number)
            json_path = pr_dir / f"{pr_number}.json"

            if not json_path.exists():
                try:
                    def _get_pr(client, rfn, pn):
                        return client.get_repo(rfn).get_pull(pn)
                    pr = _call_with_retry(pool, _get_pr, repo_full_name, pr_number)
                except GithubException as exc:
                    logger.warning("Could not fetch %s#%s: %s", repo_full_name, pr_number, exc)
                    continue

                if not _pr_matches(pr, args):
                    continue

                download_pr(pool, repo_full_name, pr, pr_dir)
            else:
                logger.debug("PR %s#%s already downloaded, skipping", repo_full_name, pr_number)
                try:
                    def _get_pr(client, rfn, pn):
                        return client.get_repo(rfn).get_pull(pn)
                    pr = _call_with_retry(pool, _get_pr, repo_full_name, pr_number)
                except GithubException as exc:
                    logger.warning("Could not fetch %s#%s: %s", repo_full_name, pr_number, exc)
                    continue

            if args.reviews:
                reviews_dir = pr_dir / "reviews"
                if not reviews_dir.exists():
                    download_reviews(pool, pr, reviews_dir)

            if args.comments:
                download_comments(pool, pr, pr_dir)


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
                download_comments(pool, pr, pr_dir)


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

    # Validate token format: must start with "ghp_" followed by 36 alphanumeric chars
    _token_re = re.compile(r'^ghp_[A-Za-z0-9]{36}$')
    invalid = [t for t in tokens if not _token_re.match(t)]
    if invalid:
        logger.error(
            "Invalid GitHub token(s) detected (expected ghp_ + 36 alphanumeric chars): %s",
            ", ".join(invalid),
        )
        sys.exit(1)

    pool = TokenPool(tokens)

    if not args.repos:
        if args.reviews or args.comments:
            # Backfill-only mode: walk existing data
            if args.reviews:
                backfill_reviews(pool, args)
            if args.comments:
                backfill_comments(pool, args)
        else:
            # No repos and no backfill flags: use GitHub search API
            scrape_via_search(pool, args)
    else:
        scrape_repos(pool, args.repos, args)


if __name__ == "__main__":
    main()
