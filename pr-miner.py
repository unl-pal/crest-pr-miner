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
        comments.json     Review comments as a JSON array (only with --reviews)
        <review_id>.json  Review objects (only with --reviews)
    comments.json         PR review comments as a JSON array (only with --comments)
    timeline.json         PR issue timeline as a JSON array (only with --timeline)
    commits/
        <sha>.json        Commit metadata (only with --commits)
        <sha>.diff        Commit diff (only with --commits)
"""

import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.request

from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from github import Auth, Github, RateLimitExceededException, GithubException
from pathlib import Path


load_dotenv()

log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
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
    """Round-robin token pool that respects per-token rate-limit resets.

    GitHub exposes separate rate-limit buckets for different API categories
    (e.g. ``core`` for most REST calls and ``search`` for the search API).
    Each token entry tracks a reset time per category so that the pool
    can rotate and sleep correctly regardless of which bucket a call uses.
    """

    def __init__(self, tokens: list[str]):
        if not tokens:
            raise ValueError("At least one GitHub token is required.")
        # Each entry: {"token": str, "client": Github, "reset_at": {category: datetime|None}}
        self._pool = [
            {
                "token": t,
                "client": Github(auth=Auth.Token(t), per_page=100, user_agent="CREST-PR-Miner/1.0.0 (https://github.com/unl-pal/crest-pr-miner)"),
                "reset_at": {},
            }
            for t in tokens
        ]
        self._current = 0

    def get(self, category: str = "core") -> Github:
        """Return the next available GitHub client in round-robin order.

        Only tokens whose ``category`` rate-limit reset time has passed are
        considered available.  If all tokens are exhausted the method sleeps
        until the earliest reset and then returns that token's client.
        """
        now = datetime.now(tz=timezone.utc)
        n = len(self._pool)

        # Try each token starting from _current, wrapping around.
        for i in range(n):
            entry = self._pool[(self._current + i) % n]
            ra = entry["reset_at"].get(category)
            if ra is None or ra <= now:
                self._current = (self._current + i + 1) % n
                return entry["client"]

        # All tokens are rate-limited for this category; sleep until earliest reset.
        best = min(self._pool, key=lambda e: e["reset_at"].get(category, now))
        wait = (best["reset_at"][category] - now).total_seconds() + 5
        logger.warning(
            "All tokens rate-limited for '%s'; sleeping %.0f seconds until %s",
            category,
            wait,
            best["reset_at"][category].isoformat(),
        )
        time.sleep(wait)
        self._current = (self._pool.index(best) + 1) % n
        return best["client"]

    def get_token(self, client: Github) -> str | None:
        """Return the raw token string associated with a client."""
        for entry in self._pool:
            if entry["client"] is client:
                return entry["token"]
        return None

    def _fetch_reset(self, client: Github, category: str) -> datetime | None:
        """Fetch the rate-limit reset time for *category* from the API."""
        try:
            rl = client.get_rate_limit()
            resource = getattr(rl, category, None)
            if resource is not None:
                reset_ts = resource.reset
                return reset_ts.replace(tzinfo=timezone.utc)
        except Exception:
            pass
        return None

    def update_rate_limit(self, client: Github, category: str = "core"):
        """Refresh the rate-limit reset time for a client after a successful API call."""
        for entry in self._pool:
            if entry["client"] is client:
                ts = self._fetch_reset(client, category)
                if ts is not None:
                    entry["reset_at"][category] = ts
                break

    def mark_rate_limited(self, client: Github, category: str = "core"):
        """Record the reset time for a client that just hit a rate limit."""
        for entry in self._pool:
            if entry["client"] is client:
                ts = self._fetch_reset(client, category)
                if ts is None:
                    ts = datetime.now(tz=timezone.utc) + timedelta(hours=1)
                entry["reset_at"][category] = ts
                logger.info("Token rate-limited (%s); reset at %s", category, ts)
                break


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _call_with_retry(pool: TokenPool, fn, *args, category: str = "core", **kwargs):
    """Call fn(client, *args, **kwargs), rotating tokens on rate limits.

    ``category`` identifies the GitHub API rate-limit bucket the call uses
    (e.g. ``"core"`` or ``"search"``).  It is forwarded to :meth:`TokenPool.get`,
    :meth:`TokenPool.update_rate_limit`, and :meth:`TokenPool.mark_rate_limited`
    so that each bucket is tracked independently.
    """
    while True:
        client = pool.get(category)
        try:
            result = fn(client, *args, **kwargs)
            pool.update_rate_limit(client, category)
            return result
        except RateLimitExceededException:
            pool.mark_rate_limited(client, category)


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
    #if args.opened_before and pr.created_at.replace(tzinfo=timezone.utc) > args.opened_before:
    #    return False

    # Keyword filter
    #text = " ".join(filter(None, [pr.title, pr.body or ""]))
    #if not any(kw.lower() in text.lower() for kw in args.keywords):
    #    return False

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
    reviews = _call_with_retry(pool, lambda client: list(pr.get_reviews()))

    for review in reviews:
        review_path = reviews_dir / f"{review.id}.json"
        if review_path.exists():
            continue
        review_path.write_text(json.dumps(review.raw_data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Saved %s", review_path)


def download_review_comments(pool: TokenPool, pr, reviews_dir: Path):
    """Download all review comments for a PR into a single comments.json file."""
    comments_path = reviews_dir / "comments.json"
    if comments_path.exists():
        return
    reviews_dir.mkdir(parents=True, exist_ok=True)
    comments = _call_with_retry(pool, lambda client: list(pr.get_review_comments()))

    comments_path.write_text(
        json.dumps([c.raw_data for c in comments], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Saved %s (%d review comments)", comments_path, len(comments))


def download_comments(pool: TokenPool, pr, pr_dir: Path):
    """Download all comments for a PR into a single comments.json file."""
    comments_path = pr_dir / "comments.json"
    if comments_path.exists():
        return
    pr_dir.mkdir(parents=True, exist_ok=True)
    comments = _call_with_retry(pool, lambda client: list(pr.get_issue_comments()))

    comments_path.write_text(
        json.dumps([c.raw_data for c in comments], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Saved %s (%d comments)", comments_path, len(comments))


def download_timeline(pool: TokenPool, repo_full_name: str, pr_number: int, pr_dir: Path):
    """Download the issue timeline for a PR into timeline.json."""
    timeline_path = pr_dir / "timeline.json"
    if timeline_path.exists():
        return
    pr_dir.mkdir(parents=True, exist_ok=True)

    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/timeline"
    events: list = []
    page = 1
    while True:
        paged_url = f"{url}?page={page}"
        while True:
            client = pool.get()
            token = pool.get_token(client)
            req = urllib.request.Request(paged_url)
            req.add_header("Authorization", f"token {token}")
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 403:
                    pool.mark_rate_limited(client)
                else:
                    logger.warning(
                        "Timeline request failed for %s#%s (page %d): %s",
                        repo_full_name, pr_number, page, exc,
                    )
                    data = []
                    break
            except Exception as exc:
                logger.warning(
                    "Timeline request failed for %s#%s (page %d): %s",
                    repo_full_name, pr_number, page, exc,
                )
                data = []
                break

        if not data:
            break
        events.extend(data)
        if len(data) < 100:
            break
        page += 1

    timeline_path.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Saved %s (%d events)", timeline_path, len(events))


def download_commits(pool: TokenPool, pr, pr_dir: Path):
    """Download commit metadata and diffs for a PR into a commits/ subdirectory."""
    commits_dir = pr_dir / "commits"
    commits_dir.mkdir(parents=True, exist_ok=True)
    commits = _call_with_retry(pool, lambda client: list(pr.get_commits()))

    for commit in commits:
        sha = commit.sha
        json_path = commits_dir / f"{sha}.json"
        diff_path = commits_dir / f"{sha}.diff"

        if not json_path.exists():
            json_path.write_text(
                json.dumps(commit.raw_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("Saved %s", json_path)

        if not diff_path.exists():
            diff_url = f"https://github.com/{pr.base.repo.full_name}/commit/{sha}.diff"
            try:
                req = urllib.request.Request(diff_url)
                client = pool.get()
                token = pool.get_token(client)
                if token:
                    req.add_header("Authorization", f"token {token}")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    diff_path.write_bytes(resp.read())
                logger.info("Saved %s", diff_path)
            except Exception as exc:
                logger.warning("Could not download diff for commit %s: %s", sha, exc)


# ---------------------------------------------------------------------------
# Backfill reviews / comments from existing JSON files
# ---------------------------------------------------------------------------
def backfill_reviews(pool: TokenPool, args):
    """Walk existing PR JSON files and download missing reviews."""
    for pr_dir, repo_full_name, pr_number in _iter_pr_dirs():
        reviews_dir = pr_dir / "reviews"
        if reviews_dir.exists():
            continue
        logger.info("Backfilling reviews for %s PR #%s", repo_full_name, pr_number)
        try:
            def _get_pr(client, rfn, pn):
                return client.get_repo(rfn).get_pull(pn)
            pr = _call_with_retry(pool, _get_pr, repo_full_name, pr_number)
            download_reviews(pool, pr, reviews_dir)
            download_review_comments(pool, pr, reviews_dir)
        except GithubException as exc:
            logger.warning("Could not fetch PR %s#%s: %s", repo_full_name, pr_number, exc)


def backfill_comments(pool: TokenPool, args):
    """Walk existing PR JSON files and download missing review comments."""
    for pr_dir, repo_full_name, pr_number in _iter_pr_dirs():
        if (pr_dir / "comments.json").exists():
            continue
        logger.info("Backfilling comments for %s PR #%s", repo_full_name, pr_number)
        try:
            def _get_pr(client, rfn, pn):
                return client.get_repo(rfn).get_pull(pn)
            pr = _call_with_retry(pool, _get_pr, repo_full_name, pr_number)
            download_comments(pool, pr, pr_dir)
        except GithubException as exc:
            logger.warning("Could not fetch PR %s#%s: %s", repo_full_name, pr_number, exc)


def _iter_pr_dirs():
    """Yield (pr_dir, repo_full_name, pr_number) for all previously mined PRs."""
    for json_path in sorted(DATA_ROOT.rglob("*.json")):
        if json_path.name in ("comments.json", "timeline.json"):
            continue
        if json_path.parent.name in ("reviews", "commits"):
            continue
        pr_dir = json_path.parent
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
        yield pr_dir, repo_full_name, pr_number


def backfill_timeline(pool: TokenPool, args):
    """Walk existing PR JSON files and download missing timeline data."""
    for pr_dir, repo_full_name, pr_number in _iter_pr_dirs():
        if (pr_dir / "timeline.json").exists():
            continue
        logger.info("Backfilling timeline for %s PR #%s", repo_full_name, pr_number)
        download_timeline(pool, repo_full_name, pr_number, pr_dir)


def backfill_commits(pool: TokenPool, args):
    """Walk existing PR JSON files and download missing commit data."""
    for pr_dir, repo_full_name, pr_number in _iter_pr_dirs():
        commits_dir = pr_dir / "commits"
        if commits_dir.exists():
            continue
        logger.info("Backfilling commits for %s PR #%s", repo_full_name, pr_number)
        try:
            def _get_pr(client, rfn, pn):
                return client.get_repo(rfn).get_pull(pn)
            pr = _call_with_retry(pool, _get_pr, repo_full_name, pr_number)
            download_commits(pool, pr, pr_dir)
        except GithubException as exc:
            logger.warning("Could not fetch PR %s#%s: %s", repo_full_name, pr_number, exc)


# ---------------------------------------------------------------------------
# Search-based scraping (no explicit repos given)
# ---------------------------------------------------------------------------
def _get_pr(client, rfn, pn):
    return client.get_repo(rfn).get_pull(pn)


def _scrape_search_page(pool: TokenPool, args, query: str, seen: set) -> tuple[int, datetime | None]:
    """Execute one search query, process all results, and return (total_count, oldest_created_at).

    ``seen`` is mutated in place to record (repo_full_name, pr_number) pairs that have
    already been processed, so that overlapping results from subsequent date-windowed
    queries are skipped automatically.

    Returns the ``total_count`` reported by the API and the creation date of the oldest
    result seen in this page (or ``None`` if no results were returned).
    """
    def _search(client, q):
        results = client.search_issues(query=q, sort="created", order="desc")
        # Work around a PyGithub bug where totalCount is capped at 1000.
        # Fetching the first page forces the underlying HTTP response to be
        # parsed, after which totalCount reflects the real value from the JSON
        # 'total_count' field.
        results.get_page(0)
        return results

    try:
        results = _call_with_retry(pool, _search, query, category="search")
    except GithubException as exc:
        logger.error("Search failed: %s", exc)
        return 0, None

    total_count = results.totalCount
    oldest_created_at: datetime | None = None

    for issue in results:
        if issue.pull_request is None:
            continue

        repo_full_name = issue.repository.full_name
        owner, _, repo_name = repo_full_name.partition("/")
        pr_number = issue.number

        # Track the oldest creation date we see so we can narrow the next window.
        issue_created = issue.created_at
        if issue_created is not None:
            if issue_created.tzinfo is None:
                issue_created = issue_created.replace(tzinfo=timezone.utc)
            if oldest_created_at is None or issue_created < oldest_created_at:
                oldest_created_at = issue_created

        key = (repo_full_name, pr_number)
        if key in seen:
            continue
        seen.add(key)

        pr_dir = DATA_ROOT / owner / repo_name / str(pr_number)
        json_path = pr_dir / f"{pr_number}.json"

        if not json_path.exists():
            try:
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

    return total_count, oldest_created_at


def _get_time_window(pool: TokenPool, base_query: str) -> tuple[datetime | None, datetime | None]:
    """Return (earliest_created_at, latest_created_at) for a search query.

    Issues two lightweight single-item requests to discover the full time span
    of matching results, which is used to initialise the windowed pagination
    loop in :func:`scrape_via_search`.
    """
    def _search_one(client, q, order):
        client.requester.per_page = 1
        results = client.search_issues(query=q, sort="created", order=order)
        page = results.get_page(0)
        client.requester.per_page = 100
        return page[0] if page else None

    latest_issue = None
    earliest_issue = None
    try:
        latest_issue = _call_with_retry(pool, _search_one, base_query, "desc", category="search")
        earliest_issue = _call_with_retry(pool, _search_one, base_query, "asc", category="search")
    except GithubException as exc:
        logger.error("Could not determine time window: %s", exc)

    def _ts(issue) -> datetime | None:
        if issue is None:
            return None
        ts = issue.created_at
        if ts is not None and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts

    return _ts(earliest_issue), _ts(latest_issue)


def scrape_via_search(pool: TokenPool, args):
    """Use the GitHub search API to find PRs matching the configured filters.

    The GitHub search API caps results at 1 000 items per query.  To work
    around this limit the function determines the full creation-date window of
    matching results with two lightweight probe requests, then issues repeated
    searches using a ``created:EARLIEST..WINDOW_END`` range.  After each batch
    the window end is moved back to the oldest timestamp seen in that batch,
    progressively narrowing the window until all results have been collected.
    Overlapping results between batches are skipped via the ``seen`` set.
    """
    # Build base search query (no date filter yet — that is added per window)
    query_parts = ["is:pr"]

    # Keyword filter: search for any keyword in the title/body
    keyword_clause = " OR ".join(f'"{kw}"' for kw in args.keywords)
    query_parts.append(f"({keyword_clause})")

    # Language filter: issue a separate search per language (the GitHub search
    # API does not support OR for the language: qualifier) and merge results
    # by (repo, pr_number) to avoid duplicates.
    languages_to_search = sorted(args.languages) if args.languages else [None]

    seen: set[tuple[str, int]] = set()

    for lang in languages_to_search:
        base_parts = list(query_parts)
        if lang is not None:
            base_parts.append(f"language:{lang}")

        # Apply the opened_before ceiling to the probe query so we discover the
        # window only within the requested date range.
        probe_parts = list(base_parts)
        if args.opened_before:
            probe_parts.append(f"created:<={args.opened_before.strftime('%Y-%m-%d')}")
        probe_query = " ".join(probe_parts)

        logger.info("Determining time window for query: %s", probe_query)
        earliest_ts, latest_ts = _get_time_window(pool, probe_query)

        if earliest_ts is None or latest_ts is None:
            logger.warning("Could not determine time window for language=%s; skipping.", lang)
            continue

        logger.info(
            "Time window for language=%s: %s .. %s",
            lang,
            earliest_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            latest_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        # Format helpers
        def _fmt(dt: datetime) -> str:
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # --- Paginated search loop ---
        # Each iteration issues one search query covering earliest_ts..window_end.
        # After each batch the window_end is set to the oldest timestamp seen,
        # progressively narrowing the window toward the past.
        window_end: datetime = latest_ts
        expected_total: int | None = None
        seen_before_lang = len(seen)

        while True:
            range_filter = f"created:{_fmt(earliest_ts)}..{_fmt(window_end)}"
            parts = [p for p in base_parts if not p.startswith("created:")] + [range_filter]
            query = " ".join(parts)

            processed = len(seen) - seen_before_lang
            logger.info(
                "Searching GitHub with query: %s (processed so far: %d / %s)",
                query,
                processed,
                str(expected_total) if expected_total is not None else "?",
            )

            total_count, oldest_created_at = _scrape_search_page(pool, args, query, seen)

            if expected_total is None:
                expected_total = total_count
                logger.info("Total results reported by API: %d", expected_total)

            processed = len(seen) - seen_before_lang
            logger.info("Processed %d / %d unique results so far", processed, expected_total)

            # Stop if the API returned nothing useful.
            if oldest_created_at is None:
                logger.info("No results returned; stopping search for language=%s", lang)
                break

            # Stop if we have accounted for (at least) the expected total.
            if processed >= expected_total:
                logger.info(
                    "Collected %d results, meeting expected total of %d; done.",
                    processed,
                    expected_total,
                )
                break

            # Narrow the window: move window_end back to the oldest timestamp seen.
            if oldest_created_at >= window_end:
                # No progress; avoid an infinite loop.
                logger.info(
                    "Window end unchanged (%s); cannot make further progress. "
                    "Stopping search for language=%s.",
                    _fmt(window_end),
                    lang,
                )
                break
            window_end = oldest_created_at


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
             "--reviews, --comments, --timeline, or --commits is used alone to backfill existing data.",
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
    mode_group.add_argument(
        "--timeline",
        action="store_true",
        help="Backfill PR issue timeline data (stored as timeline.json).",
    )
    mode_group.add_argument(
        "--commits",
        action="store_true",
        help="Backfill PR commit metadata and diffs (stored in commits/).",
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
        if args.reviews or args.comments or args.timeline or args.commits:
            # Backfill-only mode: walk existing data
            if args.reviews:
                backfill_reviews(pool, args)
            if args.comments:
                backfill_comments(pool, args)
            if args.timeline:
                backfill_timeline(pool, args)
            if args.commits:
                backfill_commits(pool, args)
        else:
            # No repos and no backfill flags: use GitHub search API
            scrape_via_search(pool, args)
    else:
        scrape_repos(pool, args.repos, args)


if __name__ == "__main__":
    main()
