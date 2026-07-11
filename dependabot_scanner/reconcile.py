"""Reconcile: watch dispatched sessions through to a terminal state.

Scope of mutations (per policy): creating/nudging Devin sessions, posting
session messages, applying PR labels, and filing tracking issues are all in
scope. Mutating the repo's mainline (merging PRs) is NOT -- the human-merge
gate is deliberate policy, so reconcile never merges.
"""
import json
import re

import requests

from .config import (
    GITHUB_API,
    KNOWN_STATES,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    TERMINAL_STATES,
)
from .devin import (
    format_session_log,
    get_devin_session,
    send_session_message,
    session_is_finished,
)
from .github_api import (
    _github_headers,
    ci_status,
    file_run_summary,
    get_pr_labels,
    open_tracking_issue,
    post_pr_comment,
)

_PR_URL_RE = re.compile(r"https://github\.com/([^/\s]+/[^/\s]+)/pull/(\d+)")


def discover_pr(repo, entry, session):
    """Find the fix PR for this alert. Returns (url, number, method) or (None, None, None).

    Prefer the PR URL emitted in the Devin session output; fall back to searching
    the repo's PRs for one that references the alert's GHSA id. ``method`` records
    which path matched so a wrong match can be debugged later.
    """
    # 1) Preferred: a PR URL for this repo anywhere in the session payload.
    if session is not None:
        for match in _PR_URL_RE.finditer(json.dumps(session)):
            if match.group(1).lower() == repo.lower():
                return match.group(0), int(match.group(2)), "session_output"

    # 2) Fallback: search the repo's PRs that reference the GHSA id.
    ghsa = entry.get("ghsa_id") or ""
    if ghsa:
        try:
            response = requests.get(
                f"{GITHUB_API}/search/issues",
                headers=_github_headers(),
                params={"q": f"repo:{repo} is:pr {ghsa}"},
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                items = response.json().get("items", [])
                if items:
                    pr = items[0]
                    return pr.get("html_url"), pr.get("number"), "ghsa_search"
        except requests.RequestException as exc:
            print(f"WARN  PR search failed for {ghsa} ({exc})")
    return None, None, None


def attach_session_log_to_pr(repo, entry, session, reason, dry_run):
    """Attach the failed session's log as a PR comment, once per retry attempt."""
    pr_number = entry.get("pr_number")
    if not pr_number:
        return
    # De-dupe: at most one log comment per retry count, so re-running reconcile
    # while a PR stays red does not spam identical comments.
    marker = entry.get("retries", 0)
    if entry.get("log_attached_at_retry") == marker:
        return
    log = format_session_log(session)
    if not log:
        return
    comment = (
        f"**Automated remediation log** ({reason})\n\n"
        f"Devin session: {entry.get('session_url')}\n\n"
        f"<details><summary>Session log</summary>\n\n```\n{log}\n```\n\n</details>"
    )
    if not dry_run and post_pr_comment(repo, pr_number, comment):
        entry["log_attached_at_retry"] = marker
        print(f"      attached session log to PR #{pr_number}")


def _bump_retry_or_escalate(repo, entry, label, reason, nudge, session, dry_run):
    """Move a problem entry one step: nudge the session, or escalate at the retry cap.

    If a PR exists, the failed session's log is attached to it as a comment so the
    reviewer sees why the automated fix failed.
    """
    attach_session_log_to_pr(repo, entry, session, reason, dry_run)
    retries = entry.get("retries", 0)
    if retries >= MAX_RETRIES:
        entry["status"] = "escalated"
        if not dry_run:
            issue_url = open_tracking_issue(repo, entry, format_session_log(session))
            if issue_url:
                entry["tracking_issue"] = issue_url
        print(f"ESCALATE {label}: {reason}; retries exhausted -> {entry.get('tracking_issue', 'issue not filed')}")
    else:
        entry["retries"] = retries + 1
        if not dry_run:
            send_session_message(entry.get("session_id"), nudge)
        print(f"RETRY {label}: {reason} (attempt {entry['retries']}/{MAX_RETRIES})")


def reconcile(repo, state, dry_run):
    """Advance every non-terminal state entry toward a terminal state.

    Invariant: after this pass, an entry is either in a TERMINAL_STATE, or in a
    bounded non-terminal state whose retry counter guarantees it escalates within
    MAX_RETRIES passes. No entry can loop forever.
    """
    if not state:
        print("No recorded sessions to reconcile.")
        return
    for key, entry in state.items():
        entry.setdefault("status", "dispatched")
        label = f"[{entry.get('severity')}] {entry.get('package')} ({entry.get('ghsa_id')})"

        if entry["status"] in TERMINAL_STATES:
            print(f"DONE  {label}: {entry['status']} (terminal)")
            continue

        session = get_devin_session(entry.get("session_id"))
        pr_url, pr_number, method = discover_pr(repo, entry, session)

        if pr_url:
            entry["pr_url"] = pr_url
            entry["pr_number"] = pr_number
            entry["pr_discovery_method"] = method
            entry["pr_labels"] = sorted(get_pr_labels(repo, pr_number))
            ci = ci_status(repo, pr_number)
            entry["ci"] = ci
            if ci == "success":
                entry["status"] = "verified"
                print(f"VERIFY {label}: PR {pr_url} green (via {method})")
            elif ci == "failure":
                _bump_retry_or_escalate(
                    repo, entry, label, f"CI failing on {pr_url}",
                    nudge=(f"CI is failing on your PR {pr_url} for {entry.get('ghsa_id')}. "
                           "Please investigate the failing checks and push fixes."),
                    session=session, dry_run=dry_run,
                )
            else:
                entry["status"] = "pr_open"
                print(f"WAIT  {label}: PR {pr_url} CI {ci} (via {method})")
        elif session_is_finished(session):
            entry["status"] = "no_pr_stalled"
            _bump_retry_or_escalate(
                repo, entry, label, "session finished without opening a PR",
                nudge=(f"Your session for {entry.get('ghsa_id')} appears finished but no PR was "
                       f"found in {repo}. Please open the fix PR (or explain the blocker)."),
                session=session, dry_run=dry_run,
            )
        else:
            entry["status"] = "dispatched"
            print(f"WORK  {label}: session still in progress, no PR yet")

    # Loop-closure invariant: every entry must be in a known state.
    assert all(e.get("status") in KNOWN_STATES for e in state.values()), \
        "reconcile left an entry in an unknown state"

    counts = {}
    for e in state.values():
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    print("Reconcile summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    details = [
        f"- `{e.get('status')}` {e.get('package')} ({e.get('ghsa_id')})"
        + (f" → {e.get('pr_url')}" if e.get("pr_url") else "")
        for e in state.values()
    ]
    file_run_summary(repo, "reconcile", counts, details, dry_run)
