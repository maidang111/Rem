"""GitHub REST client: alerts, PRs, CI status, labels, comments, and issues."""
from datetime import datetime, timezone

import requests

from .config import (
    GITHUB_API,
    GITHUB_TOKEN,
    LABEL_REVIEW,
    MAX_DISPATCH,
    REQUEST_TIMEOUT,
    SEVERITY_THRESHOLD,
    SUMMARY_REPO,
)
from .policy import _normalize_package


def _github_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def fetch_open_alerts(repo):
    """Return all open Dependabot alerts for ``repo`` (owner/name)."""
    headers = _github_headers()
    # The Dependabot alerts API uses cursor-based pagination via the Link header
    # (before/after cursors); it rejects the `page` parameter.
    alerts = []
    url = f"{GITHUB_API}/repos/{repo}/dependabot/alerts"
    params = {"state": "open", "per_page": 100}
    while url:
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            raise RuntimeError(
                f"Failed to fetch Dependabot alerts for {repo}: "
                f"{response.status_code} - {response.text}"
            )
        alerts.extend(response.json())
        # Follow the "next" cursor; its URL already carries the query string.
        url = response.links.get("next", {}).get("url")
        params = None
    return alerts


def fetch_open_dependabot_prs(repo):
    """Return open PRs opened by Dependabot as ``[{"title", "head_ref"}, ...]``.

    Used to skip alerts Dependabot is already fixing on its own (the trivial,
    patch-available bumps), so Devin is not dispatched to duplicate that work.
    Returns ``[]`` on any fetch error so a failure here never blocks scanning.
    """
    headers = _github_headers()
    prs = []
    page = 1
    try:
        while True:
            response = requests.get(
                f"{GITHUB_API}/repos/{repo}/pulls",
                headers=headers,
                params={"state": "open", "per_page": 100, "page": page},
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code != 200:
                print(
                    f"WARN  could not list PRs for dedup ({response.status_code}); "
                    "proceeding without Dependabot-PR dedup"
                )
                return []
            batch = response.json()
            if not batch:
                break
            for pr in batch:
                login = (pr.get("user") or {}).get("login", "")
                if login in ("dependabot[bot]", "dependabot-preview[bot]"):
                    prs.append(
                        {
                            "title": pr.get("title", ""),
                            "head_ref": (pr.get("head") or {}).get("ref", ""),
                            "base_ref": (pr.get("base") or {}).get("ref", ""),
                        }
                    )
            if len(batch) < 100:
                break
            page += 1
    except requests.RequestException as exc:
        print(f"WARN  could not list PRs for dedup ({exc}); proceeding without dedup")
        return []
    return prs


def cascade_package_count(repo, base, head, cat):
    """Count OTHER packages a Dependabot bump changes, via the dependency-graph
    compare API (base...head). Returns an int, or None if it can't be determined.

    The compare endpoint diffs the resolved dependency graph between the default
    branch and the Dependabot PR branch, so it captures the real transitive
    cascade of the upgrade without asking Devin to resolve it.
    """
    if not base or not head:
        return None
    headers = _github_headers()
    url = f"{GITHUB_API}/repos/{repo}/dependency-graph/compare/{base}...{head}"
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        print(f"WARN  cascade check failed ({exc}); not escalating")
        return None
    if response.status_code != 200:
        print(f"WARN  cascade check unavailable ({response.status_code}); not escalating")
        return None
    target = _normalize_package(cat["package"])
    changed = {_normalize_package(dep.get("name", "")) for dep in response.json()}
    changed.discard(target)
    changed.discard("")
    return len(changed)


def ci_status(repo, pr_number):
    """Aggregate CI conclusion for a PR: 'success' | 'failure' | 'pending' | 'unknown'."""
    if not pr_number:
        return "unknown"
    headers = _github_headers()
    try:
        pr = requests.get(
            f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}", headers=headers, timeout=REQUEST_TIMEOUT
        )
        if pr.status_code != 200:
            return "unknown"
        sha = (pr.json().get("head") or {}).get("sha")
        if not sha:
            return "unknown"
        runs = requests.get(
            f"{GITHUB_API}/repos/{repo}/commits/{sha}/check-runs",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if runs.status_code != 200:
            return "unknown"
        check_runs = runs.json().get("check_runs", [])
    except requests.RequestException as exc:
        print(f"WARN  CI status fetch failed for PR #{pr_number} ({exc})")
        return "unknown"
    if not check_runs:
        return "unknown"
    if any(r.get("status") != "completed" for r in check_runs):
        return "pending"
    bad = {"failure", "timed_out", "cancelled", "action_required", "startup_failure"}
    if any((r.get("conclusion") or "") in bad for r in check_runs):
        return "failure"
    return "success"


def get_pr_labels(repo, pr_number):
    """Return the set of label names on a PR (empty set on any error)."""
    if not pr_number:
        return set()
    try:
        response = requests.get(
            f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/labels",
            headers=_github_headers(),
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            return set()
        return {lbl.get("name", "") for lbl in response.json()}
    except requests.RequestException:
        return set()


def post_pr_comment(repo, pr_number, body):
    """Comment on a PR (a remediation-state mutation; never touches mainline)."""
    if not pr_number:
        return False
    try:
        response = requests.post(
            f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments",
            headers=_github_headers(),
            json={"body": body},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        print(f"WARN  could not comment on PR #{pr_number} ({exc})")
        return False
    if response.status_code not in (200, 201):
        print(f"WARN  could not comment on PR #{pr_number} ({response.status_code})")
        return False
    return True


def open_tracking_issue(repo, entry, session_log=None):
    """File a tracking issue for an escalated alert (a remediation-state mutation)."""
    title = f"[dependabot-scan] Manual remediation needed: {entry.get('package')} ({entry.get('ghsa_id')})"
    log_section = f"\n\n<details><summary>Session log</summary>\n\n```\n{session_log}\n```\n\n</details>" if session_log else ""
    body = (
        f"Automated remediation for `{entry.get('package')}` "
        f"({entry.get('ghsa_id')}) did not reach a verified fix after "
        f"{entry.get('retries', 0)} retr(y/ies).\n\n"
        f"- Devin session: {entry.get('session_url')}\n"
        f"- PR: {entry.get('pr_url') or 'none opened'}\n"
        f"- Last status: {entry.get('status')}\n\n"
        "A human needs to take over."
        f"{log_section}"
    )
    try:
        response = requests.post(
            f"{GITHUB_API}/repos/{repo}/issues",
            headers=_github_headers(),
            json={"title": title, "body": body, "labels": [LABEL_REVIEW]},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (200, 201):
            return response.json().get("html_url")
        print(f"WARN  could not open tracking issue ({response.status_code})")
    except requests.RequestException as exc:
        print(f"WARN  could not open tracking issue ({exc})")
    return None


def file_run_summary(repo, mode, counts, details, dry_run):
    """File one issue per run in SUMMARY_REPO: the ledger an eng leader reads.

    Counts answer "is it working"; the decision bullets answer "what did it
    decide". Skipped entirely when the run did nothing, so a scheduled scan
    with no new alerts does not generate noise.
    """
    if not any(counts.values()) and not details:
        return  # nothing happened; don't file noise
    title = f"[rem] {mode} run summary — {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC"
    lines = [f"- **{k}**: {v}" for k, v in sorted(counts.items())]
    body = (
        f"## Redress {mode} run — `{repo}`\n\n" + "\n".join(lines)
        + "\n\n### Decisions\n" + ("\n".join(details) if details else "_none_")
        + f"\n\n_threshold: `{SEVERITY_THRESHOLD}` · max dispatch: `{MAX_DISPATCH}`_"
    )
    if dry_run:
        print("DRY   would file run summary issue")
        return
    try:
        response = requests.post(
            f"{GITHUB_API}/repos/{SUMMARY_REPO}/issues",
            headers=_github_headers(),
            json={"title": title, "body": body, "labels": ["rem:run-summary"]},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (200, 201):
            print(f"SUMMARY filed: {response.json().get('html_url')}")
        else:
            print(f"WARN  could not file run summary ({response.status_code})")
    except requests.RequestException as exc:
        print(f"WARN  could not file run summary ({exc})")
