#!/usr/bin/env python3
"""Run-once Dependabot alert scanner.

Fetches open Dependabot alerts for a repository, categorizes them, applies a
dispatch policy, and hands the qualifying ones to Devin. Each dispatched Devin
session is responsible for opening the fix PR in the affected repository itself
(that is where the vulnerable manifest lives).

Dispatch policy: severity is a PRIORITY, not a filter. Any alert with a
published patch (and that ships to production) qualifies; alerts are sorted by
severity (then direct-before-transitive) and MAX_DISPATCH caps how many
sessions a single run opens. Criticals always go first; the rest of the
backlog drains at a controlled rate on subsequent runs.

State is tracked in a local JSON file so re-running the script does not create
duplicate Devin sessions for alerts it already handled.

Usage:
    python dependabot_scan.py            # scan and dispatch
    python dependabot_scan.py --dry-run  # scan and print decisions, dispatch nothing
    python dependabot_scan.py --check    # compute the cascade, route through reviewed-upgrade path, and Devin ships the fix PR
    python dependabot_scan.py --reset    # reset the state file
"""
import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

GITHUB_API = "https://api.github.com"
DEVIN_API = "https://api.devin.ai/v1"
# Devin prompt text lives in these template files so it can be edited without code changes.
TEMPLATE_DIR = Path(os.getenv("PROMPT_TEMPLATE_DIR", Path(__file__).parent / "templates"))

DEVIN_API_KEY = os.getenv("DEVIN_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SCAN_REPO = os.getenv("SCAN_REPO", "maidang111/superset")
STATE_FILE = os.getenv("DEPENDABOT_STATE_FILE", ".dependabot_state.json")
# Where run-summary issues are filed: the orchestrator repo, NOT the scan target,
# so the ledger lives next to the code that produced it.
SUMMARY_REPO = os.getenv("SUMMARY_REPO", "maidang111/Rem")
# Minimum severity to dispatch to Devin: low | medium | high | critical.
# Default is "low": if a patch exists, we patch. Severity orders the queue;
# it does not gate it. Raise this only if a deployment genuinely needs to
# suppress low-priority remediation entirely.
SEVERITY_THRESHOLD = os.getenv("SEVERITY_THRESHOLD", "low").lower()
# Safety cap on how many sessions a single run may open. This is the real
# throttle - it rate-limits for Devin session budget and human PR-review
# bandwidth, not for remediation cost.
MAX_DISPATCH = int(os.getenv("MAX_DISPATCH", "5"))
# If an upgrade cascades to (forces version changes in) more than this many OTHER
# packages, Devin must stop the auto-fix and flag the PR for human review instead.
MAX_CASCADE = int(os.getenv("MAX_CASCADE", "2"))
# Seconds to wait on any HTTP request before giving up, so a hung endpoint can't
# stall the whole run. (connect timeout, read timeout)
REQUEST_TIMEOUT = (float(os.getenv("REQUEST_TIMEOUT", "30")), float(os.getenv("REQUEST_TIMEOUT", "30")))
# How many times --reconcile nudges a stuck session (no PR, or red CI) before it
# escalates the alert to a human.
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))

# Lifecycle of every state entry. The reconcile loop must move each entry toward a
# TERMINAL_STATE; retrying/no_pr_stalled are bounded by MAX_RETRIES then escalate.
#   dispatched     -> session created, no PR seen yet
#   pr_open        -> PR discovered, CI still pending/unknown
#   verified       -> PR open AND CI green                         (terminal, success)
#   retrying       -> PR CI is failing; session nudged to fix it   (bounded)
#   no_pr_stalled  -> session finished without opening a PR; nudged (bounded)
#   escalated      -> retries exhausted; tracking issue filed      (terminal, needs human)
TERMINAL_STATES = {"verified", "escalated"}
KNOWN_STATES = {"dispatched", "pr_open", "verified", "retrying", "no_pr_stalled", "escalated"}

# Labels the Devin session applies to the fix PR so humans can triage at a glance.
LABEL_ROUTINE = "rem:routine-bump"
LABEL_REVIEW = "rem:needs-careful-review"

HTTP_TIMEOUT = 30  # seconds; a hung API call should fail, not hang the run

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# Runtime dependencies ship in the codebase, so they outrank dev-only ones at equal severity.
SCOPE_ORDER = {"development": 0}  # everything else (runtime / unknown) ranks higher

# Packages considered high-blast-radius / system-wide. An unreviewed insta-bump of
# these is risky, so they are ALWAYS routed to a reviewed Devin upgrade -- even when
# Dependabot already opened a PR (i.e. they bypass the dedup skip).
#
# The list lives in its own file (default: sensitive_packages.txt, override with
# SENSITIVE_PACKAGES_FILE) -- one package per line, blank lines and "#" comments
# ignored. The SENSITIVE_PACKAGES env var may still add extras (comma-separated).
# All names are normalized: lower-cased, leading npm scope "@" stripped.
SENSITIVE_PACKAGES_FILE = os.getenv("SENSITIVE_PACKAGES_FILE", "sensitive_packages.txt")


def _normalize_sensitive(name):
    return name.strip().lower().lstrip("@")


def load_sensitive_packages(path=SENSITIVE_PACKAGES_FILE):
    """Read the sensitive-package list from `path` (if present) plus the env var."""
    packages = set()
    if path and os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()  # drop inline comments
                if line:
                    packages.add(_normalize_sensitive(line))
    for entry in os.getenv("SENSITIVE_PACKAGES", "").split(","):
        if entry.strip():
            packages.add(_normalize_sensitive(entry))
    return packages


SENSITIVE_PACKAGES = load_sensitive_packages()


def require_config():
    """Fail loudly (instead of a later NoneType error) if credentials are missing."""
    # Checked once at startup so the run aborts before any API calls if creds are unset.
    missing = [
        name
        for name, value in (("DEVIN_API_KEY", DEVIN_API_KEY), ("GITHUB_TOKEN", GITHUB_TOKEN))
        if not value
    ]
    if missing:
        sys.exit(
            "Missing required environment variable(s): "
            + ", ".join(missing)
            + ". Set them in a .env file next to this script (see .env.example)."
        )


def fetch_open_alerts(repo):
    """Return all open Dependabot alerts for ``repo`` (owner/name)."""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
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
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
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


def _normalize_package(name):
    """Lowercase and drop a leading npm scope ``@`` for matching."""
    return (name or "").lower().lstrip("@")


def find_dependabot_pr(cat, dep_prs):
    """Return the open Dependabot PR that bumps this alert's package, or None.

    Matches the package name as a delimited token in either the PR title
    ("Bump <pkg> from ...") or the branch ref ("dependabot/<eco>/.../<pkg>-<ver>"),
    so scoped names like ``@babel/traverse`` match without false positives on
    packages that merely share a prefix.
    """
    pkg = _normalize_package(cat["package"])
    if not pkg:
        return None
    pattern = re.compile(rf"(^|[\s/@]){re.escape(pkg)}([\s\-/@]|$)")
    for pr in dep_prs:
        if pattern.search(pr["title"].lower()) or pattern.search(pr["head_ref"].lower()):
            return pr
    return None


def has_open_dependabot_pr(cat, dep_prs):
    """True if an open Dependabot PR already bumps this alert's package."""
    return find_dependabot_pr(cat, dep_prs) is not None


def cascade_package_count(repo, base, head, cat):
    """Count OTHER packages a Dependabot bump changes, via the dependency-graph
    compare API (base...head). Returns an int, or None if it can't be determined.

    The compare endpoint diffs the resolved dependency graph between the default
    branch and the Dependabot PR branch, so it captures the real transitive
    cascade of the upgrade without asking Devin to resolve it.
    """
    if not base or not head:
        return None
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
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


def is_sensitive(cat):
    """True if the alert's package is on the policy-sensitive (high-blast-radius) list."""
    return _normalize_package(cat["package"]) in SENSITIVE_PACKAGES


def categorize_alert(alert):
    """Extract the decision-relevant fields from a raw Dependabot alert."""
    advisory = alert.get("security_advisory", {})
    vuln = alert.get("security_vulnerability", {})
    package = vuln.get("package", {})
    dependency = alert.get("dependency", {})
    patched = vuln.get("first_patched_version") or {}

    # Prefer the per-package vulnerability severity; it can differ from the
    # advisory-level score and is the more specific signal. Fall back to the
    # advisory severity.
    severity = (vuln.get("severity") or advisory.get("severity") or "low").lower()

    return {
        "number": alert.get("number"),
        "ghsa_id": advisory.get("ghsa_id"),
        "severity": severity,
        "summary": advisory.get("summary", ""),
        "package": package.get("name"),
        "ecosystem": package.get("ecosystem"),
        "vulnerable_range": vuln.get("vulnerable_version_range"),
        "patched_version": patched.get("identifier"),
        "has_fix": bool(patched.get("identifier")),
        "scope": dependency.get("scope"),  # "runtime" | "development" | None
        "relationship": dependency.get("relationship"),  # "direct" | "transitive" | None
        "manifest_path": dependency.get("manifest_path"),
        "url": alert.get("html_url"),
    }


def should_dispatch(cat):
    """Decide whether an alert is eligible for a Devin session at all.

    Severity is intentionally NOT a gate here (beyond the optional
    SEVERITY_THRESHOLD escape hatch) - it is used to rank the queue in
    ``priority_key``. If a patch exists and the dependency ships to
    production, the safest state is patched.

    Severity is NOT a filter: a low-severity advisory can still matter (e.g. a
    widely-used dependency), and a medium one is often a trivial bump worth doing.
    So any alert with an available patch is dispatched; severity only affects
    ordering (see ``priority``). We skip only alerts with no patched version,
    since a bump cannot resolve those.

    Returns (dispatch: bool, reason: str).
    """
    if not cat["has_fix"]:
        # No patched version exists yet; a bump cannot resolve it. Flag for a human.
        return False, "no patched version available - flagged for human review"
    if cat["scope"] == "development":
        return False, "dev-only dependency"
    if SEVERITY_ORDER.get(cat["severity"], 0) < SEVERITY_ORDER[SEVERITY_THRESHOLD]:
        return False, f"below severity threshold ({cat['severity']} < {SEVERITY_THRESHOLD})"
    return True, "patched version available"


def priority_key(cat):
    """Sort key: highest severity first, direct dependencies before transitive.

    Direct deps are the one cheap exposure proxy the API gives us - they are
    more likely to be invoked by first-party code and their bumps are less
    likely to break. Real reachability analysis is the roadmap item.
    """
    return (
        -SEVERITY_ORDER.get(cat["severity"], 0),
        0 if cat["relationship"] == "direct" else 1,
    )


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)


def state_key(repo, cat):
    """Stable per-alert key so we do not re-dispatch across runs.

    GHSA id alone is not unique: one advisory can produce multiple alerts
    (same package in several manifests, or several packages under one GHSA),
    so the key includes package and manifest path.
    """
    return f"{repo}#{cat['ghsa_id'] or cat['number']}#{cat['package']}#{cat['manifest_path']}"

def _load_prompt_template(name):
    """Read a prompt template from the templates/ directory (fail loudly if missing)."""
    path = TEMPLATE_DIR / name
    if not path.exists():
        raise RuntimeError(f"Missing prompt template: {path}")
    return path.read_text(encoding="utf-8")


def build_prompt(repo, cat, review=False):
    """Render the Devin prompt from templates/ (routine vs reviewed upgrade).

    The prompt text lives in templates/*.md so it can be edited without touching code;
    placeholders are filled from the alert's fields plus the scanner's policy config.
    """
    ctx = {
        "repo": repo,
        "package": cat["package"],
        "ecosystem": cat["ecosystem"],
        "severity": cat["severity"],
        "ghsa_id": cat["ghsa_id"],
        "summary": cat["summary"],
        "vulnerable_range": cat["vulnerable_range"],
        "patched_version": cat["patched_version"],
        "manifest_path": cat["manifest_path"],
        "url": cat["url"],
        "max_cascade": MAX_CASCADE,
        "label_routine": LABEL_ROUTINE,
        "label_review": LABEL_REVIEW,
    }
    ctx["details"] = _load_prompt_template("vulnerability_details.md").format(**ctx)
    template = "reviewed_upgrade.md" if review else "routine_upgrade.md"
    return _load_prompt_template(template).format(**ctx)


def dispatch_to_devin(prompt):
    headers = {
        "Authorization": f"Bearer {DEVIN_API_KEY}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        f"{DEVIN_API}/sessions",
        headers=headers,
        json={"prompt": prompt, "idempotent": True},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Devin API error: {response.status_code} - {response.text}"
        )
    return response.json()


# ---------------------------------------------------------------------------
# Reconcile: watch dispatched sessions through to a terminal state.
#
# Scope of mutations (per policy): creating/nudging Devin sessions, posting
# session messages, applying PR labels, and filing tracking issues are all in
# scope. Mutating the repo's mainline (merging PRs) is NOT -- the human-merge
# gate is deliberate policy, so reconcile never merges.
# ---------------------------------------------------------------------------
def _github_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def get_devin_session(session_id):
    """Return the Devin session object, or None if it can't be fetched."""
    if not session_id:
        return None
    headers = {"Authorization": f"Bearer {DEVIN_API_KEY}"}
    try:
        response = requests.get(
            f"{DEVIN_API}/session/{session_id}", headers=headers, timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException as exc:
        print(f"WARN  could not fetch session {session_id} ({exc})")
        return None
    if response.status_code != 200:
        print(f"WARN  could not fetch session {session_id} ({response.status_code})")
        return None
    return response.json()


def send_session_message(session_id, message):
    """Post a follow-up message to a Devin session (a remediation-state mutation)."""
    headers = {
        "Authorization": f"Bearer {DEVIN_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(
            f"{DEVIN_API}/session/{session_id}/message",
            headers=headers,
            json={"message": message},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        print(f"WARN  could not message session {session_id} ({exc})")
        return False
    if response.status_code not in (200, 201, 204):
        print(f"WARN  could not message session {session_id} ({response.status_code})")
        return False
    return True


def session_is_finished(session):
    """True if the Devin session has reached a terminal state (no longer working)."""
    status = (session or {}).get("status_enum") or (session or {}).get("status") or ""
    return status.lower() in {"finished", "blocked", "expired", "stopped"}


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


def format_session_log(session, max_chars=6000):
    """Render a compact, readable log from a Devin session for attaching to a PR/issue.

    Pulls the session's messages if present, else falls back to a truncated JSON dump.
    Returns None if there is nothing usable.
    """
    if not session:
        return None
    lines = []
    messages = session.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            kind = msg.get("type") or msg.get("role") or "message"
            text = msg.get("message") or msg.get("content") or msg.get("text") or ""
            if text:
                lines.append(f"[{kind}] {text}")
    body = "\n".join(lines) if lines else json.dumps(session, indent=2, default=str)
    if not body.strip():
        return None
    if len(body) > max_chars:
        body = "...(truncated)...\n" + body[-max_chars:]
    return body


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


def main():
    parser = argparse.ArgumentParser(description="Scan Dependabot alerts and dispatch fixes to Devin.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print categorization and decisions without creating Devin sessions.",
    )
    parser.add_argument("--repo", default=SCAN_REPO, help=f"Repo to scan (default: {SCAN_REPO}).")
    parser.add_argument(
        "--force",
        action="append",
        default=[],
        metavar="GHSA_ID",
        help=("Re-dispatch this alert even if it is already recorded in state "
              "(e.g. its PR was closed). Repeatable or comma-separated."),
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear all recorded state before scanning, so every open alert is reconsidered.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=("Compute the upgrade cascade in the scanner (not in Devin): if a bump forces "
              f"changes to more than MAX_CASCADE (={MAX_CASCADE}) other packages, escalate the "
              "alert to the careful-review path (rem:needs-careful-review label + review prompt)."),
    )
    parser.add_argument(
        "--reconcile",
        action="store_true",
        help=("Instead of scanning, watch previously dispatched sessions: discover their PR, "
              "check CI, and drive each recorded alert to a terminal state (verified/escalated). "
              "Never merges PRs -- the human-merge gate is policy."),
    )
    args = parser.parse_args()

    require_config()

    if args.reconcile:
        state = load_state()
        print(f"Reconciling {len(state)} recorded session(s) for {args.repo} ...")
        reconcile(args.repo, state, args.dry_run)
        if not args.dry_run:
            save_state(state)
        return

    # Normalize --force values (accept repeated flags and comma-separated lists).
    forced = {
        g.strip().lower()
        for item in args.force
        for g in item.split(",")
        if g.strip()
    }

    repo = args.repo
    print(f"Scanning open Dependabot alerts for {repo} ...")
    alerts = fetch_open_alerts(repo)
    print(f"Found {len(alerts)} open alert(s).")

    if args.reset:
        state = {}
        if not args.dry_run and os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
        print("Reset: ignoring existing state; every open alert will be reconsidered.")
    else:
        state = load_state()

    # Dependabot auto-opens PRs for the trivial patch-available bumps; skip those so
    # Devin only handles what Dependabot can't (breaking/major bumps, no clean patch).
    dep_prs = fetch_open_dependabot_prs(repo)
    if dep_prs:
        print(f"Found {len(dep_prs)} open Dependabot PR(s); will skip alerts they already cover.")

    # Categorize everything, then decide. Non-dispatch outcomes are reported up front.
    # Pass 1: categorize everything and split into skips vs. the dispatch queue.
    queue = []
    details = []  # one markdown bullet per decision, for the run-summary issue
    for alert in alerts:
        cat = categorize_alert(alert)
        key = state_key(repo, cat)
        label = f"[{cat['severity']}] {cat['package']} ({cat['ghsa_id']})"

        is_forced = (cat["ghsa_id"] or "").lower() in forced
        if key in state and not is_forced:
            print(f"SKIP  {label}: already handled ({state[key].get('session_url', 'no url')})")
            details.append(f"- ⏭️ SKIP {label} — already handled")
            continue
        if key in state and is_forced:
            print(f"FORCE {label}: re-dispatching (was already handled)")

        dispatch, reason = should_dispatch(cat)
        if not dispatch:
            print(f"SKIP  {label}: {reason}")
            details.append(f"- ⏭️ SKIP {label} — {reason}")
            continue

        sensitive = is_sensitive(cat)
        dep_pr = find_dependabot_pr(cat, dep_prs)
        has_dep_pr = dep_pr is not None

        # --check: compute the upgrade's transitive cascade from the Dependabot PR's
        # dependency graph (base...head). If it touches more than MAX_CASCADE other
        # packages, escalate to a reviewed upgrade instead of letting it auto-merge.
        cascade_escalated = False
        if args.check and dep_pr:
            n = cascade_package_count(repo, dep_pr.get("base_ref"), dep_pr.get("head_ref"), cat)
            if n is not None and n > MAX_CASCADE:
                cascade_escalated = True
                print(
                    f"CHECK {label}: upgrade cascades to {n} other packages "
                    f"(> MAX_CASCADE={MAX_CASCADE}); escalating to reviewed upgrade."
                )

        review = sensitive or cascade_escalated

        # Non-sensitive packages Dependabot is already bumping are left to Dependabot,
        # UNLESS the cascade check escalated them. Sensitive packages are never skipped
        # -- they always get a reviewed upgrade, since an insta-bump is risky.
        if has_dep_pr and not review:
            print(f"SKIP  {label}: Dependabot already has an open PR for this package")
            details.append(f"- ⏭️ SKIP {label} — Dependabot PR already open")
            continue

        if sensitive:
            tag = f"[sensitive] {cat['package']}"
            if has_dep_pr:
                print(
                    f"DISPATCH {tag}: Dependabot PR exists but package is policy-sensitive; "
                    "routing to reviewed upgrade."
                )
            else:
                print(f"DISPATCH {tag}: policy-sensitive package; routing to reviewed upgrade.")
        elif cascade_escalated:
            print(
                f"DISPATCH [cascade] {cat['package']}: Dependabot PR exists but the bump "
                f"cascades to more than {MAX_CASCADE} packages; routing to reviewed upgrade."
            )

        queue.append((key, cat, label, review))

    # Rank the queue - highest severity first, direct deps before transitive -
    # THEN apply the MAX_DISPATCH cut, so criticals are never held behind
    # lower-severity alerts that arrived earlier in the API response.
    queue.sort(key=lambda item: priority_key(item[1]))
    to_dispatch, held = queue[:MAX_DISPATCH], queue[MAX_DISPATCH:]

    dispatched = 0
    failed = 0
    for key, cat, label, review in to_dispatch:
        if review:
            label = f"[review] {label}"
        if args.dry_run:
            mode = " (reviewed upgrade)" if review else ""
            print(f"WOULD DISPATCH  {label}{mode}")
            details.append(f"- ✅ would dispatch {label}{mode}")
            dispatched += 1
            continue

        print(f"DISPATCH  {label}")
        try:
            session = dispatch_to_devin(build_prompt(repo, cat, review=review))
        except Exception as exc:  # noqa: BLE001 - isolate one flaky call from the run
            failed += 1
            print(f"FAIL  {label}: dispatch failed, will retry next run ({exc})")
            details.append(f"- ❌ FAILED {label} — will retry next run")
            continue
        state[key] = {
            "session_id": session.get("session_id"),
            "session_url": session.get("url"),
            "severity": cat["severity"],
            "package": cat["package"],
            "ghsa_id": cat["ghsa_id"],
            "reviewed_upgrade": review,
            "status": "dispatched",
            "retries": 0,
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
        }
        save_state(state)
        print(f"          -> {session.get('url')}")
        details.append(f"- ✅ dispatched {label} → {session.get('url')}")
        dispatched += 1
        time.sleep(1)

    for rank, (_key, _cat, label, _review) in enumerate(held, start=MAX_DISPATCH + 1):
        print(f"HOLD  {label}: rank {rank} of {len(queue)}, MAX_DISPATCH={MAX_DISPATCH} reached")
        details.append(f"- ⏸️ HOLD {label} — rank {rank}, cap reached")
    verb = "would dispatch" if args.dry_run else "dispatched"
    summary = f"Done. {verb} {dispatched} session(s); {len(held)} held"
    if failed:
        summary += f"; {failed} FAILED (will retry next run)"
    print(summary + ".")

    file_run_summary(
        repo, "scan",
        {"dispatched": dispatched, "held": len(held), "failed": failed},
        details, args.dry_run,
    )

    if failed and not args.dry_run:
        sys.exit(1)  # non-zero exit so a scheduler/CI wrapper can alert on it

if __name__ == "__main__":
    main()