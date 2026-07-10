#!/usr/bin/env python3
"""Run-once Dependabot alert scanner.

Fetches open Dependabot alerts for a repository, categorizes them, applies a
dispatch policy, and hands the qualifying ones to Devin. Each dispatched Devin
session is responsible for opening the fix PR in the affected repository itself
(that is where the vulnerable manifest lives).

State is tracked in a local JSON file so re-running the script does not create
duplicate Devin sessions for alerts it already handled.

Usage:
    python dependabot_scan.py            # scan and dispatch
    python dependabot_scan.py --dry-run  # scan and print decisions, dispatch nothing
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

GITHUB_API = "https://api.github.com"
DEVIN_API = "https://api.devin.ai/v1"

DEVIN_API_KEY = os.getenv("DEVIN_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SCAN_REPO = os.getenv("SCAN_REPO", "maidang111/superset")
STATE_FILE = os.getenv("DEPENDABOT_STATE_FILE", ".dependabot_state.json")
# Safety cap on how many sessions a single run may open.
MAX_DISPATCH = int(os.getenv("MAX_DISPATCH", "5"))

# Used to rank alerts so the most severe are dispatched first (not to filter them out).
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# Runtime dependencies ship in the codebase, so they outrank dev-only ones at equal severity.
SCOPE_ORDER = {"development": 0}  # everything else (runtime / unknown) ranks higher


def require_config():
    """Fail loudly (instead of a later NoneType error) if credentials are missing."""
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
        response = requests.get(url, headers=headers, params=params)
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


def categorize_alert(alert):
    """Extract the decision-relevant fields from a raw Dependabot alert."""
    advisory = alert.get("security_advisory", {})
    vuln = alert.get("security_vulnerability", {})
    package = vuln.get("package", {})
    dependency = alert.get("dependency", {})
    patched = vuln.get("first_patched_version") or {}

    return {
        "number": alert.get("number"),
        "ghsa_id": advisory.get("ghsa_id"),
        "severity": (advisory.get("severity") or "low").lower(),
        "summary": advisory.get("summary", ""),
        "package": package.get("name"),
        "ecosystem": package.get("ecosystem"),
        "vulnerable_range": vuln.get("vulnerable_version_range"),
        "patched_version": patched.get("identifier"),
        "has_fix": bool(patched.get("identifier")),
        "scope": dependency.get("scope"),  # "runtime" | "development" | None
        "manifest_path": dependency.get("manifest_path"),
        "url": alert.get("html_url"),
    }


def should_dispatch(cat):
    """Decide whether an alert is worth a Devin session.

    Severity is NOT a filter: a low-severity advisory can still matter (e.g. a
    widely-used dependency), and a medium one is often a trivial bump worth doing.
    So any alert with an available patch is dispatched; severity only affects
    ordering (see ``priority``). We skip only alerts with no patched version,
    since a bump cannot resolve those.

    Returns (dispatch: bool, reason: str).
    """
    if not cat["has_fix"]:
        return False, "no patched version available"
    return True, "patched version available"


def priority(cat):
    """Sort key (descending) for dispatch order: severity first, then scope.

    Higher tuples are dispatched first, so within the MAX_DISPATCH budget the
    most severe and most-impactful (runtime over dev-only) alerts win.
    """
    return (
        SEVERITY_ORDER.get(cat["severity"], 0),
        SCOPE_ORDER.get(cat["scope"], 1),
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
    """Stable per-alert key so we do not re-dispatch across runs."""
    return f"{repo}#{cat['ghsa_id'] or cat['number']}"


def build_prompt(repo, cat):
    return f"""A Dependabot security alert needs to be fixed in the {repo} repository.

Vulnerability:
- Package: {cat['package']} ({cat['ecosystem']})
- Severity: {cat['severity']}
- Advisory (GHSA): {cat['ghsa_id']} - {cat['summary']}
- Vulnerable range: {cat['vulnerable_range']}
- First patched version: {cat['patched_version']}
- Manifest file: {cat['manifest_path']}
- Alert: {cat['url']}

Task:
1. In the {repo} repository, upgrade {cat['package']} to {cat['patched_version']} (or the
   nearest safe version that satisfies the advisory) in {cat['manifest_path']} and any
   lockfile.
2. Resolve any breaking changes the upgrade introduces so the project still builds.
3. Run the project's test suite / linters and make sure they pass.
4. Open a pull request against the default branch of {repo} with a clear description that
   references {cat['ghsa_id']}.

Only touch what is needed to remediate this advisory.
"""


def dispatch_to_devin(prompt):
    headers = {
        "Authorization": f"Bearer {DEVIN_API_KEY}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        f"{DEVIN_API}/sessions",
        headers=headers,
        json={"prompt": prompt, "idempotent": True},
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Devin API error: {response.status_code} - {response.text}"
        )
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Scan Dependabot alerts and dispatch fixes to Devin.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print categorization and decisions without creating Devin sessions.",
    )
    parser.add_argument("--repo", default=SCAN_REPO, help=f"Repo to scan (default: {SCAN_REPO}).")
    args = parser.parse_args()

    require_config()

    repo = args.repo
    print(f"Scanning open Dependabot alerts for {repo} ...")
    alerts = fetch_open_alerts(repo)
    print(f"Found {len(alerts)} open alert(s).")

    state = load_state()

    # Categorize everything, then decide. Non-dispatch outcomes are reported up front.
    candidates = []
    for alert in alerts:
        cat = categorize_alert(alert)
        key = state_key(repo, cat)
        label = f"[{cat['severity']}] {cat['package']} ({cat['ghsa_id']})"

        if key in state:
            print(f"SKIP  {label}: already handled ({state[key].get('session_url', 'no url')})")
            continue

        dispatch, reason = should_dispatch(cat)
        if not dispatch:
            print(f"SKIP  {label}: {reason}")
            continue

        candidates.append((cat, key, label))

    # Sort by priority (severity, then runtime-over-dev) so the most important go first.
    candidates.sort(key=lambda c: priority(c[0]), reverse=True)

    dispatched = 0
    for cat, key, label in candidates:
        if dispatched >= MAX_DISPATCH:
            print(f"HOLD  {label}: MAX_DISPATCH={MAX_DISPATCH} reached, leaving for next run")
            continue

        if args.dry_run:
            print(f"WOULD DISPATCH  {label}")
            dispatched += 1
            continue

        print(f"DISPATCH  {label}")
        session = dispatch_to_devin(build_prompt(repo, cat))
        state[key] = {
            "session_id": session.get("session_id"),
            "session_url": session.get("url"),
            "severity": cat["severity"],
            "package": cat["package"],
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
        }
        save_state(state)
        print(f"          -> session {session.get('url')}")
        dispatched += 1
        time.sleep(1)  # be gentle with the API

    verb = "would dispatch" if args.dry_run else "dispatched"
    print(f"Done. {verb} {dispatched} session(s) (highest-severity first).")


if __name__ == "__main__":
    main()
