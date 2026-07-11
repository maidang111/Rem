"""Command-line entry point: argument parsing and the scan/reconcile orchestration."""
import argparse
import os
import sys
import time
from datetime import datetime, timezone

from .config import MAX_CASCADE, MAX_DISPATCH, SCAN_REPO, STATE_FILE, require_config
from .github_api import (
    cascade_package_count,
    fetch_open_alerts,
    fetch_open_dependabot_prs,
    file_run_summary,
)
from .devin import dispatch_to_devin
from .policy import (
    categorize_alert,
    find_dependabot_pr,
    is_sensitive,
    priority_key,
    should_dispatch,
)
from .prompts import build_prompt
from .reconcile import reconcile
from .state import load_state, save_state, state_key


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
