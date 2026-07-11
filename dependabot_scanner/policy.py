"""Alert categorization and dispatch policy (pure decision logic)."""
import re

from .config import (
    SENSITIVE_PACKAGES,
    SEVERITY_ORDER,
    SEVERITY_THRESHOLD,
)


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
