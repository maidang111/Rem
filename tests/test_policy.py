"""Unit tests for the pure dispatch-policy logic (no network)."""
from dependabot_scanner.policy import (
    categorize_alert,
    find_dependabot_pr,
    priority_key,
    should_dispatch,
)


def _cat(**overrides):
    base = {
        "number": 1,
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "severity": "high",
        "summary": "",
        "package": "requests",
        "ecosystem": "pip",
        "vulnerable_range": "< 2.31.0",
        "patched_version": "2.31.0",
        "has_fix": True,
        "scope": "runtime",
        "relationship": "direct",
        "manifest_path": "requirements.txt",
        "url": "https://example.test",
    }
    base.update(overrides)
    return base


def test_dispatch_when_patch_available():
    dispatch, reason = should_dispatch(_cat())
    assert dispatch is True
    assert reason == "patched version available"


def test_skip_when_no_patch():
    dispatch, reason = should_dispatch(_cat(has_fix=False, patched_version=None))
    assert dispatch is False
    assert "no patched version" in reason


def test_skip_dev_only_dependency():
    dispatch, reason = should_dispatch(_cat(scope="development"))
    assert dispatch is False
    assert reason == "dev-only dependency"


def test_low_severity_still_dispatches_by_default():
    # Severity is a priority, not a filter: a low-severity alert with a patch dispatches.
    dispatch, _ = should_dispatch(_cat(severity="low"))
    assert dispatch is True


def test_priority_orders_critical_first_then_direct():
    critical = _cat(severity="critical", relationship="transitive")
    high_direct = _cat(severity="high", relationship="direct")
    high_transitive = _cat(severity="high", relationship="transitive")
    ordered = sorted([high_transitive, high_direct, critical], key=priority_key)
    assert [c["severity"] for c in ordered] == ["critical", "high", "high"]
    # At equal severity, direct deps rank before transitive.
    assert ordered[1]["relationship"] == "direct"
    assert ordered[2]["relationship"] == "transitive"


def test_find_dependabot_pr_matches_scoped_package_without_prefix_false_positive():
    cat = _cat(package="@babel/traverse")
    prs = [
        {"title": "Bump @babel/traverse from 7.0.0 to 7.23.2", "head_ref": "dependabot/npm_and_yarn/babel/traverse-7.23.2"},
        {"title": "Bump @babel/core from 7.0.0 to 7.1.0", "head_ref": "dependabot/npm_and_yarn/babel/core-7.1.0"},
    ]
    match = find_dependabot_pr(cat, prs)
    assert match is not None
    assert "traverse" in match["title"]

    # A package that only shares a prefix must not match.
    assert find_dependabot_pr(_cat(package="req"), [
        {"title": "Bump requests from 2.30 to 2.31", "head_ref": "dependabot/pip/requests-2.31"},
    ]) is None


def test_categorize_prefers_vulnerability_severity():
    alert = {
        "number": 7,
        "security_advisory": {"ghsa_id": "GHSA-a", "severity": "medium", "summary": "x"},
        "security_vulnerability": {
            "severity": "critical",
            "package": {"name": "flask", "ecosystem": "pip"},
            "first_patched_version": {"identifier": "3.0.1"},
            "vulnerable_version_range": "< 3.0.1",
        },
        "dependency": {"scope": "runtime", "relationship": "direct", "manifest_path": "requirements.txt"},
        "html_url": "https://example.test/7",
    }
    cat = categorize_alert(alert)
    assert cat["severity"] == "critical"  # per-package severity wins over advisory
    assert cat["package"] == "flask"
    assert cat["has_fix"] is True
