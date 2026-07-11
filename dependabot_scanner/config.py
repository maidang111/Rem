"""Configuration, environment variables, and shared constants for the scanner.

All values are read from the environment once at import time (matching the
original single-file behavior). A ``.env`` file next to the project root is
loaded automatically.
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

GITHUB_API = "https://api.github.com"
DEVIN_API = "https://api.devin.ai/v1"
# Devin prompt text lives in these template files so it can be edited without code changes.
TEMPLATE_DIR = Path(os.getenv("PROMPT_TEMPLATE_DIR", Path(__file__).resolve().parent.parent / "templates"))

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
