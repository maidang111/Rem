import os
import hmac
import hashlib
import logging
import requests
from pathlib import Path
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load .env sitting next to this file, regardless of working directory
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("remedy")

app = Flask(__name__)

# --- Configuration (validated at boot: fail loudly, not at request time) ---
DEVIN_API_KEY = os.getenv("DEVIN_API_KEY")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # used by ingest/emit, not this file
SUPERSET_REPO = os.getenv("SUPERSET_REPO", "maidang111/superset")
TEMPLATE_DIR = Path(__file__).parent / "templates"

DISPATCH_LABEL = "Remediate"

_missing = [name for name, val in [
    ("DEVIN_API_KEY", DEVIN_API_KEY),
    ("WEBHOOK_SECRET", WEBHOOK_SECRET),
] if not val]
if _missing:
    raise SystemExit(f"Missing required env vars: {', '.join(_missing)} — check .env")

if not (TEMPLATE_DIR / "remediation.md").exists():
    raise SystemExit(f"Missing prompt template: {TEMPLATE_DIR / 'remediation.md'}")

# Dedup registry: issue number -> session_id.
# In-memory (resets on restart); swap for a SQLite lookup to persist.
_dispatched = {}


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook HMAC signature against the raw request body."""
    try:
        hash_algorithm, github_signature = signature.split("=", 1)
    except ValueError:
        return False
    if hash_algorithm != "sha256":
        return False
    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), github_signature)


def extract_issue_context(webhook_data: dict) -> dict:
    """Extract relevant context from a GitHub issue webhook payload."""
    issue = webhook_data.get("issue", {})
    repository = webhook_data.get("repository", {})
    return {
        "issue_number": issue.get("number"),
        "issue_title": issue.get("title", "(untitled)"),
        "issue_body": issue.get("body") or "",
        "issue_url": issue.get("html_url", ""),
        "repo_name": repository.get("full_name", ""),
        "labels": [l.get("name", "") for l in issue.get("labels", [])],
        "state": issue.get("state"),
        "user": issue.get("user", {}).get("login"),
    }


def load_prompt(template_name: str, **facts) -> str:
    template = (TEMPLATE_DIR / template_name).read_text()
    return template.format(**facts)


def create_devin_session(issue_context: dict) -> dict:
    """Dispatch a Devin session. Devin makes the fix and opens the PR."""
    prompt = load_prompt(
        "remediation.md",
        repo=SUPERSET_REPO,
        issue_title=issue_context["issue_title"],
        issue_body=issue_context["issue_body"],
        issue_url=issue_context["issue_url"],
    )

    resp = requests.post(
        "https://api.devin.ai/v1/sessions",
        headers={
            "Authorization": f"Bearer {DEVIN_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"prompt": prompt, "idempotent": True},
        timeout=30,
    )

    log.info("Devin API response: %s", resp.status_code)
    if not resp.ok:
        raise RuntimeError(f"Devin API {resp.status_code}: {resp.text[:300]}")

    data = resp.json()
    if "session_id" not in data:
        raise RuntimeError(f"Devin API response missing session_id: {data}")
    return data


@app.route("/webhook", methods=["POST"])
def webhook():
    """Orchestrator entry point: ordered gates, then dispatch or decline."""

    # Gate 1 — signature. Missing header = reject, always.
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature or not verify_webhook_signature(request.data, signature):
        return jsonify({"error": "Invalid signature"}), 401

    # Gate 2 — event type whitelist.
    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type != "issues":
        log.info("Ignoring event type: %s", event_type)
        return jsonify({"status": "ignored", "event": event_type}), 200

    webhook_data = request.get_json(silent=True) or {}

    # Gate 3 — action whitelist. 'labeled' = a human promoting an issue.
    action = webhook_data.get("action", "")
    if action not in ("opened", "labeled"):
        log.info("Ignoring action: %s", action)
        return jsonify({"status": "ignored", "action": action}), 200

    # Gate 4 — payload shape.
    issue = webhook_data.get("issue")
    if not issue:
        log.info("Ignoring payload with no issue object")
        return jsonify({"status": "ignored", "reason": "no issue payload"}), 200

    issue_context = extract_issue_context(webhook_data)
    issue_number = issue_context["issue_number"]

    # Gate 5 — routing fork. Only the agent lane dispatches.
    if DISPATCH_LABEL not in issue_context["labels"]:
        log.info(
            "Issue #%s '%s' routed non-agent (labels: %s)",
            issue_number, issue_context["issue_title"], issue_context["labels"],
        )
        # TODO: metrics row -> routed=non-agent
        return jsonify(
            {"status": "logged", "route": "non-agent", "issue": issue_number}
        ), 200

    # Gate 6 — dedup. Webhooks are at-least-once; the handler is idempotent.
    if issue_number in _dispatched:
        log.info(
            "Issue #%s already has session %s — dropping duplicate",
            issue_number, _dispatched[issue_number],
        )
        # TODO: metrics row -> dropped=duplicate
        return jsonify({
            "status": "dropped",
            "reason": "duplicate",
            "issue": issue_number,
            "session_id": _dispatched[issue_number],
        }), 200

    # Gate 7 — dispatch. Devin opens the PR from its session; we return now.
    log.info("Dispatching issue #%s: %s", issue_number, issue_context["issue_title"])
    try:
        session_data = create_devin_session(issue_context)
        session_id = session_data.get("session_id")
        _dispatched[issue_number] = session_id
        log.info("Created Devin session %s for issue #%s", session_id, issue_number)
        # TODO: metrics row -> dispatched, session_id

        return jsonify({
            "status": "dispatched",
            "issue": issue_number,
            "session_id": session_id,
            "session_url": session_data.get("url"),
        }), 200

    except Exception:
        log.exception("Dispatch failed for issue #%s", issue_number)
        # TODO: metrics row -> dispatch_failed
        return jsonify({"error": "dispatch failed", "issue": issue_number}), 500


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Remedy Webhook Orchestrator",
        "status": "running",
        "endpoints": {"webhook": "/webhook (POST)", "health": "/health (GET)"},
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    log.info("Remedy orchestrator starting on port %s", port)
    log.info("Dispatch label: %s | Target repo: %s", DISPATCH_LABEL, SUPERSET_REPO)
    app.run(host="0.0.0.0", port=port, debug=True)