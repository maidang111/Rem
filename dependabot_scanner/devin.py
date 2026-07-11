"""Devin API client: dispatch sessions, poll them, and post follow-up messages."""
import json

import requests

from .config import DEVIN_API, DEVIN_API_KEY, REQUEST_TIMEOUT


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
