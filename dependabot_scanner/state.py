"""Local JSON state file: idempotency ledger keyed per alert."""
import json
import os

from .config import STATE_FILE


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
