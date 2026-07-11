"""Render Devin prompts from the templates/ directory."""
from .config import (
    LABEL_REVIEW,
    LABEL_ROUTINE,
    MAX_CASCADE,
    TEMPLATE_DIR,
)


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
