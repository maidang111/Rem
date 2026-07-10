# Remedy - Automated Issue Fixing with Devin AI

A lightweight webhook server that listens for GitHub issues created in the Superset repository, uses Devin AI to generate fixes, and creates pull requests in the Remedy repository.

## Architecture

1. **Webhook Server**: Flask-based server that receives GitHub issue webhooks
2. **Context Extraction**: Extracts issue title, body, labels, and metadata
3. **Devin AI Integration**: Creates a Devin session to analyze and fix the issue
4. **PR Creation**: Automatically creates a PR in the Remedy repository with the fix

## Setup

### Prerequisites

- Python 3.8+
- GitHub Personal Access Token
- Devin API Key
- ngrok (for local testing)

### Installation

1. Clone the repository:
```bash
cd /Users/Lock-In/Cognition/Remedy
```

2. Create a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
```

### GitHub Token Setup

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate a new token with `repo` scope (needed to create PRs)
3. Add the token to your `.env` file

### Webhook Secret Setup (Optional but Recommended)

1. Generate a random secret:
```bash
openssl rand -hex 32
```

2. Add it to your `.env` as `WEBHOOK_SECRET`

## Running the Server

### Local Development

1. Start the server:
```bash
python app.py
```

2. Expose the server to the internet using ngrok:
```bash
ngrok http 5000
```

3. Copy the ngrok URL (e.g., `https://abc123.ngrok.io`)

### Setting Up GitHub Webhook

1. Go to your Superset repository on GitHub
2. Navigate to Settings → Webhooks → Add webhook
3. Configure:
   - **Payload URL**: `https://your-ngrok-url.ngrok.io/webhook`
   - **Content type**: `application/json`
   - **Secret**: (optional) Use the same value as `WEBHOOK_SECRET` in `.env`
   - **Events**: Select "Issues" only
4. Click "Add webhook"

## How It Works

1. When an issue is created in the Superset repository, GitHub sends a webhook to the server
2. The server verifies the webhook signature (if secret is configured)
3. Issue context is extracted (title, body, labels, URL, etc.)
4. A Devin AI session is created with a prompt to fix the issue
5. The server polls the Devin session until completion
6. A PR is created in the Remedy repository with the generated fix

## API Endpoints

- `POST /webhook` - Receives GitHub issue webhooks
- `GET /health` - Health check endpoint

## Dependabot Alert Scanner (`dependabot_scan.py`)

A separate, run-once script that scans a repository's **open Dependabot security
alerts**, categorizes them, and dispatches the ones worth fixing to Devin. Each
dispatched Devin session opens the fix PR in the affected repository itself
(where the vulnerable manifest lives).

### Flow

1. Fetch open alerts via `GET /repos/{repo}/dependabot/alerts?state=open`.
2. **Categorize** each alert by severity, whether a patched version exists, and
   dependency scope (runtime vs development).
3. **Decide** via `should_dispatch()`: severity is **not** a filter (a low-severity
   advisory on a widely-used dependency still matters, and a medium is often a
   trivial bump worth doing). Any alert that has a patched version is dispatched;
   only alerts with **no** patched version are skipped (a bump can't fix those).
4. **Dedup with Dependabot:** if Dependabot already has an open PR bumping the
   package, the alert is skipped (`SKIP … Dependabot already has an open PR`) so
   Devin doesn't duplicate the trivial fix — **unless** the package is
   policy-sensitive (see below).
5. **Sensitive packages:** packages listed in `SENSITIVE_PACKAGES` are treated as
   high-blast-radius. They are **never** skipped by the dedup step and are routed to
   a *reviewed* Devin upgrade (a careful-review prompt: audit call sites, read the
   changelog, adapt breakage, request human review — no auto-merge), even when a
   Dependabot PR exists:
   `DISPATCH [sensitive] sqlalchemy: Dependabot PR exists but package is policy-sensitive; routing to reviewed upgrade.`
6. **Prioritize** via `priority()`: dispatch order is sorted by severity
   (critical → low), then runtime-before-dev at equal severity, so the most
   important alerts win the `MAX_DISPATCH` budget.
7. **Dispatch** the selected alerts to Devin with a structured prompt; the session
   performs the upgrade, fixes any breakage, runs tests, and opens the PR. Each PR is
   labeled `rem:routine-bump` (clean minimal bump) or `rem:needs-careful-review`
   (sensitive package, cascade over `MAX_CASCADE`, or non-trivial breaking changes) so
   humans can triage at a glance.
8. **Idempotency:** every dispatched alert is recorded in
   `DEPENDABOT_STATE_FILE` (keyed by GHSA id), so re-running never double-dispatches.

### Prompt templates

The Devin prompt text is not hard-coded — it lives in `templates/` and is filled at
dispatch time via `build_prompt()`:

- `routine_upgrade.md` — clean minimal-bump prompt.
- `reviewed_upgrade.md` — careful-review prompt for sensitive / cascade-escalated alerts.
- `vulnerability_details.md` — the shared advisory block embedded in both.

Placeholders use `{name}` (e.g. `{package}`, `{patched_version}`, `{max_cascade}`,
`{label_review}`) and are substituted from the alert's fields plus policy config. Edit the
`.md` files to tune wording without touching code; point `PROMPT_TEMPLATE_DIR` elsewhere to
override the location.

### Configuration (in `.env`)

- `SCAN_REPO` — repo to scan (default `maidang111/superset`)
- `MAX_DISPATCH` — safety cap on sessions opened per run, highest-severity first (default `5`)
- `MAX_CASCADE` — if an upgrade cascades to more than this many other packages, Devin flags
  the PR for human review instead of auto-fixing (default `2`)
- `SENSITIVE_PACKAGES_FILE` — file listing high-blast-radius packages that always get a
  reviewed Devin upgrade and bypass the Dependabot-PR dedup (default `sensitive_packages.txt`;
  one package per line, `#` comments allowed, npm `@` scope optional)
- `SENSITIVE_PACKAGES` — optional comma-separated extras added on top of that file
- `DEPENDABOT_STATE_FILE` — path to the idempotency state file
- Also requires `GITHUB_TOKEN` (with `security_events`/`repo` scope) and `DEVIN_API_KEY`

### Usage

```bash
# Preview decisions without creating any Devin sessions
python dependabot_scan.py --dry-run

# Scan and dispatch
python dependabot_scan.py

# Override the repo for a single run
python dependabot_scan.py --repo owner/name

# Re-dispatch a specific alert even if it was already handled (e.g. its PR was closed).
# By GHSA id; repeatable or comma-separated.
python dependabot_scan.py --force GHSA-xxxx-yyyy-zzzz
python dependabot_scan.py --force GHSA-aaaa-bbbb-cccc,GHSA-dddd-eeee-ffff

# Clear all recorded state and reconsider every open alert
python dependabot_scan.py --reset

# Compute the upgrade cascade in the scanner (via the GitHub dependency-graph
# compare API) and escalate wide bumps to a reviewed upgrade
python dependabot_scan.py --check
```

`--check` measures the real transitive cascade of each Dependabot bump (comparing
the PR branch's dependency graph against the base) instead of leaving that to the
Devin session. If a bump forces changes to more than `MAX_CASCADE` other packages,
the alert is escalated to the careful-review path (`rem:needs-careful-review` label
+ review prompt) even if Dependabot already opened a PR. Cascade is only measurable
for alerts that have an open Dependabot PR (that branch is the compare head).

State is keyed by GHSA id in `DEPENDABOT_STATE_FILE`, so a handled alert is never
re-dispatched automatically — closing its PR does not trigger a new session. Use
`--force <ghsa>` to re-dispatch specific alerts, or `--reset` to start fresh.

## Reconciling dispatched sessions

Dispatch is fire-and-forget; `--reconcile` is the companion run-once pass that watches
each recorded session through to a terminal state:

```bash
python dependabot_scan.py --reconcile            # advance every recorded session
python dependabot_scan.py --reconcile --dry-run  # report only; no messages/issues/state writes
```

For each recorded alert it polls the Devin session, discovers the fix PR (preferring the
PR URL in the session output, falling back to searching the repo's PRs for the GHSA id —
the matched method is stored as `pr_discovery_method` for debugging), reads the PR's labels,
and aggregates its CI check-runs.

**In scope:** creating/nudging Devin sessions, posting session messages, applying labels,
filing tracking issues, and — when a fix fails (red CI, or a stalled session that did open
a PR) — attaching the failed session's log to the PR as a comment so a reviewer sees why.
**Out of scope:** merging PRs — the human-merge gate is deliberate policy, so reconcile
never touches mainline. (The log is de-duped per retry attempt to avoid spamming; on
escalation without a PR the log goes into the tracking issue instead.)

### State machine (every entry ends terminal)

```
dispatched ──PR found──> pr_open ──CI green──> verified        (terminal)
    │                        │
    │                        └──CI red──> retrying(n) ──n>MAX_RETRIES──> escalated (terminal)
    └──session finished, no PR──> no_pr_stalled ──n>MAX_RETRIES──> escalated (terminal)
```

`retrying`/`no_pr_stalled` nudge the session (a follow-up message) and are bounded by
`MAX_RETRIES` (default 2); once exhausted the alert is `escalated` — a tracking issue is
filed and it's left for a human. **Invariant:** every state entry eventually reaches a
terminal state (`verified` or `escalated`); the retry counter guarantees the loop closes.
This is enforced by an assertion at the end of the reconcile pass.
(`--dry-run` never writes or deletes state.)

Because it is run-once, schedule it however you like (cron, CI on a schedule,
`launchd`, etc.) — no long-running server required.

## Testing

1. Start the server and ngrok
2. Create a test issue in the Superset repository
3. Check the server logs for processing status
4. Verify the PR is created in the Remedy repository

## Limitations

This is a lightweight demo implementation. Known limitations:

- PR creation assumes the branch already exists (full implementation would create branches)
- Devin session polling has a 5-minute timeout
- No retry logic for failed API calls
- Minimal error handling
- No authentication on the webhook endpoint (relies on GitHub signature verification)

## Future Improvements

- Implement proper branch creation in GitHub
- Add retry logic and exponential backoff
- Improve error handling and logging
- Add support for issue comments and updates
- Implement session result extraction for actual code changes
- Add web UI for monitoring
- Support for multiple repositories
