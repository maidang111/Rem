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
4. **Prioritize** via `priority()`: dispatch order is sorted by severity
   (critical → low), then runtime-before-dev at equal severity, so the most
   important alerts win the `MAX_DISPATCH` budget.
5. **Dispatch** the selected alerts to Devin with a structured prompt; the session
   performs the upgrade, fixes any breakage, runs tests, and opens the PR.
6. **Idempotency:** every dispatched alert is recorded in
   `DEPENDABOT_STATE_FILE` (keyed by GHSA id), so re-running never double-dispatches.

### Configuration (in `.env`)

- `SCAN_REPO` — repo to scan (default `maidang111/superset`)
- `MAX_DISPATCH` — safety cap on sessions opened per run, highest-severity first (default `5`)
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
```

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
