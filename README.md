# Rem

Rem (short for **Rem**ediation) is an orchestration layer for automated dependency related
security remediation. It sits between vulnerability detection (Dependabot
alerts, GitHub issues) and execution (Dependabot, Devin, humans) and decides
which findings get fixed, in what order, and by whom.

Devin writes the patches and opens the PRs. Rem decides what Devin works on.

Built and demonstrated against a fork of
[apache/superset](https://github.com/maidang111/superset)

## Architecture

Two independent entry points feed the same idea — route each finding to the
cheapest owner that can actually fix it:

```
                        ┌──────────────────────────────┐
Dependabot alerts ────► │  dependabot_scan.py          │──► Devin session ──► fix PR
(scheduled scan)        │  categorize → rank → route   │──► delegate to Dependabot
                        │                              │──► hold + report
GitHub issues     ────► │  app.py (Flask webhook)      │──► escalate to human
(labeled "Remediate")   │  7 ordered gates → dispatch  │
                        └──────────────┬───────────────┘
                                       │
                            .dependabot_state.json
                          (per-alert lifecycle state)
```

### Lane 1 — Dependabot alert scanner (`dependabot_scan.py`)

A run-once script (cron/Actions-friendly). Each run:

1. Fetches all open Dependabot alerts for `SCAN_REPO` and extracts the
   decision-relevant fields: severity, patched version, scope
   (runtime/development), dependency relationship (direct/transitive),
   manifest path.
2. Applies the routing rules below, in order. The first match wins.
3. Ranks whatever routed to Devin (severity first, direct deps before
   transitive) and dispatches up to `MAX_DISPATCH` sessions. The rest print
   as `HOLD` and drain on subsequent runs.

Routing rules, in the order the code applies them:

| # | Condition | Outcome |
|---|-----------|---------|
| 1 | No patched version exists | **HELD** — reported for human review, never silently dropped |
| 2 | Dev-only dependency, or below `SEVERITY_THRESHOLD` | **SKIP** |
| 3 | An open fix PR already covers the advisory (matched by GHSA id, *any author* — a prior scan's `devin/…` PR or a human's) | **SKIP** — don't duplicate in-flight work |
| 4 | Package is in `sensitive_packages.txt`, or (with `--check`) the bump cascades to more than `MAX_CASCADE` other packages | **Devin, reviewed-upgrade prompt** — PR labeled `rem:needs-careful-review`; applies even when Dependabot already has a PR open |
| 5 | Dependabot already has an open PR for the package | **SKIP** — Dependabot owns it |
| 6 | Dependabot is *capable* of the fix (see below) | **DELEGATED** to Dependabot, with a deadline |
| 7 | Everything else with a patch | **Devin, routine-upgrade prompt** — PR labeled `rem:routine-bump` |

**Predictive delegation (rule 6).** Rule 5 is reactive — it only fires if
Dependabot has already opened a PR. Rule 6 routes on capability instead:
`dependabot_capable()` returns true when the dependency is verifiably direct
(the API's `relationship` field, or a top-level pin found in the manifest)
and the patched version stays within the installed major (read from the
manifest pin, falling back to the vulnerable range's lower bound). Anything
it can't verify falls through to Devin, and the reason is printed either
way.

A delegation is a prediction, so it gets a deadline: if Dependabot's PR
hasn't appeared within `DEPENDABOT_WAIT_HOURS`, the reconcile pass dispatches
the alert to Devin. If the PR appears but its CI goes red — the bump alone
broke something — it is also promoted to Devin, since that is now a code
migration, not a version edit.
```
delegated  → dependabot_pr_open → verified          (Dependabot PR, CI green)
          ↘ deadline passed / PR red → dispatched   (promoted to Devin)

dispatched → pr_open → verified                     (Devin PR, CI green)
          ↘ retrying / no_pr_stalled                (nudged, bounded by MAX_RETRIES)
                     ↘ escalated                    (tracking issue filed, human takes over)
```

**Reconcile (`--reconcile`).** Drives every non-terminal entry one step:
discovers fix PRs, checks their CI, nudges stuck Devin sessions with a
follow-up message (at most `MAX_RETRIES` times), promotes overdue
delegations, and escalates exhausted retries by filing a tracking issue with
the full Devin session log embedded. CI is the verification authority
throughout — a session claiming success is never marked `verified` until the
PR's checks are green. Rem never merges PRs; merging is a human decision by
design.

### Lane 2 — Issue webhook orchestrator (`app.py`)

A Flask service exposing `POST /webhook` (plus `GET /` and `GET /health`).
It receives GitHub issue webhooks and walks seven ordered gates:

1. **Signature** — HMAC-SHA256 (`X-Hub-Signature-256`) against
   `WEBHOOK_SECRET`; missing or invalid → 401.
2. **Event type** — only `issues` events proceed.
3. **Action** — only `opened` and `labeled`.
4. **Payload shape** — must contain an issue object.
5. **Routing label** — only issues labeled `Remediate` dispatch; everything
   else is logged and returned as non-agent.
6. **Dedup** — webhook delivery is at-least-once; an issue that already has
   a session is dropped as a duplicate. (Dedup is in-memory per process;
   a persistent registry is on the roadmap.)
7. **Dispatch** — a Devin session is created (`idempotent: true`) from the
   issue's title/body/URL and the session id is recorded.

## Design principles

The decisions the routing and lifecycle above are built on:

- **Cheapest capable owner.** Route each finding to the cheapest owner that
  can actually fix it — Dependabot (free) → Devin → human. Never spend a Devin
  session where Dependabot works; never spend a human where Devin suffices.
- **Capability, not activity.** Delegate to Dependabot on whether it *could*
  fix an alert (direct dependency, in-major patch, no cascade), predictively —
  not on whether it has already opened a PR.
- **Bounded delegation, never rots.** A delegation is a prediction, so it
  carries a `DEPENDABOT_WAIT_HOURS` deadline; if the predicted PR never appears
  (or its CI goes red), the reconcile pass promotes the alert to Devin.
- **Sensitivity and cascade outrank capability.** A sensitive or
  cascade-escalated package always gets a reviewed Devin upgrade — it is never
  delegated to Dependabot or skipped as "Dependabot's", even for a trivial bump.
- **Don't duplicate in-flight work.** An advisory already covered by an open
  fix PR (any author, matched by GHSA id) is skipped rather than re-dispatched.
- **Minimum bump, security-justified only.** Upgrade to the *first* patched
  version (or an existing higher constraint), never downgrade a sibling, no
  opportunistic jumps to latest — and only vulnerabilities *with* a patch get
  fixed; hygiene bumps don't.
- **Major bumps are Devin's lane.** A cross-major patch implies possible API
  removals — code migration, not a version-number edit Dependabot can make.
- **Ranks, not gates.** If a patch exists the default is to take it;
  `SEVERITY_THRESHOLD` is a deployment knob and severity only *orders* the
  queue (capped by `MAX_DISPATCH`), it doesn't filter it.
- **Verification is never self-report.** CI is the authority on Devin's fixes
  and the reconcile loop on Dependabot's follow-through; no owner is trusted on
  its word, and Rem never merges — merging is a human decision by design.
- **Conservative on unknowns.** An unreadable manifest, unparsable
  version/range, or unknown dependency relationship falls through to Devin
  rather than being silently dropped or wrongly delegated.
- **Fail-open on infra, fail-toward-action on ambiguity.** A failed PR or
  cascade fetch degrades dedup but never blocks a scan; an unparsable
  delegation timestamp promotes to Devin rather than stalling.
- **Idempotent, state-tracked runs.** Each remediation is keyed
  `repo#ghsa_id#package` (manifest-independent, so one advisory across several
  manifests collapses into one session), and re-runs only consider net-new
  alerts.

## Setup

The two lanes are independent — you can activate one without the other. Both
run from the same Docker image and the same `.env`.

### 1. Build the image

Install [Docker](https://docs.docker.com/get-docker/) (Docker Desktop on
Mac/Windows, `docker` + the compose plugin on Linux), then:

```bash
unzip Rem.zip && cd Rem
cp .env.example .env   # fill in DEVIN_API_KEY, GITHUB_TOKEN, WEBHOOK_SECRET
docker build -t rem .
```

Both lanes ship in this single image — build once, then run either the
webhook server or the scanner from it. The GitHub token needs Dependabot
alerts (read), contents (read), pull requests (read), and issues (write, for
tracking/summary issues).

Prefer running without Docker? A local venv works too:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Lane 1 — the scanner (`dependabot_scan.py`)

There are two ways to run the scanner. It's a run-once script, not a server —
each invocation scans, decides, dispatches, and exits.

**Option A — GitHub Actions (no infrastructure).** The workflow lives at
`.github/workflows/dependabot-scan.yml` and runs weekday mornings
(`cron: '0 13 * * 1-5'`, UTC). It also allows `workflow_dispatch`, so you can
trigger a run on demand from the **Actions** tab — pick the workflow and hit
**Run workflow**. To activate it:

1. Add two repository secrets under **Settings → Secrets and variables →
   Actions**: `DEPENDABOT_SCAN_TOKEN` (a PAT with `security_events`/`repo`
   scope — the built-in `GITHUB_TOKEN` can't read another repo's alerts) and
   `DEVIN_API_KEY`.
2. Make sure Actions is enabled for the repo. Edit the `cron:` line to change
   cadence.

**Option B — run it yourself.** `SCAN_REPO` in `.env` picks the repo it scans:

```bash
docker compose run --rm scanner --dry-run    # categorize + decide, touch nothing
docker compose run --rm scanner              # dispatch/delegate (up to MAX_DISPATCH)
docker compose run --rm scanner --reconcile  # advance all state entries one step
```

Or directly, with the venv activated:

```bash
python dependabot_scan.py --dry-run
python dependabot_scan.py
python dependabot_scan.py --check            # also compute upgrade cascades
python dependabot_scan.py --reconcile
python dependabot_scan.py --force GHSA-...   # re-dispatch a specific alert
python dependabot_scan.py --reset            # clear state; reconsider every alert
```

Always start with `--dry-run` and read the decision ledger before a real run.
The compose `scanner` service mounts `.dependabot_state.json` from the host so
per-alert state persists across one-shot runs.

### 3. Lane 2 — the issue webhook (`app.py`)

The webhook lane **is** a long-running server that GitHub pushes events to.
Activating it is two steps: start the server, then register the webhook on
every repo that should feed it.

**Start the server:**

```bash
docker run --rm -p 5000:5000 --env-file .env rem   # gunicorn on :5000
# or, with compose:
docker compose up webhook
# or, without Docker:
./run.sh                 # creates .venv, installs deps, copies .env, starts :5000
```

`GET /health` returns `{"status":"healthy"}` if the server is up.

**Register the webhook on a target repo.** GitHub needs a public URL to call.
Locally, expose the port with a tunnel:

```bash
ngrok http 5000          # gives you a public https URL
```

Then, in each repo you want Rem to watch: **Settings → Webhooks → Add
webhook** —

- **Payload URL:** `<public-url>/webhook`
- **Content type:** `application/json`
- **Secret:** the same value as `WEBHOOK_SECRET` in `.env`
- **Events:** "Let me select individual events" → **Issues**

Once registered, label any issue `Remediate` and the orchestrator dispatches a Devin session.

## Configuration

All via environment variables (see `.env.example`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `DEVIN_API_KEY` | — | Devin API auth (required) |
| `GITHUB_TOKEN` | — | GitHub API auth (required) |
| `WEBHOOK_SECRET` | — | HMAC secret for webhook signature verification |
| `SCAN_REPO` | `maidang111/superset` | Repo the scanner reads alerts from |
| `SUPERSET_REPO` | `maidang111/superset` | Repo the webhook lane targets |
| `SUMMARY_REPO` | `maidang111/Rem` | Where run-summary issues are filed |
| `SEVERITY_THRESHOLD` | `low` | Minimum severity to dispatch (ranking still applies above it) |
| `MAX_DISPATCH` | `5` | Devin sessions per scan run |
| `MAX_CASCADE` | `2` | Cascade size that escalates a bump to careful review |
| `SENSITIVE_PACKAGES_FILE` | `sensitive_packages.txt` | High-blast-radius packages that always get a reviewed upgrade |
| `SENSITIVE_PACKAGES` | (empty) | Comma-separated extras on top of the file |
| `DEPENDABOT_WAIT_HOURS` | `24` | Deadline for a delegated alert's Dependabot PR before promotion to Devin |
| `MAX_RETRIES` | `2` | Nudges for a stuck session before escalation |
| `DEPENDABOT_STATE_FILE` | `.dependabot_state.json` | State file location |
| `REQUEST_TIMEOUT` | `30` | HTTP timeout (seconds) for GitHub/Devin calls |
| `PORT` | `5000` | Webhook server port |
| `PROMPT_TEMPLATE_DIR` | `templates/` | Directory holding the Devin prompt templates |

Devin prompts live in `templates/` as plain Markdown with `{placeholders}`
(`routine_upgrade.md`, `reviewed_upgrade.md`, `vulnerability_details.md` for
the scanner; `remediation.md` for the webhook lane), so policy wording can be
tuned without touching code.

## Observability

- **Decision ledger** — every scan prints one line per alert with the lane it
  took and why (`DELEG`, `DISPATCH`, `SKIP`, `HELD`, `HOLD`), and each Devin
  dispatch carries the reason it wasn't delegable.
- **Run-summary issues** — each scan/reconcile run that did anything files an
  issue in `SUMMARY_REPO` (label `rem:run-summary`) with the counts
  (dispatched / delegated / held / failed) and the full decision list.
- **Per-alert state** — `.dependabot_state.json` records each alert's current
  status, session URL, PR URL, CI result, retry count, and timestamps.
- **Escalation issues** — when retries are exhausted, a tracking issue is
  filed with the failed session's log embedded, so the human picking it up
  starts with context.
- **PR labels** — `rem:routine-bump` vs `rem:needs-careful-review` for
  at-a-glance triage in the PR list.
