# Rem

Rem (short for **Rem**ediation) is an orchestration layer for automated
security remediation. It sits between vulnerability detection (Dependabot
alerts, GitHub issues) and execution (Dependabot, Devin, humans) and decides
which findings get fixed, in what order, and by whom.

Devin writes the patches and opens the PRs. Rem decides what Devin works on.

Built and demonstrated against a fork of
[apache/superset](https://github.com/maidang111/superset), a real repo with
real open CVE alerts.

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
| 3 | Package is in `sensitive_packages.txt`, or (with `--check`) the bump cascades to more than `MAX_CASCADE` other packages | **Devin, reviewed-upgrade prompt** — PR labeled `rem:needs-careful-review`; applies even when Dependabot already has a PR open |
| 4 | Dependabot already has an open PR for the package | **SKIP** — Dependabot owns it |
| 5 | Dependabot is *capable* of the fix (see below) | **DELEGATED** to Dependabot, with a deadline |
| 6 | Everything else with a patch | **Devin, routine-upgrade prompt** — PR labeled `rem:routine-bump` |

Severity ranks the queue; it does not gate it. If a patch exists the default
is to take it — `SEVERITY_THRESHOLD` exists as a deployment knob, not a
default filter.

**Predictive delegation (rule 5).** Rule 4 is reactive — it only fires if
Dependabot has already opened a PR. Rule 5 routes on capability instead:
`dependabot_capable()` returns true when the dependency is verifiably direct
(the API's `relationship` field, or a top-level pin found in the manifest)
and the patched version stays within the installed major (read from the
manifest pin, falling back to the vulnerable range's lower bound). Anything
it can't verify falls through to Devin, and the reason is printed either
way — every routing decision in the ledger explains itself:

```
DELEG [high] Werkzeug (GHSA-...): in-major bump 3.0.1 → 3.0.3 (manifest pin), direct; ...
DISPATCH [high] gunicorn (GHSA-...) [major bump 22.x → 23.x — code migration is Devin's lane]
```

A delegation is a prediction, so it gets a deadline: if Dependabot's PR
hasn't appeared within `DEPENDABOT_WAIT_HOURS`, the reconcile pass dispatches
the alert to Devin. If the PR appears but its CI goes red — the bump alone
broke something — it is also promoted to Devin, since that is now a code
migration, not a version edit.

**State.** Every handled alert gets an entry in `.dependabot_state.json`,
keyed `repo#ghsa_id#package` (deliberately not per-manifest: one advisory can
raise alerts in several manifests, and one Devin session bumps the package
repo-wide). Re-runs are incremental — only net-new alerts are considered.

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

```bash
git clone https://github.com/maidang111/Rem.git && cd Rem
./run.sh          # creates .venv, installs deps, copies .env.example → .env,
                  # and starts the webhook server on :5000
```

Or manually:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in DEVIN_API_KEY, GITHUB_TOKEN, WEBHOOK_SECRET
```

The GitHub token needs Dependabot alerts (read), contents (read), pull
requests (read), and issues (write, for tracking/summary issues).

### Scanner usage

```bash
python dependabot_scan.py --dry-run        # categorize + decide, touch nothing
python dependabot_scan.py                  # dispatch/delegate (up to MAX_DISPATCH sessions)
python dependabot_scan.py --check          # also compute upgrade cascades where a
                                           # Dependabot PR exists to diff against
python dependabot_scan.py --reconcile      # advance all state entries one step
python dependabot_scan.py --force GHSA-... # re-dispatch a specific alert
python dependabot_scan.py --reset          # clear state; reconsider every open alert
```

Always start with `--dry-run` and read the decision ledger before a real run.

### Webhook usage

```bash
python app.py            # starts on :5000 (PORT to override)
ngrok http 5000          # point the repo's webhook at <ngrok-url>/webhook,
                         # content type application/json, secret = WEBHOOK_SECRET
```

Label an issue `Remediate` and the orchestrator dispatches it.

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

## Known limitations / roadmap

- Webhook dedup is in-memory; restarting the server forgets dispatched
  issues. SQLite-backed registry planned.
- Cascade computation (`--check`) requires an existing Dependabot PR to diff
  against, so cascade checks don't run for alerts Dependabot hasn't touched.
- Manifest parsing for delegation covers pip-style pins (`pkg==x.y.z`) and
  `package.json` entries; other lockfile formats fall back to the vulnerable
  range's lower bound or route to Devin.
- Docker packaging planned.
- Exploitability signals (e.g. EPSS) as a ranking input alongside severity.
- Devin Review integration to catch vulnerable dependencies at PR time.
