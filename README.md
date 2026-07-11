# Redress

**An agent harness for security remediation.** Rem sits between vulnerability
detection (Dependabot alerts, GitHub issues) and execution (Devin, Dependabot,
humans), and makes the decision every enterprise makes differently: *which
findings get fixed, in what order, by whom, under whose policy.*

Devin writes the patches and opens the PRs. Rem decides what Devin works on.

> Repo is `Rem`, short for Remediation. Built against a fork of
> [apache/superset](https://github.com/maidang111/superset) as the target codebase.

## The problem

Detection is solved and getting cheaper — Dependabot, Devin Review, Security
Swarm. Remediation capacity is not. Findings pile up faster than engineering
time appears, SLA clocks start the moment an alert lands, and every open
critical CVE is time attackers get for free.

The missing layer is triage and routing: deciding that this alert is a free
Dependabot bump, that one is worth a Devin session, and this third one touches
a high-blast-radius package and needs human review. That logic is
deployment-specific — it never ships in the box. Rem is that layer, built
as a working system against a real repo with real CVEs.

## How it works

Two event-driven lanes, one policy brain:

```
                          ┌──────────────────────────────┐
  Dependabot alerts ────► │  dependabot_scan.py          │
  (scheduled scan)        │  categorize → rank → route   │──► Devin session ──► fix PR
                          │                              │──► leave to Dependabot
  GitHub issues     ────► │  app.py (Flask webhook)      │──► escalate to human
  (labeled "Remediate")   │  7 ordered gates → dispatch  │
                          └──────────────┬───────────────┘
                                         │
                              .dependabot_state.json
                          (per-alert lifecycle, idempotent re-runs)
```

**Lane 1 — Dependabot scanner** (`dependabot_scan.py`): pulls open Dependabot
alerts, categorizes each (severity, scope, patched version, sensitivity),
ranks the queue, and routes every alert to its **cheapest capable owner**:

- Trivial bump Dependabot already has a PR for → **skip, Dependabot owns it**
- Patch exists, low blast radius → **Devin session** (routine upgrade prompt)
- Sensitive package or cascade > `MAX_CASCADE` → **Devin reviewed-upgrade path**,
  PR labeled `rem:needs-careful-review`
- No patched version → **held**, reported, never silently dropped

Severity **ranks the queue; it does not gate it**. If a patch exists, the
default policy is to take it — severity just decides who goes first.

**Lane 2 — Webhook orchestrator** (`app.py`): a Flask endpoint that receives
GitHub issue webhooks and walks seven ordered gates — HMAC signature, event
type, action whitelist, payload shape, routing label, dedup, dispatch. Webhook
delivery is at-least-once, so the handler is idempotent by construction.

**Reconcile loop** (`--reconcile`): drives every dispatched session to a
terminal state. Discovers the fix PR, checks CI, nudges stuck sessions with a
follow-up message (bounded by `MAX_RETRIES`), then either verifies or
escalates with a tracking issue containing the full session log.

```
dispatched → pr_open → verified            (terminal: success)
          ↘ retrying / no_pr_stalled       (bounded nudges)
                     ↘ escalated           (terminal: human, tracking issue filed)
```

Rem **never merges PRs**. The human-merge gate is policy, not a TODO.

## Policy is configuration

The knobs an FDE would tune per deployment, not per rewrite:

| Knob | Default | What it controls |
|---|---|---|
| `SEVERITY_THRESHOLD` | `low` | Minimum severity to dispatch (ranking still applies above it) |
| `MAX_DISPATCH` | `5` | Devin sessions per run — budgets session cost *and* human PR-review bandwidth |
| `MAX_CASCADE` | `2` | If a bump forces changes in more than N other packages, route to careful review |
| `SENSITIVE_PACKAGES_FILE` | `sensitive_packages.txt` | High-blast-radius packages that always get a reviewed upgrade — even when Dependabot already opened a PR |
| `MAX_RETRIES` | `2` | Nudges for a stuck session before escalating to a human |

## Quickstart

```bash
git clone https://github.com/maidang111/Rem.git && cd Rem
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add DEVIN_API_KEY, GITHUB_TOKEN, WEBHOOK_SECRET
```

**Scanner (Dependabot lane):**

```bash
python dependabot_scan.py --dry-run        # categorize + decide, touch nothing
python dependabot_scan.py                  # dispatch up to MAX_DISPATCH sessions
python dependabot_scan.py --check          # also compute upgrade cascades before routing
python dependabot_scan.py --reconcile      # drive dispatched sessions to terminal states
python dependabot_scan.py --force GHSA-... # re-dispatch a specific alert
python dependabot_scan.py --reset          # clear state; reconsider every open alert
```

**Webhook (issue lane):**

```bash
python app.py                              # starts on :5000
ngrok http 5000                            # point the GitHub webhook at /webhook
```

Label an issue `Remediate` and the orchestrator dispatches it.

## Observability

*"If I were an engineering leader, how would I know this is working?"*

- **Per-alert state** — `.dependabot_state.json` records every alert's lifecycle
  (`dispatched` → `pr_open` → `verified`/`escalated`) with session URLs. Re-runs
  are incremental: only net-new alerts spend Devin sessions.
- **Run summaries** — every scan and reconcile prints its ledger:
  dispatched / held / verified / escalated counts.
- **Escalation issues** — when retries are exhausted, Rem files a tracking
  issue with the full Devin session log embedded, so the human picking it up
  starts with context instead of archaeology.
- **PR labels** — `rem:routine-bump` vs `rem:needs-careful-review` make triage
  legible at a glance in the PR list.

## Demo case: paramiko

The centerpiece alert in the Superset fork: paramiko 3.x removed `DSSKey`,
which breaks `sshtunnel` — a real CVE with a real cascade. Rem categorizes
it, `--check` computes the cascade, routes it through the reviewed-upgrade
path, and Devin ships the fix PR with the session log attached.

## Design decisions

- **Cheapest capable owner.** Never spend a Devin session where Dependabot
  works for free; never spend a human where Devin suffices.
- **No security-justification-free version bumps.** Bumps cost review time,
  can introduce new vulnerabilities, and cause breakage. A vuln *with* a patch
  always gets fixed — by the cheapest owner. Hygiene bumps don't.
- **Ranks, not gates.** Suppressing low-severity alerts is a deployment choice
  (`SEVERITY_THRESHOLD`), not a default. The safest state for a patched vuln
  is patched.
- **Idempotent everywhere.** At-least-once webhooks, `idempotent: true` on
  session creation, stable per-alert state keys (`repo#ghsa#package#manifest`).

## Roadmap

- GitHub Actions `schedule` + `workflow_dispatch` trigger for the scanner
- Run summary filed as a GitHub issue per scan (dashboard-in-an-issue)
- SQLite-backed state for the webhook dedup registry
- Devin Review integration: catch vulnerable dependencies at PR time,
  before they ship
