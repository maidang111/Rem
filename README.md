# Rem

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

Detection tools also stop at detection. A wall of unprioritized bump PRs is
noise teams learn to ignore; every vulnerability is treated identically
regardless of blast radius; and remediation guidance ends at "update to
version X" — useless when the fix requires migrating the code that calls it.

The missing layer is triage and routing: deciding that this alert is a free
Dependabot bump, that one is worth a Devin session, and this third one touches
a high-blast-radius package and needs human review. That logic is
deployment-specific — it never ships in the box. Rem is that layer, built
as a working system against a real repo with real CVEs.

## How it works

Two event-driven lanes, one policy brain:

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
                        (per-alert lifecycle, idempotent re-runs)
```

**Lane 1 — Dependabot scanner** (`dependabot_scan.py`): pulls open Dependabot
alerts, categorizes each (severity, scope, patched version, sensitivity,
dependency relationship), ranks the queue, and routes every alert to its
**cheapest capable owner**:

- No patched version → **held**, reported, never silently dropped
- Sensitive package or cascade > `MAX_CASCADE` → **Devin reviewed-upgrade
  path**, PR labeled `rem:needs-careful-review` — even when Dependabot
  already opened a PR
- Dependabot already has a PR → **skip, Dependabot owns it** — that fix is free
- Dependabot *capable* (direct dependency, in-major patched version, no
  cascade) → **delegated to Dependabot**, even if its PR doesn't exist yet
- Everything else with a patch → **Devin session** (routine upgrade prompt)

The delegation is **predictive, not reactive**. In real deployments Dependabot
batches, queues, and hits open-PR limits — "enabled" doesn't mean "caught up."
Rem routes to Dependabot based on what Dependabot *can* fix (a direct
dependency, a patch within the current major, no downstream cascade), not on
whether it has acted yet. And the prediction is verified, not trusted: if a
delegated alert has no Dependabot PR after `DEPENDABOT_WAIT_HOURS`, the
reconcile loop promotes it to a Devin session. Free labor gets a deadline.

Severity **ranks the queue; it does not gate it**. If a patch exists, the
default policy is to take it — severity just decides who goes first.

**Lane 2 — Webhook orchestrator** (`app.py`): a Flask endpoint that receives
GitHub issue webhooks and walks seven ordered gates — HMAC signature, event
type, action whitelist, payload shape, routing label, dedup, dispatch. Webhook
delivery is at-least-once, so the handler is idempotent by construction.

**Reconcile loop** (`--reconcile`): drives every alert to a terminal state.
Discovers fix PRs (Devin's and Dependabot's), checks CI, nudges stuck Devin
sessions with a follow-up message (bounded by `MAX_RETRIES`), promotes
overdue delegations, then either verifies or escalates with a tracking issue
containing the full session log.

```
delegated  → dependabot_pr_open → verified     (terminal: success, cost: $0)
          ↘ wait exhausted → dispatched        (promoted to Devin)

dispatched → pr_open → verified                (terminal: success)
          ↘ retrying / no_pr_stalled           (bounded nudges)
                     ↘ escalated               (terminal: human, tracking issue filed)
```

Rem **never merges PRs**. The human-merge gate is policy, not a TODO.

## Policy is configuration

The knobs an FDE would tune per deployment, not per rewrite:

| Knob                      | Default                  | What it controls                                                                                          |
| ------------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `SEVERITY_THRESHOLD`      | `low`                    | Minimum severity to dispatch (ranking still applies above it)                                              |
| `MAX_DISPATCH`            | `5`                      | Devin sessions per run — budgets session cost *and* human PR-review bandwidth                               |
| `MAX_CASCADE`             | `2`                      | If a bump forces changes in more than N other packages, route to careful review                             |
| `SENSITIVE_PACKAGES_FILE` | `sensitive_packages.txt` | High-blast-radius packages that always get a reviewed upgrade — even when Dependabot already opened a PR    |
| `DEPENDABOT_WAIT_HOURS`   | `24`                     | How long a delegated alert waits for Dependabot's PR before being promoted to a Devin session               |
| `MAX_RETRIES`             | `2`                      | Nudges for a stuck session before escalating to a human                                                     |

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
python dependabot_scan.py                  # dispatch/delegate up to MAX_DISPATCH
python dependabot_scan.py --check          # also compute upgrade cascades before routing
python dependabot_scan.py --reconcile      # drive alerts to terminal states
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

If I were an engineering leader, how would I know this is working?

- **Per-alert state** — `.dependabot_state.json` records every alert's
  lifecycle (`delegated`/`dispatched` → `pr_open` → `verified`/`escalated`)
  with session URLs. Re-runs are incremental: only net-new alerts spend Devin
  sessions.
- **Run summaries** — every scan and reconcile prints its ledger:
  delegated / dispatched / held / verified / escalated counts. The
  delegated-vs-dispatched split is the cost story: how much remediation
  happened for free.
- **Escalation issues** — when retries are exhausted, Rem files a tracking
  issue with the full Devin session log embedded, so the human picking it up
  starts with context instead of archaeology.
- **PR labels** — `rem:routine-bump` vs `rem:needs-careful-review` make triage
  legible at a glance in the PR list.

## Demo case: paramiko

The centerpiece alert in the Superset fork: paramiko 3.x removed `DSSKey`,
which breaks `sshtunnel` — a real CVE with a real cascade. It fails every
delegation check (major-version bump, cascade, sensitive), so Rem routes it
through the reviewed-upgrade path and Devin ships the fix PR — API migration
included — with the session log attached. This is the lane that justifies an
autonomous coding agent: Dependabot can bump a version number; it cannot
migrate the code that depended on the removed API.

## Design decisions

- **Cheapest capable owner.** Never spend a Devin session where Dependabot
  works for free; never spend a human where Devin suffices.
- **Capability, not activity.** Delegation to Dependabot is based on what it
  can fix (direct dep, in-major patch, no cascade), not on whether it has
  opened a PR yet — with a bounded wait and automatic promotion when the
  prediction misses.
- **Verification is never self-report.** CI is the authority on Devin's
  fixes; the reconcile loop is the authority on Dependabot's follow-through.
  No owner in the routing table is trusted on its word.
- **No security-justification-free version bumps.** Bumps cost review time,
  can introduce new vulnerabilities, and cause breakage. A vuln *with* a patch
  always gets fixed — by the cheapest owner. Hygiene bumps don't.
- **Ranks, not gates.** Suppressing low-severity alerts is a deployment choice
  (`SEVERITY_THRESHOLD`), not a default. The safest state for a patched vuln
  is patched.
- **Idempotent everywhere.** At-least-once webhooks, `idempotent: true` on
  session creation, stable per-alert state keys (`repo#ghsa#package#manifest`).

## Roadmap

- Docker packaging for one-command deployment
- Run summary filed as a GitHub issue per scan (dashboard-in-an-issue)
- Exploitability signals (e.g. EPSS) as a ranking input alongside severity
- Devin Review integration: catch vulnerable dependencies at PR time,
  before they ship
