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

- Any open fix PR already covers the alert (Dependabot's bump, or a fix PR a
  prior scan opened) → **skip, don't duplicate in-flight work**
- Patch exists, low blast radius → **Devin session** (routine upgrade prompt)
- Sensitive package or cascade > `MAX_CASCADE` → **Devin reviewed-upgrade path**,
  PR labeled `rem:needs-careful-review`
- No patched version → **held**, reported, never silently dropped

One advisory can raise several alerts for the same package pinned in multiple
manifests; Rem keys a remediation by `repo#ghsa#package` (not manifest), so a
multi-manifest CVE dispatches **one** session that bumps the package repo-wide,
not one per file.

Severity **ranks the queue; it does not gate it**. If a patch exists, the
default policy is to take it — severity just decides who goes first.

**Lane 2 — Webhook orchestrator** (`app.py`): a Flask endpoint that receives
GitHub issue webhooks and walks seven ordered gates — HMAC signature, event
type, action whitelist, payload shape, routing label, dedup, dispatch. Webhook
delivery is at-least-once, so the handler is idempotent by construction.

**Reconcile loop** (`--reconcile`): drives every dispatched session to a
terminal state. Discovers the fix PR, reads its CI status when checks are configured
(on this fork, upstream CI can't run — see note below), nudges stuck sessions with a
follow-up message (bounded by `MAX_RETRIES`), then either verifies or
escalates with a tracking issue containing the full session log.

```
dispatched → pr_open → verified            (terminal: success)
          ↘ retrying / no_pr_stalled       (bounded nudges)
                     ↘ escalated           (terminal: human, tracking issue filed)
```

Rem **never merges PRs**. The human-merge gate is policy, not a TODO.

Fork scoping note: apache/superset's CI can't run on a fork (missing secrets, self-hosted runners), so it's disabled here and PRs verify to pr_open / awaiting review rather than a green-check verified. In a real engagement, the customer's pipeline is the verification authority — reconcile reads their check runs, not Devin's self-report.

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
- **Run-summary issues** — every scan and reconcile files one issue in this
  repo (label: `rem:run-summary`) with counts (dispatched / held / failed /
  verified / escalated) and one decision bullet per alert: what was dispatched
  and to whom, what was skipped and why, what was held at the cap. The Issues
  tab is the dashboard. Runs that do nothing file nothing.
- **Per-alert state** — `.dependabot_state.json` records every alert's lifecycle
  (`dispatched` → `pr_open` → `verified`/`escalated`) with session URLs. Re-runs
  are incremental: only net-new alerts spend Devin sessions.
- **Escalation issues** — when retries are exhausted, Rem files a tracking
  issue with the full Devin session log embedded, so the human picking it up
  starts with context instead of archaeology.
- **PR labels** — `rem:routine-bump` vs `rem:needs-careful-review` make triage
  legible at a glance in the PR list.
- **Externalized prompt templates** (`templates/*.md`) — tune Devin's wording
  per deployment without touching code.

## Architecture decisions

Every decision below is a deliberate policy choice, grouped by the two
properties the system optimizes for: **cost-efficiency** (spend the least
capable resource that can safely close a vuln) and **safety** (never make the
codebase worse, never drop a finding silently). Code pointers are to
`dependabot_scan.py` unless noted.

### Routing & cost-efficiency

- **Cheapest capable owner.** Dependabot (free) → Devin → human, in that order.
  Never spend a Devin session where Dependabot already works; never spend a
  human where Devin suffices. *(`should_dispatch`, and the Dependabot-dedup skip
  in the scan loop.)*
- **Don't duplicate work already in flight.** If an open PR already remediates
  the alert, skip it. A fix PR from a prior scan (matched by the advisory's GHSA
  id, any author) is skipped unconditionally; a Dependabot bump PR (matched by
  package name) is skipped *unless* the package is sensitive or the cascade check
  escalated it. *(`fetch_open_fix_prs` + `find_fix_pr` → the `not has_dep_pr` and
  `has_dep_pr and not review` skips.)*
- **Minimum-bump policy.** Prompts tell Devin to upgrade to **at least** the
  first patched version — and if the repo already constrains the package to a
  higher compatible version, use that instead, never downgrade another
  dependency to hit the target. Smallest change that closes the vuln, no
  opportunistic jumps to latest. *(`templates/routine_upgrade.md`,
  `templates/reviewed_upgrade.md`.)*
- **No security-justification-free version bumps.** Bumps cost review time, can
  introduce new vulnerabilities, and cause breakage. A vuln *with* a patch
  always gets fixed — by the cheapest owner. Hygiene bumps don't.
- **Ranks, not gates.** Severity orders the queue; it does not filter it.
  Suppressing low-severity alerts is a deployment choice (`SEVERITY_THRESHOLD`),
  not a default — the safest state for a patched vuln is patched. `MAX_DISPATCH`
  then caps sessions per run *after* ranking, so criticals are never held behind
  earlier low-severity alerts; the rest drain on later runs. *(`priority_key`,
  then `queue[:MAX_DISPATCH]`.)*
- **Direct-before-transitive tiebreak.** At equal severity, directly-declared
  dependencies rank ahead of transitive ones — a cheap proxy for exposure.
  *(`priority_key`.)*
- **Skip the unfixable and the irrelevant.** No published patch → held and
  reported (a bump can't fix it); development-only dependencies → skipped (they
  don't ship to production). *(`should_dispatch`.)*
- **One remediation per advisory + package.** State is keyed `repo#ghsa#package`,
  so the same CVE across multiple manifests collapses into a single Devin
  session instead of N duplicate ones. *(`state_key`, plus a per-run
  `queued_keys` guard.)*

### Safety

- **Cascade check via the GitHub dependency-graph compare API.** `--check`
  measures how many *other* packages a Dependabot bump actually moves
  (`base...head` on the resolved graph) rather than guessing. Cascades beyond
  `MAX_CASCADE` are escalated to the reviewed-upgrade path, not auto-applied.
  *(`cascade_package_count`.)*
- **Sensitive-package override.** High-blast-radius packages
  (`sensitive_packages.txt`) always get a *reviewed* upgrade and bypass the
  Dependabot-dedup skip — an insta-bump on these is too risky. *(`is_sensitive`.)*
- **Two working modes, chosen by policy.** `routine_upgrade.md` (bump → fix
  breakage → test → PR) for ordinary alerts; `reviewed_upgrade.md` (audit the
  blast radius → read the upstream changelog → adapt every call site → full test
  suite → `rem:needs-careful-review`) for sensitive or wide-cascade bumps. The
  sensitive/cascade decisions don't just flag an alert — they switch Devin into
  a fundamentally more careful mode.
- **Human-merge gate.** Rem prepares and verifies; a human always merges to
  mainline. Reconcile never merges — that's policy, not a TODO. Both upgrade
  paths require a human before merge; the reviewed path additionally forces a
  documented blast-radius + changelog review.
- **Every alert ends terminal.** The reconcile loop drives each dispatched
  alert to `verified` (PR + green CI) or `escalated` (retries exhausted →
  tracking issue with the full session log). Bounded by `MAX_RETRIES`. Nothing
  is silently dropped. *(`reconcile`, `_bump_retry_or_escalate`.)*

Every decision above is also visible in the run output and the Issues tab — see
[Observability](#observability) for the dashboard, per-alert state, escalation
issues, PR labels, and externalized prompt templates.

### Reliability & correctness

- **Idempotent everywhere.** At-least-once webhooks (`app.py` dedup gate),
  `idempotent: true` on Devin session creation, and stable per-remediation state
  keys (`repo#ghsa#package`) so re-runs never double-dispatch or double-fix.
- **`--dry-run` never mutates.** No sessions, comments, issues, or state
  writes — a safe preview of every decision.
- **Fail-loud config, fail-soft runtime.** Missing credentials abort up front
  (`require_config`); a single flaky dispatch or API call is isolated so it
  can't kill the run; every HTTP call has a timeout (`REQUEST_TIMEOUT`) so a
  hung endpoint can't stall the scan; a dispatch failure exits non-zero so a
  scheduler can alert.
- **Warnings deduped.** Transient/environmental warnings print once per run
  (`warn_once`) so they don't bury the actual decisions.
- **Seven ordered webhook gates.** `app.py` walks HMAC signature → event type →
  action whitelist → payload shape → routing label → dedup → dispatch, in that
  order, so untrusted input is rejected before any work happens.

## Roadmap

- Devin Review integration: catch vulnerable dependencies at PR time,
  before they ship
