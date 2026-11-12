# Product scope — evidence, trials, AI facts, questionnaires
2026-09-19 · updated 2026-10-11

ServiceNow keeps the ticket. This app fills the ticket.
Order of work: [docs/DESIGN_QUEUE.md](DESIGN_QUEUE.md) (the roadmap).

## Objects

### Vendor
Already exists: factors, inherent/residual, AI controls, human gate.

Add:
- engagement_stage: inquiry | trial_30 | trial_60 | trial_90 | contracted | offboard
- trial_started_on, trial_ends_on
- product_description (one paragraph the analyst writes)
- ai_factsheet (structured)

### Evidence item
One row per document or public claim.
- type: soc2 | iso27001 | pentest | ai_redteam | dpa | baa | trust_center | subprocessors | architecture | other
- received_on, period_start, period_end
- expires_on (alert 90/60/30 then expired)
- status: current | expiring_60 | expired | missing
- source_rank 1–7
- storage: local path or object key — never commit customer files to git
- extract: JSON the model pulled
- hash + filename

### AI factsheet
Each field is Known / Unknown / Evidence id. Unknown is not No.
- trains_on_customer_content
- training_default off|on
- model_providers / regions
- subprocessors_inference
- silent_model_swap
- agent_write_actions
- prompt_injection_surface
- retention_prompts_days
- log_access_on_incident
- source_evidence_ids

### Questionnaire pack (AI questionnaire, built 2026-09-28)
There is no static question list to write or version. The model reads the vendor's
published security, trust and privacy pages, works out the engagement type (SaaS,
device, on-site service, remote access to our systems), and asks only about gaps,
including requests for the documents the risk calls for. A missing document becomes a
flag at the severity the model set and the analyst confirmed. An analyst approves every
question. Model-agnostic (any OpenAI-compatible provider; Grok today).
See `docs/AI_QUESTIONNAIRE.md`.
Queued (DESIGN_QUEUE §5): also generate from gaps in evidence and AI factsheet Unknowns.
Pre-fill known answers. Only send blanks. Lock what we already have on the vendor portal.
Next: model review of answers and follow-up rounds; reading uploaded SOC 2 / pentest
reports and checking them against answers; maturity score by area.

### Live access (added 2026-09-27)
What the vendor actually holds in the environment, one row per app, role or token.
See `docs/ACCESS_MODULE.md`. Rules flag drift from the assessment; a human decides.
Shipped: file import of Entra, Okta and Google app exports (`access_import.py`), the shadow IT queue with Start tracking, and a declared vs observed panel on the vendor Integrations tab. Queued: Accept the risk from that panel. Live IdP API is not built; it waits until the file import has seen real use.

### Unregistered app (shipped as shadow IT, `/shadow`)
Not a vendor yet. Built from an organisation-wide connected-app export and a proxy domain list. Kinds: unknown app, vendor not authorized, approved vendor with the connection not recorded, shadow SaaS. Actions: Start tracking (creates a not-authorized vendor with the app as live access) or Mark as known (a note is required). See `docs/DATA_LAYER.md`.

### Integrations, environment, control objectives (added 2026-10-11 to this scope)
Every connection between your tenants, vendors and own systems, the systems you run, and 20 control objectives (16 on by default, plus an optional NERC CIP-013 pack) checked against the records. Rule-based; no model. A findings worklist at `/findings` joins them with shadow IT and vendor flags and can raise tickets in ServiceNow or Jira. A per-vendor threat model exports to Word and PDF. See `docs/INTEGRATIONS.md`, `docs/DATA_LAYER.md` and `docs/THREAT_MODEL.md`.

### Risk acceptance (added 2026-09-28)
A named approver accepts one flag on one vendor, for one org unit, until a date.
Tier thresholds: Low/Medium = director, High/Critical = VP or CISO. No permanent
acceptances; expired ones reopen the flag. Org units come from Entra ID departments.
See `docs/RISK_ACCEPTANCE.md`.
Per-person login with authenticator codes and OpenID Connect single sign-on is shipped (`ENTROPY_AUTH=accounts`). Next: expiry reminders, live Microsoft Graph sync.

## Trial clocks
Trial is time-boxed residual risk, not approval.
Day 0: inherent + questionnaire + missing evidence.
Day 30: T1 or AI-01/08/10 unknown → human extend or kill.
Day 60: SOC2/pentest still missing on T1/T2 → residual High.
Day 90: no signed residual → default reject for production data.
Agents remind. Agents do not extend T1 trials. The strip never auto-greens.

## v1 will not
Replace ServiceNow, clone SIG Core, treat SOC2 as a pass on AI-01, score or offboard with a model, revoke IdP grants from this app.
