# Data model

Everything lives under `ENTROPY_DATA_DIR` (default `./data`, gitignored). Only `records.py`, `tokens.py`, `audit.py`, `policy_store.py`, `evidence_store.py`, `risk_store.py`, `notes_store.py`, `accounts.py`, `integrations.py`, `environment.py`, `control_objectives.py`, `catalog.py`, `shadow.py`, `findings.py` and `ops.py` touch these files.

```
data/
  vendors/<slug>.json     one file per onboarded vendor
  evidence/<slug>/<id>_<filename>   uploaded reports (unless Blob storage is configured)
  tokens.json             vendor magic links (hashed)
  audit.log.imported      an older install's text audit log, after it was imported into riskprism.db (kept, no longer read)
  policy.json             this tenant's restricted models/regions (falls back to the repo policy.json)
  riskprism.db            SQLite: org_units, org_aliases, approvers, acceptances (risk_store.py); vendor_notes (notes_store.py); users (accounts.py); audit (audit.py)
  integrations.json       every integration between your tenants, vendors and own systems (integrations.py)
  environment.json        your environment: identity provider, tenants, clouds, data stores, setup answers (environment.py)
  objectives.json         company settings for control objectives: switched off, tiers, owners, own objectives, attestations (control_objectives.py)
  catalog.json            product profiles learned from confirmed integrations, and imported ones; absent until something is learned or imported (catalog.py)
  shadow.json             imported connected-app and domain exports, and decisions on shadow IT items (shadow.py)
  tickets.json            finding key to ticket number, from ServiceNow, Jira or entered by hand (findings.py)
  findings_state.json     first-seen and closed dates per finding key, and daily count snapshots (findings.py)
  ops_state.json          last backup, last digest and their errors (ops.py); not included in backups
  backups/                riskprism-<YYYYMMDD-HHMMSS>.tar.gz, newest ENTROPY_BACKUP_KEEP kept (ops.py; only when ENTROPY_BACKUP_DIR is not set)
  secret.key              signs sessions, CSRF tokens and audit seals; encrypts authenticator secrets (mode 0600; not included in backups)
```

Writes are atomic (temp file then rename) and serialised by one process-wide lock.

## Slugs

`slugify(name)` produces the file key. Every read and write goes through `valid_slug`, which only accepts `[A-Za-z0-9_.-]`, up to 100 characters, no `..`, and checks that the resolved path stays inside its folder. A bad slug is a 404, never a file access.

## Vendor record: `vendors/<slug>.json`

Created by intake, report, import, seed, or "Start tracking this vendor" on a demo row.

```
vendor                display name
slug                  file key
website               http(s) URL only
contact               security contact
owner                 internal owner
business              why we care
mode                  saas | hybrid | onprem | unknown
stage                 inquiry | trial_30 | contracted | renewal_due | offboarded
authorization         not_authorized | trial_only | authorized | blocked
ai_used / ai_train    yes | no | unknown style enums (see textclass.py)
data_class            standard | sensitive | critical
connects              unknown | yes | no: will the vendor connect to our systems
connects_to           which of our systems, free text
category              vendor kind (from anticipate.CATEGORIES); drives anticipated connections
notes
source                employee_report | csv_import | seed | intake | demo_csv | shadow_it
created_by            analyst identity (or reporter)

soc2_expires          YYYY-MM-DD, validated
pentest_expires       YYYY-MM-DD, validated
next_review           YYYY-MM-DD, validated
contract_end          YYYY-MM-DD, validated; offered as an acceptance expiry
model_list_affirmed   YYYY-MM-DD, last time the vendor confirmed their model list
soc2_url / pentest_url  http(s) only

questionnaire_status  submitted
renewal_status        sent | submitted
answers               onboard answers keyed by question id (whitelisted keys only)
renewal_answers       renewal answers keyed by question id
followup_answers      answers to follow-up questions
submissions           last 20 vendor submissions: [{ at, kind, answers }]  (history, oldest dropped)
reports               employee "I use this" reports: [{ ... }]
evidence_files        uploads, see below
followups             open/resolved follow-up flags, see below
followup_open         count of open follow-ups
factsheet             parse_answers.factsheet()
draft_factors         provisional scoring factors, see below
exception             legacy, read once at startup and copied into riskprism.db (see RISK_ACCEPTANCE.md)
exceptions            legacy history, copied the same way; no longer written
offboarded_at
live_access           live third-party access rows, see below (not editable from a form)
live_access_synced_at ISO timestamp of the last replace_rows()

ai_q                  AI questionnaire state: status, source_url, context, model, research (pages read,
                      no text), profile, draft[], approved[], approved_at, approved_by (see AI_QUESTIONNAIRE.md)
ai_answers            vendor answers to the approved AI questions, keyed by question id
ai_mapped_keys        rule fields in `answers` that were filled from AI answers (so rules still run)
ai_docs               per requested document: { status: provided|not_available|missing, files[], note, doc_type }
```

Only the fields above are accepted from a form. Unknown keys are dropped rather than stored (no mass assignment).

### `live_access[]`

```
{ id, kind: oauth_app|enterprise_app|service_principal|role|token,
  source: demo|manual|entra|okta|google|saas_audit, display_name, app_id,
  scopes[], last_seen, first_seen, owner, status: active|stale|revoked, notes }
```

Normalized by `access_store.normalize_row()`; rows without a name are dropped, ids are de-duplicated. Written only through `records.update_vendor()`. See `docs/ACCESS_MODULE.md`.

### `evidence_files[]`

```
{ id, filename, stored_as, bytes, kind, sha256,
  uploaded_at, uploaded_by, azure: null | "<container>/<slug>/<stored_as>",
  period_end, valid_until, description,      # YYYY-MM-DD or "", free text (200)
  reviewed_by, reviewed_at,                  # "" until an analyst records a review
  question_id, doc_type }     # last two only on files a vendor uploaded for a document request
```

`kind` is one of `documents.TYPES`: `soc2_type2, soc2_type1, soc1, iso27001, bridge_letter, pentest, insurance, questionnaire, contract, other`. Older uploads may still say `soc2` (shown as "SOC 2 / ISO"). Files a vendor uploads get a type guessed from the request's wording.

Status is computed, never stored (`documents.status()`): **Expired** when `valid_until` has passed (or, for SOC reports, pentests and bridge letters with no `valid_until`, a year after `period_end`); otherwise **Not reviewed** until someone records a review; then **Expiring soon** inside 30 days, else **Reviewed**. Received is not reviewed, so an unread report is never green.

Uploading a SOC 1/2, ISO 27001 or pentest with a `valid_until` later than the vendor's `soc2_expires` / `pentest_expires` moves that clock forward (audit: `clock_from_document`). It never moves a clock back.

`uploaded_by` is the analyst, or `vendor:<slug>` for files uploaded through the vendor portal. Uploads are checked for extension (pdf, docx, xlsx, pptx, txt, csv, png, jpg, jpeg, md), magic bytes and size (25 MB) before they are stored.

### `followups[]`

```
{ id, severity: high|medium|low, title, detail, ask, status: open|resolved, opened_at }
```

`followup.scan()` regenerates flags from the answers, plus `doc_<question id>` flags for requested documents the vendor did not provide (severity from the question's `if_missing`). A follow-up an analyst marked `resolved` stays resolved and keeps its history; it is not reopened when the scan runs again.

### `draft_factors`

Drafted from the questionnaire so an onboarded vendor gets a provisional tier. Same keys as `score.py` uses for the demo portfolio:

```
data_sensitivity  data_volume  access_level  criticality
ai_involvement    blast_radius substitutability regulatory
unconfirmed       list of factors that were guessed and need an analyst to confirm
note
```

The UI marks those factors "to confirm" and the tier "draft". A human still owns the residual decision.

## Analyst notes: `vendor_notes` in `riskprism.db`

```
id, vendor_slug, kind: general|finding|follow_up|call|doc_review, body (1..8000),
doc_id (evidence file id, or ""), corrects (id of the note this one corrects, or NULL),
author (signed-in identity), created_at
```

Append-only: triggers refuse every UPDATE and DELETE. A mistake is fixed by adding a note with `corrects` set; the page strikes through the original and shows the correction. A correction must be on the same vendor. Recording a document review with text adds a `doc_review` note linked by `doc_id`. Purging a vendor does not delete its notes (the same as signed acceptances). The old single `notes` field on the vendor JSON is still the intake note and is shown at the bottom of the timeline.

## Users: `users` in `riskprism.db`

Used only when `ENTROPY_AUTH=accounts`. One row per person:

```
id, email (unique), name, status: invited|active|disabled, is_admin, view_only,
pw_hash (scrypt), totp_secret (encrypted, "enc1:" prefix), totp_last_step,
invite_hash, invite_expires, session_ver, failed, locked_until,
created_at, created_by, last_login
```

Invite links are stored as a hash. The authenticator secret is encrypted with a key derived from `ENTROPY_SECRET` (or `secret.key`), so the database alone cannot produce codes. Raising `session_ver` signs that person out everywhere. `view_only = 1` makes the person read-only; it cannot be set together with `is_admin`, and databases from before the column existed get it added with `0` on first start. A person who signs in with single sign-on (OIDC) still needs a row here; the first SSO sign-in activates an invited account. See `SECURITY.md`.

## Other data files

All are written atomically by the module named in the layout above.

- `integrations.json`: `{"integrations": [...]}`. Each integration has two parties, mechanism, identity, scopes, data flows, network, owner and status. See `docs/INTEGRATIONS.md`.
- `environment.json`: the systems you run or rent, and the guided-setup answers (organisation name, sensitive-data labels, default secret rotation period). See `docs/DATA_LAYER.md`.
- `objectives.json`: only the company's changes to the built-in library, plus attestations. The built-in objectives are in code.
- `catalog.json`: learned and imported product profiles. Exported without owners, identities, tenant names, purposes or dates through `/integrations/catalog.json`.
- `shadow.json`: the latest imported apps and domains, where each came from, and the decisions (Mark as known, with its note).
- `tickets.json`: a map from stable finding key (for example `F-3f9a1c0d2e`) to ticket number. Credentials for ServiceNow and Jira are never stored here.
- `findings_state.json`: `{"first": {key: date}, "closed": {key: date}, "snapshots": {date: {total, high, medium, low, overdue, ticketed}}}`. Written only when something changed. A finding that closes and returns within 14 days keeps its first-seen date; closed keys are dropped after 180 days and snapshots after 400 days. See `docs/DATA_LAYER.md`.
- `ops_state.json`: `last_backup`, `last_backup_file`, `last_backup_error`, `last_digest`, `last_digest_error`. Read by the scheduler and the Data and audit page.
- `environment.json` also holds `security_contact` (the address vendors are told to write to) and `finding_days` (`{high, medium, low}` days to fix, default 30 / 90 / 180).

## Backups: `backups/` (or `ENTROPY_BACKUP_DIR`)

One `.tar.gz` per backup, mode 0600 where the disk supports it: every file and folder in the data folder except `backups/`, `before-restore-*`, `secret.key`, `ops_state.json` and SQLite side files, with each `.db` copied through SQLite's online backup, plus a `BACKUP.json` (created at, by, data folder, and a one-way fingerprint of the server key so a restore can tell whether the same key is in place). `python3 ops.py restore FILE --force` moves the current contents (except `secret.key` and `backups/`) into `before-restore-<stamp>/` inside the data folder and unpacks the archive. Backups skip `before-restore-*` folders.

The per-vendor threat model is stored on the vendor record under `threat_model` (see `docs/THREAT_MODEL.md`).

## Tokens: `tokens.json`

```
"h:<sha256 of the token>": { vendor, slug, kind: onboard | renewal | followup | ai,
                             created_at, expires_at, revoked, last_used_at, by }
```

`by` is the analyst who issued the link. The vendor form names them (with their name in accounts mode) so the vendor can check who sent it.

Only the hash is stored, so a copy of the file cannot be used to open vendor links. The raw token exists only in the link shown to the analyst. Issuing a new link for the same vendor and kind revokes the older active one. Tokens expire after `ENTROPY_TOKEN_DAYS` (default 30), and offboarding or purging a vendor revokes its links. Tokens written by the earlier version were stored raw and are ignored, so links have to be re-issued after upgrading.

## Audit log: `audit` in `riskprism.db`

```
id, at (ISO time), actor ("local-analyst" | "ana@example.com" | "vendor:<slug>" | "system"),
action ("vendor_created" | "risk_accepted" | "evidence_uploaded" | "view_only_refused" | "backup_made" | ...),
slug, detail (up to 300 characters), ip,
prev (seal of the entry before; 64 zeros for the first), seal (HMAC-SHA256 over prev and this entry's fields)
```

The seal key is derived from the server secret. Triggers refuse every UPDATE and DELETE, and an index on `(slug, id)` serves the vendor's Activity tab. `audit.verify()` walks the chain and reports the first entry whose `prev` or `seal` does not match. Only **Delete all data** removes entries: it drops the table and starts a new chain with one `audit_log_wiped` entry. An older install's `audit.log` (one JSON object per line) is imported once, in order, then renamed `audit.log.imported`. See `SECURITY.md` for what the seals prove.

## Policy: `policy.json`

```
restricted_models     list of model names the customer does not allow
restricted_regions    list of regions the customer does not allow (matched as whole words)
required_region_if_critical   true | false
notes
```

The copy in the repository is only the default. Changes made on the Policy page are saved to `DATA_DIR/policy.json` for the tenant.

## Demo portfolio: `vendors.demo.csv` and `controls.demo.csv`

Scored by `score.py` and `portfolio.py`. Not editable through the UI. "Start tracking this vendor" copies a demo row into a real record so it can have clocks, evidence and a signed acceptance.
