# Architecture

Single-process Python 3.10+ app. Standard library only. No framework. Vendor records are files; org units, risk acceptances, notes, accounts and the audit log are one SQLite file through the stdlib `sqlite3` (see [RISK_ACCEPTANCE.md](RISK_ACCEPTANCE.md) and [DATA_MODEL.md](DATA_MODEL.md)).

```
browser  →  serve.py (ThreadingHTTPServer)
              ├─ config.py        environment variables, startup checks
              ├─ auth.py          analyst auth modes, sessions, CSRF, Host allow-list
              ├─ tpl.py           templates: {{x}} is HTML-escaped, {{!x}} is raw
              ├─ views.py         builds page fragments (layout.html wraps them)
              ├─ *.html           layout, ui, alerts, intake, report, import, policy,
              │                   evidence, record, qform (vendor portal), share, login, error
              ├─ static/app.css, static/app.js
              ├─ records.py       data/vendors/<slug>.json   (atomic writes, slug validation)
              ├─ tokens.py        data/tokens.json           (hashed, expiring)
              ├─ audit.py         data/riskprism.db `audit` table: HMAC-sealed, chained, triggers refuse edits;
              │                   verify(), head seal, CSV; imports an old audit.log once
              ├─ evidence_store.py  uploads: local folder or Azure Blob
              ├─ documents.py     document types, dates, review status, clock updates
              ├─ notes_store.py   data/riskprism.db: append-only analyst notes
              ├─ multipart.py     upload parsing
              ├─ questionnaire.py onboard vs renewal question packs
              ├─ textclass.py     conservative yes/no, training default, whole-word matching
              ├─ parse_answers.py factsheet + draft scoring factors
              ├─ followup.py      answers → follow-up flags
              ├─ alerts.py        clocks + access flags → flag queue, dashboard rows
              ├─ access_store.py  live_access[] normalize / replace
              ├─ access_flags.py  live_access → rule-based flags (no model calls)
              ├─ access_demo.py   sample live-access rows (local demo only)
              ├─ llm.py           any OpenAI-compatible model (xAI, OpenAI, Ollama, ...)
              ├─ vendor_research.py  vendor's public security pages (public addresses only)
              ├─ ai_questionnaire.py  profile + draft questions, validation, background job
              ├─ risk_store.py    data/riskprism.db: org units, aliases, approvers, acceptances
              ├─ risk_rules.py    approval thresholds, acceptable detections, frozen snapshot
              ├─ threat_model.py  per-vendor threat model: computed from the record; stores decisions, answers, reviews
              ├─ threat_export.py  Word (.docx) and PDF writers from one block list (stdlib only)
              ├─ threat_views.py   Threat model tab on the vendor record (forms only, no scripts)
              ├─ threat_diagram.py  architecture diagram per vendor: one layout, drawn as SVG, PDF and a PNG fallback
              ├─ integrations.py  data/integrations.json: connections, scopes, flows, findings, coverage, drafts
              ├─ integrations_views.py  Integrations dashboard and the vendor Integrations tab
              ├─ integrations_demo.py  sample integrations (local demo only)
              ├─ environment.py / environment_views.py  your systems, tenants, settings; map and system pages
              ├─ control_objectives.py / controls_views.py  objectives, checks, attestations, matrix
              ├─ anticipate.py    predicted connections and the vendor's likely stack
              ├─ catalog.py       product profiles: built in, learned, imported
              ├─ shadow.py / shadow_views.py  unapproved apps and SaaS from IdP and proxy exports
              ├─ executive.py     executive summary page and board PDF
              ├─ findings.py / findings_views.py  one worklist; ServiceNow and Jira tickets; CSV
              ├─ memo.py          per-request cache of expensive reads, dropped on any write
              ├─ oidc.py          analyst single sign-on (OpenID Connect, PKCE, RS256 checked in stdlib)
              ├─ mailer.py        optional outgoing email over SMTP (smtplib): vendor links, invites, digest texts
              ├─ ops.py           backups and restore, export .zip, remove sample data, delete all, weekly digest,
              │                   background scheduler; command line: backup | restore FILE [--force] | verify-audit
              ├─ ops_views.py     the Data and audit page (/admin/data)
              ├─ entra_import.py  Entra users CSV → department strings → org units
              ├─ policy_store.py  restricted models/regions per tenant
              ├─ portfolio.py     demo CSV rows + onboarded vendors, one list
              ├─ score.py         inherent score and residual tier (demo + drafts)
              └─ seed.py / csv_import.py
```

## Why this shape

Built so one person can run it on a laptop for a closed beta, and one small instance can run it on Azure. Persistence is files so a programmer can open a vendor in an editor. `records.py` is the only module that reads and writes vendor files; replace it with Postgres later without touching the routes.

## Process model

`serve.py` is the only process. Templates are read on each request, so a `git pull` shows up without a restart, but Python modules load once, so restart after a pull that changes `.py` files. Keep it to **one instance**; the lock that serialises writes lives in that process.

Startup runs `config.check_startup()` and exits if the configuration is unsafe (a non-loopback bind with no analyst auth, a weak password in password mode, SSO settings without accounts mode or without https, an unknown `ENTROPY_AI` value, `ENTROPY_SMTP_HOST` without a valid `ENTROPY_SMTP_FROM`, an unknown `ENTROPY_SMTP_TLS` or `ENTROPY_DIGEST` value, `ENTROPY_SMTP_TLS=none` to a non-loopback mail server, an unknown `ENTROPY_BACKUP` value). It then prints `Backups:` and `Email:` lines with what is switched on.

One background thread (`ops.start_scheduler`, daemon, named `riskprism-scheduler`) wakes every 15 minutes. It makes the nightly backup at the first check after 02:00 server time, and sends the weekly digest on Monday after 08:00 server time when email is on. Its state (last backup, last digest, last errors) is in `data/ops_state.json`. Failures are written to the audit log and stderr and never stop the server.

`ENTROPY_AI=off` is checked inside `llm.py` and `vendor_research.py` on every call, not only in the UI: with it off, no code path can reach a model provider or fetch a vendor's website, even if `LLM_*` variables are set.

## Performance as data grows

Dashboards are computed live from the files on every page load, so their cost grows with the number of vendors and integrations. Two rules keep that cost close to linear:

- **Compute once per request.** `memo.py` keeps the parsed vendor records (`records.list_vendors`), the integrations overview (`integrations.overview`) and party names for the length of one request. Executive summary, findings, control objectives and environment exposure all reuse them. Any write through `records.atomic_write` or `records.delete_vendor` bumps a generation counter and drops every cached answer, so a page that saves and then re-renders always sees the save. Outside a request (tests, command line) nothing is cached. Cached values are shared: treat them as read-only.
- **Index instead of rescanning.** Live-access scopes are indexed by app ID once per pass (`integrations.observed_index`). Control objectives group integrations by vendor once and load active risk acceptances in one query (`control_objectives.matrix`).

Measured on one core with synthetic data (each vendor with one integration and one live-access app):

| Page | 200 vendors before | 200 vendors after | 1,000 vendors before | 1,000 vendors after |
|---|---|---|---|---|
| Executive summary | 0.33 s | 0.07 s | 5.66 s | 0.49 s |
| Findings | 0.25 s | 0.07 s | 3.77 s | 0.41 s |
| Control objectives | 0.17 s | 0.07 s | 2.22 s | 0.29 s |

When a new rule needs data from every vendor, build a lookup once per pass and pass it down; never loop over all vendors inside a per-vendor or per-integration loop. `tests/test_memo.py` checks the cache and the index.

## Request flow

1. Reject bad `Host` headers (DNS-rebinding defence) except on `/healthz`.
2. Public routes: `/healthz`, `/static/*`, `/login`, `/q/<token>` (vendor form).
3. Everything else needs an analyst identity from `auth.principal()`; without one it redirects to `/login` (accounts and password modes) or returns 401 (easyauth). `/setup/<token>` (account invite) is public; the token is the credential.
4. POST bodies are size-limited (256 KB, 25 MB for uploads) and must carry a valid `_csrf` token. `_page()` injects the token into every form, so templates do not need to.
5. A view-only identity is refused here with 403 for every POST except `/logout` and `/account`, and the refusal is audited as `view_only_refused`. This is the one gate for every change in the app.
6. Fields are cleaned against a whitelist, then validated (enums, dates, URLs).
7. State changes go through `update_vendor(slug, fn)` under the global lock and are written to the audit log.
8. Responses carry a strict CSP, `nosniff`, `DENY` framing, `no-referrer` and `no-store`. The CSP is `default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. No page loads anything from another host.

## Routes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` | none | Liveness |
| GET | `/static/*` | none | CSS and JS |
| GET/POST | `/login`, POST `/logout` | none | Password and accounts sign-in |
| GET | `/login/sso`, `/login/sso/callback` | none | OpenID Connect sign-in (accounts mode with `ENTROPY_OIDC_*`) |
| GET/POST | `/q/<token>` | token | Vendor questionnaire and submit |
| GET | `/` | analyst | Portfolio |
| GET | `/alerts` | analyst | Evidence clocks and flag queue |
| GET/POST | `/policy` | analyst | Restricted models and regions |
| GET/POST | `/intake` | analyst | New vendor (409 if it already exists) |
| GET/POST | `/report` | analyst | "I use this tool" report |
| GET/POST | `/import` | analyst | CSV import (max 2000 rows) |
| GET | `/vendor/<slug>` | analyst | Record: Overview, Questionnaire, Activity |
| GET/POST | `/edit` | analyst | Edit fields |
| GET/POST | `/evidence/<slug>`, `/evidence` | analyst | One vendor's documents: list, download, upload with type and dates |
| GET | `/documents` | analyst | Document library across all vendors (`?type=`, `?status=`, `?q=`) |
| POST | `/document/review` | analyst | Record that you reviewed a document, with an optional note |
| POST | `/note` | analyst | Add an analyst note, or a correction (`corrects=<id>`) |
| GET | `/share/<token>` | analyst | Share page for a fresh vendor link: the link, a ready-to-send message (Copy message), and Send email when email is on |
| POST | `/share/send` | analyst | Email the vendor link to one address (Reply-To is the security contact) |
| POST | `/track` | analyst | Start tracking a demo vendor |
| POST | `/clock` | analyst | SOC 2, pentest, next review dates and links |
| POST | `/link`, `/renewal` | analyst | Issue an onboard or renewal link |
| POST | `/followup`, `/resolve` | analyst | Send follow-up questions, mark resolved |
| POST | `/parse` | analyst | Rebuild factsheet and flags |
| POST | `/accept` | approver | Signed risk acceptance for one detection (tier thresholds enforced) |
| GET | `/ai/<slug>` | analyst | AI questionnaire: research, profile, draft review |
| POST | `/ai/draft`, `/ai/questions` | analyst | Start research and drafting; save or approve questions (approve issues an `ai` link) |
| GET | `/risk` | analyst | Acceptances by org unit (`?org=<id>` for one subtree) |
| POST | `/import/entra` | analyst | Entra users CSV; unmapped departments become units flagged for review |
| GET | `/admin/orgs` | admin | Org units, department strings, approvers |
| POST | `/admin/unit`, `/admin/merge`, `/admin/alias`, `/admin/approver` | admin | Edit, merge, re-point, set approver level |
| POST | `/offboard` | analyst | Offboard; revokes links |
| POST | `/purge` | analyst | Delete a record (must type the vendor name) |
| POST | `/seed` | analyst | Sample clocks (no-auth mode, or `ENTROPY_ALLOW_SEED=1`) |
| GET | `/threat/<slug>` | analyst | Redirects to the Threat model tab on the vendor record |
| POST | `/threat/<slug>/threat`, `/question`, `/design` | analyst | Save a threat decision, an open-question answer, or the design statement; redirects to the tab |
| POST | `/threat/<slug>/review` | analyst | Record the model as a reviewed version (blocked while any threat needs a decision) |
| GET | `/threat/<slug>/export.docx`, `export.pdf` | analyst | Word or PDF export of the model |
| GET | `/threat/<slug>/diagram.svg` | analyst | The architecture diagram as an SVG file |
| GET | `/integrations` | analyst | Integrations dashboard (`?vendor=<slug>` to filter) |
| POST | `/integrations/add`, `/integrations/<id>/retire` | analyst | Record an integration; mark one retired |
| POST | `/integrations/draft` | analyst | Draft a planned integration from a vendor's questionnaire answers |
| POST | `/integrations/seed` | analyst | Sample integrations (no-auth mode, or `ENTROPY_ALLOW_SEED=1`) |
| POST | `/integrations/anticipate`, `/integrations/catalog` | analyst | Confirm a predicted connection; import a catalog file |
| GET | `/integrations/catalog.json` | analyst | Export what the catalog learned, without customer details |
| GET/POST | `/environment`, `/environment/<id>`, `/environment/setup`, `/environment/import`, `/environment/system` | analyst | Your environment: setup, CMDB import, systems |
| GET/POST | `/controls`, `/controls/objective`, `/controls/add`, `/controls/attest` | analyst | Control objectives and attestations |
| GET/POST | `/shadow`, `/shadow/apps`, `/shadow/domains`, `/shadow/track`, `/shadow/decide` | analyst | Shadow IT queue |
| GET | `/executive`, `/executive/board.pdf` | analyst | Executive summary and board PDF |
| GET | `/findings`, `/findings.csv` | analyst | Findings worklist (`?source=`, `?show=all`) and CSV for ServiceNow or Jira import |
| POST | `/findings/push`, `/findings/ticket`, `/findings/untrack` | analyst | Raise tickets in ServiceNow or Jira; record or clear a ticket number |
| GET | `/admin/data` | admin | Data and audit: backups, audit seals, export, sample data, email, delete all |
| GET | `/admin/data/export.zip`, `/admin/data/audit.csv` | admin | Export everything; the audit log as CSV with seals |
| GET | `/admin/data/backup/<name>` | admin | Download one backup |
| POST | `/admin/data/backup`, `/admin/data/verify` | admin | Back up now; check the audit seals |
| POST | `/admin/data/sample`, `/admin/data/delete` | admin | Remove sample data; delete all data (needs `DELETE ALL DATA`) |
| POST | `/admin/data/test-email`, `/admin/data/digest` | admin | Send a test message; send the weekly digest now |

## UI split

- **One visual system**, shared with Keywarden: a soft colour field behind everything, a floating glass toolbar, glass cards, a blue accent, and the operating system's own fonts. It follows the system light or dark setting (`prefers-color-scheme`); every colour is a token in `:root` with a dark override, so new CSS should use the tokens, never fixed colours. Without backdrop blur the panels fall back to near-solid fills.
- **Analyst pages** (`layout.html`): the toolbar carries the four main views (Portfolio, Executive, Findings, Renewals) as a segmented control and the New vendor button; the sidebar groups the rest (Decide, Inventory, Admin) above the signed-in card. Below 900px the sidebar becomes a scrolling strip.
- **Risk tiers** read red (T1), orange (T2), yellow (T3), green (T4). Accepted risk is indigo, so an exception never reads as a tier.
- **Vendor questionnaire** (`qform.html`, `body.portal`) uses the same glass with a calmer reading measure and no analyst navigation: it is the customer's face to the vendor.
- Rows are rendered on the server. `static/app.js` only filters, switches tabs, copies links and updates the progress bar. It builds no HTML from data, and the CSP blocks inline scripts.

## What is not in the repo on purpose

`data/` is gitignored. Tokens, answers, evidence and vendor JSON live only where the server runs.
