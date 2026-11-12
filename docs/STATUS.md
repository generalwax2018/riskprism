# Status

Beta. Runs as one instance for one organisation, on a laptop, a small VM or App Service. One instance does not hold several organisations.

Roadmap: [docs/DESIGN_QUEUE.md](DESIGN_QUEUE.md).

## In
- Portfolio with inherent and residual tiers, filters, search, "waiting on a human" gate
- Evidence clocks (SOC 2, pentest, next review, model-list affirmation) and a flag queue
- "Report a tool" (employee), intake, CSV import, sample clocks
- AI-drafted questionnaire: reads the vendor's security, trust and privacy pages (or works from the analyst's notes when nothing is published), works out the engagement type (SaaS, device, on-site service, remote access), profiles 20 areas with sources, and drafts questions only for the gaps; analyst edits, adds and approves before a link is issued
- Document requests: the model asks for documents the risk calls for, with a severity if missing; vendors upload files or say they do not have them in the portal, and missing documents become follow-up flags at that severity
- Fixed onboard and renewal questionnaires (still available, and the fallback without a model) through expiring magic links, with structured yes/no answers
- Follow-up flags that ask questions instead of asserting findings, resolved items stay resolved
- Provisional tier for onboarded vendors from questionnaire answers (labelled draft, needs analyst confirmation)
- Risk acceptance per flag: org unit, tier, justification, compensating controls, required expiry (max 365 days), and a frozen snapshot of the risk. Low and Medium need a director; High and Critical need a VP or CISO. Signed rows cannot be edited or deleted. Accepted flags show blue as Accepted on the flag queue and go red again on expiry. The signer sets the expiry; the form suggests one by tier (30 / 60 / 90 / 180 days), the next review, the contract end, and optionally an AI-drafted date with its reason. See `docs/RISK_ACCEPTANCE.md`
- Org units from an Entra ID users export (department column). Unmapped departments become units flagged for review; the import never blocks. Admin screen to set owners, merge units, re-point department strings and manage approvers
- Risk acceptance dashboard by org unit, rolled up the org tree
- Offboard, purge with typed confirmation
- Document repository: per-vendor documents card and an all-vendor Documents library with filters; ten document types, report period, valid-until date, description; reviewed-by / reviewed-at with an optional review note; expired, not reviewed, expiring and reviewed states; a SOC or pentest upload moves its evidence clock forward. Type, size, magic-byte and hash checks; optional Azure Blob storage
- Analyst notes: append-only timeline on each vendor (note, finding, follow-up, call, document review), signed with the analyst's identity; corrections instead of edits
- Analyst sign-in (`none` on loopback, `accounts`, `password`, or Azure `easyauth`)
- Tamper-evident audit log in `riskprism.db`: each entry HMAC-sealed and chained to the one before, database triggers refuse edits and deletes, `verify()` names the first broken entry (**Data and audit** → Check the seals now, or `python3 ops.py verify-audit`). The board pack prints the head seal. An older `audit.log` is imported once and renamed `audit.log.imported`. See `SECURITY.md`
- View-only role: People page (Make view-only / Allow changes; Access on the invite form) or `ENTROPY_VIEWERS`. A viewer opens every page and downloads exports; every change is refused with 403 and audited as `view_only_refused`. Admin and view-only are exclusive
- Per-person accounts (`ENTROPY_AUTH=accounts`): invite links, scrypt-hashed passwords, required authenticator-app code (TOTP) with QR setup, single-use codes, lockout after 5 failures, admin People page (invite, reset sign-in, disable, admin on/off, view-only on/off), change own password, sessions revoked on disable/reset/password change. See README
- Per-tenant policy (restricted models and regions)
- Live access import: upload an Entra, Okta, Google or SaaS-audit export (CSV or JSON) to a tracked vendor; replaces its app list, skips and counts bad rows, audited. See `docs/ACCESS_MODULE.md`
- Live access module: `live_access[]` on each vendor, three rule-based flags (access after offboard, authorized with no live access, undisclosed write-class scopes) on the flag queue, and a Live access card on the vendor page. See `docs/ACCESS_MODULE.md`
- Vendor threat model, one per vendor: generated from the vendor record (systems, data flows, seven trust boundaries, fixed STRIDE prompts with LINDDUN privacy prompts, open questions). Analysts rate, decide, accept with an approver and expiry, and review; review is blocked while any threat is undecided. Changes to the record flag the reviewed version for review. Export to Word and PDF. See `docs/THREAT_MODEL.md` Each model includes an architecture diagram of zones, flows and trust boundaries.
- Integrations data layer: every connection between your tenants, vendors and own systems (mechanism, identity, roles, scopes, data flows, endpoints, credentials, owner), with rule-based findings, declared-vs-observed drift, onward paths for sensitive data and a central dashboard plus a per-vendor tab. Intake, the vendor questionnaire, renewal and the AI questionnaire all ask how the vendor connects; answers raise follow-ups and can be drafted into a planned integration. See `docs/INTEGRATIONS.md`
- Your environment, control objectives (20 built in, 16 on by default; mapped to NIST 800-53, ISO 27001, SOC 2, PCI DSS, HIPAA, NERC CIP and AI frameworks including EU AI Act Art. 25/26; four CIP-013 R1.2 vendor-commitment objectives ship off and are attested by hand), anticipated connections, product catalog that learns from confirmed integrations, shadow IT queue, executive summary with board PDF. See `docs/DATA_LAYER.md`
- Findings worklist across integrations, controls, shadow IT and vendor flags, with stable keys; raise tickets in ServiceNow or Jira, or export CSV and record ticket numbers. See `docs/DATA_LAYER.md`
- Finding deadlines and trend: first seen, due date from the customer's own rule (default high 30 / medium 90 / low 180 days), days open and overdue, an Overdue tile, a trend line against about a month ago on the worklist, executive summary and board pack. Due dates go into the CSV, ServiceNow `due_date`, and Jira `duedate` with `ENTROPY_JIRA_DUEDATE=1`
- Vendor-facing branding: Organisation name and a security contact under Your environment. The vendor form and the share page's ready-to-send message say who is asking, that they use RiskPrism, who sent it, the deadline, and who to write to if unexpected
- Optional email over the customer's own SMTP (`ENTROPY_SMTP_*`): vendor questionnaire links from the share page, invite links from the People page, and a weekly digest on Monday morning to active admins and `ENTROPY_DIGEST_TO`. Plain text, no tracking
- Data and audit page (admins): nightly backup of the data folder (`ENTROPY_BACKUP*`; `secret.key` is not included), Back up now, download backups, restore from the shell (`python3 ops.py restore FILE --force`), export everything as a .zip with no secrets, remove sample data, delete all data with a typed phrase. Startup prints `Backups:` and `Email:` lines, and the config check refuses bad SMTP, digest and backup values
- Glass interface in the Keywarden style: floating toolbar, grouped sidebar, frosted cards; follows the system light or dark setting; system fonts, so no page calls Google Fonts or any outside server
- Declared vs observed panel on the vendor Integrations tab: declared scopes against what the identity-provider export shows, plus live apps no integration records
- Analyst single sign-on with OpenID Connect (Entra ID, Okta, Google and others) in accounts mode; optional SSO-only. See README
- `ENTROPY_AI=off`: hides every AI control, refuses model calls and vendor website fetches in code, and shows "AI: off (enforced)". Every workflow has a manual path
- Authenticator secrets encrypted at rest with a key derived from the server secret
- Clean-install pilot test: starts the real server on an empty data folder, walks the main flows, then removes sample data, exports and deletes everything
- Analyst pages and vendor portal share the glass look; light and dark; responsive down to phone width
- Tests (`python -m unittest discover -s tests -v`, 281 tests), `Dockerfile`, `.env.example`, Azure guide, `SECURITY.md`

## Queued (not built yet)
- Portfolio Clock / Grant / Spark glyphs and red-on-disagreement
- "Accept the risk" straight from the declared vs observed panel
- Gap-only questionnaire + structured factsheet Unknowns
- Visible 0 / 30 / 60 / 90 trial strip
- Live IdP API

## Out (known limits)
- No database server. Vendor records are JSON files and risk acceptance is one SQLite file; one instance only.
- Email needs your own SMTP server or service; without it, copy the link or the ready-to-send message. No email reminder before an acceptance expires and no per-finding emails; the dashboard shows what expires within 30 days, and the weekly digest gives counts.
- Three roles: admins (`ENTROPY_ADMINS`, or the People page) edit org units, approvers, people and data; approvers sign acceptances; view-only people read and export. Everything else is open to any signed-in analyst. `password` mode is one shared identity, so it cannot sign acceptances; `accounts` mode can.
- The Entra import reads an uploaded CSV. There is no live Microsoft Graph connection, and people are not stored.
- No malware scanning of uploads. Documents cannot be deleted from the UI.
- In `password` mode every note and review is signed `analyst`, because the login is shared. Use `accounts` (or `easyauth` on App Service) for per-person attribution.
- Accounts mode: invite links are emailed only when SMTP is set up, otherwise admins copy them by hand; no self-service "forgot password" (an admin resets it). SSO (OIDC) needs an account to exist first: an admin invites the email, and the first SSO sign-in activates it. No SCIM provisioning.
- Ticketing creates tickets; it does not read their status back. Close the finding in RiskPrism (fix the cause, or clear the ticket) when the ticket closes.
- AI: the questionnaire is AI-drafted from the vendor's published pages, with analyst approval (`docs/AI_QUESTIONNAIRE.md`). The model does not yet review answers, draft follow-up rounds, or read uploaded SOC 2 / pentest reports; the fixed rules still do the answer checks. Any OpenAI-compatible model works; Grok is the default when only `XAI_API_KEY` is set.
- Threat model is rule-generated and analyst-written. Likelihood and impact are analyst judgment on a 1 to 5 scale, not scored by a model. Threat prompts are a fixed checklist, not a threat library. Systems and flows are derived from the record and cannot be edited in v1.
- Live access has no IdP connector yet. Rows come from sample data or a file you upload. The shadow IT queue finds unknown apps only from the exports you import; nothing watches your tenant.
- Backups go to a folder (`ENTROPY_BACKUP_DIR`). RiskPrism does not copy them off the server itself: mount Azure Files or another disk there. Restore is a shell command with the service stopped, not a button. `secret.key` is kept separately by you.
- Azure Blob and Easy Auth are written but were not tested against a live account.
- TLS is provided by App Service or Caddy, not by the app. Do not publish on a public IP over plain HTTP: the analyst password and vendor magic links would travel in clear text.

## Retired files
`app.py` and `vendor.html` are stubs from files that no longer serve a purpose and can be deleted. `app.py` in particular did not compile in the earlier version.

## First-run script
`python serve.py` → http://127.0.0.1:8765/alerts → Load sample clocks → open a vendor → New vendor form link → open the link in a private window.

Before real use: Data and audit → Remove sample data.

Integrations: Integrations → Load sample integrations → open a vendor's Integrations tab → Findings → Executive summary.

Risk acceptance: Import CSV → Import Entra users → Org units (set owners, add yourself as approver) → open a vendor → Risk acceptance → Risk acceptance dashboard.
