# Security notes

This app stores vendors' security answers and evidence, so it is a target. This file lists what the code defends against, what changed in the review, and what is still your job.

## Reporting a vulnerability

Report it privately through **Security → Report a vulnerability** on this repository (a private advisory), not in a public issue. If that is unavailable, use the contact on the maintainer's GitHub profile. You should hear back within 7 days. Please allow time for a fix before writing about it in public.

Do not put real vendor answers, documents, `secret.key`, session cookies, vendor links or audit exports in an issue. A description, the route, and a made-up example are enough.

Only the latest release on `main` gets security fixes.

## What was fixed in the review

| Problem in the earlier version | Fix |
|---|---|
| Vendor names, answers and notes were placed into HTML unescaped (stored XSS in the analyst UI) | Templates escape by default (`{{x}}`); raw output needs `{{!x}}` and is used only for fragments built and escaped in `views.py`. Page JSON goes through `json_for_script`. Tests inject script payloads through every field. |
| A crafted slug could reach files outside `data/` (edit, purge, upload, download) | One strict slug validator plus a resolved-path-inside-folder check in `records.py` and `evidence_store.py`. Bad slugs return 404. |
| No analyst login; binding to `0.0.0.0` exposed everything | `ENTROPY_AUTH=none` only works on loopback (startup refuses otherwise). `password` mode uses an HMAC-signed HttpOnly SameSite=Strict session cookie and throttled login. `easyauth` mode uses Azure App Service authentication. |
| Any web page could make an analyst's browser POST to the app (CSRF), and DNS rebinding could reach a loopback server | Per-user HMAC CSRF token on every POST (injected into all forms). `Host` header allow-list. SameSite=Strict cookie. |
| Vendor magic links were stored raw, never expired, and re-issuing returned the old one | Only a SHA-256 hash is stored. Links expire (30 days by default), are revoked when replaced, offboarded or purged, and record last use. |
| Uploads: no type check, no size limit, the client's filename chose the path | Extension allow-list, magic-byte check, 25 MB cap, random-prefixed stored name, SHA-256 recorded, downloads served as attachments with `nosniff`. |
| Form posts could set any field on a record (mass assignment) and overwrite existing vendors | Whitelisted fields, enum / date / URL validation, 409 on duplicate intake, atomic writes under a lock. |
| Purge was one click | Purge requires typing the vendor name. Offboarding keeps the record for audit. |
| No record of who did what | Tamper-evident audit log in `riskprism.db` with actor, action, slug and IP, each entry sealed to the one before it (see below). Shown on each vendor's Activity tab. |
| Response headers | CSP (`default-src 'none'`, scripts, styles and fonts only from `'self'`), `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. |

Logic fixes that affect risk decisions, not only security:

- Free-text answers used to be matched by substring, so "graphics" matched "phi" and "content" matched "on". Matching is now whole-word, and ambiguous answers return "unknown" for a human instead of a guess.
- A vendor writing "we do not train on customer data" could be flagged as training on customer data. The training check now judges each sentence and treats negation properly.
- Onboarded vendors had no scoring factors and showed no tier. They now get a provisional, clearly labelled tier that a person must confirm.
- Resolved follow-ups no longer reopen themselves when the answers are re-scanned.
- The demo portfolio's residual scores now use `controls.demo.csv`.

## Audit log

Entries live in the `audit` table of `DATA_DIR/riskprism.db`. Each entry is sealed with an HMAC over its own fields and the seal of the entry before it, keyed from the server secret (`ENTROPY_SECRET` or `secret.key`). Database triggers refuse UPDATE and DELETE on the table. Per-vendor reads (the Activity tab) use an index.

What it proves:

- An entry changed, removed or reordered in the middle of the log is detected. **Check the seals now** on **Data and audit**, or `python3 ops.py verify-audit`, walks the chain and names the first broken entry.

What it does not prove:

- Someone holding **both** the database and the server secret could rebuild the whole chain, or cut entries off the end. To catch that, record the latest (head) seal somewhere outside the server now and then. **Data and audit** shows it, and the board pack PDF prints it with the entry count, so a filed board pack is such a record. Keep the server secret away from the database backups.
- Changing the server secret makes every older entry fail verification. Do not rotate it casually.

Older installs kept the trail in `DATA_DIR/audit.log`. On first start it is imported once, in order, sealed, and the file is renamed `audit.log.imported`.

## How to report a problem

Open a private issue or email the repository owner. Do not put vendor data in a public issue.

## What you still have to do

- **Deploy behind TLS.** The app speaks plain HTTP. App Service and Caddy (see `docs/AZURE_DEPLOY.md`) terminate HTTPS for you.
- **Run one instance.** The write lock is per process.
- **Choose the auth mode honestly.** `password` is a single shared secret: everyone who knows it is the same "analyst" in the audit log. For that reason the app refuses to sign risk acceptances in `password` mode. Use `accounts` (or `easyauth` on App Service) for customers.
- **Accounts mode.** Passwords are scrypt-hashed; a 6-digit authenticator code is required at every sign-in and each code works once. Invite links are single use, stored only as a hash, and expire after 72 hours. Five failures lock an account for 15 minutes; the per-IP throttle still applies. Disabling, resetting or changing a password signs that person out everywhere. Authenticator secrets are encrypted in `riskprism.db` with a key derived from `ENTROPY_SECRET` (or `secret.key`), so a copy of the database alone cannot produce codes; keep `secret.key` out of the same backup set, and know that losing it means every person resets their sign-in. Secrets from older versions are encrypted on first start. Treat invite links like passwords.
- **Single sign-on (OIDC).** Uses the authorization code flow with PKCE, state and nonce. The ID token's RS256 signature is checked against the provider's published keys, along with issuer, audience, expiry and nonce. Only `https` issuers are accepted. A person must already have a RiskPrism account (admins invite them); SSO never creates one, and a disabled account cannot sign in. Use `ENTROPY_OIDC_ONLY=1` once everyone has signed in with SSO, so passwords stop being a way in. Keep `ENTROPY_OIDC_CLIENT_SECRET` out of git.
- **Ticketing credentials.** `ENTROPY_SNOW_PASSWORD` and `ENTROPY_JIRA_TOKEN` are read from the environment only and never written to disk or the audit log. Give the ServiceNow user create rights on one table only, and the Jira token an account that can create issues in one project only.
- **Turning AI off.** `ENTROPY_AI=off` is enforced in the model and web-fetch modules, not only by hiding buttons. Use it where policy forbids AI; the startup line and the sidebar say "AI: off (enforced)".
- **Use view-only for people who only need to look.** A view-only account (People page, or `ENTROPY_VIEWERS` outside accounts mode) can open every page and download exports. Every POST except sign-out and changing their own password is refused with 403 and audited as `view_only_refused`. The check is one gate in the request handler, not hidden buttons. A person cannot be admin and view-only at once, and `ENTROPY_ADMINS` does not override `ENTROPY_VIEWERS`.
- **Keep the admin list short.** `ENTROPY_ADMINS` decides who can make someone a director, VP or CISO approver, and so who can accept High and Critical risk. An admin cannot change their own level, but two admins can change each other's; review the approvers list and the `approver_set` lines in the audit log.
- **Do not use `easyauth` where clients can reach the app directly.** It trusts `X-MS-CLIENT-PRINCIPAL-NAME`, which is only safe when the platform is the sole way in.
- **Set `ENTROPY_BASE_URL` to the HTTPS URL** so vendor links and the Secure cookie flag are right.
- **Protect the data folder.** It holds vendor answers, evidence, hashed tokens, `secret.key` and `riskprism.db` (org units, approvers, signed acceptances, accounts, notes and the audit log). Restrict access.
- **Keep backups off the server, and `secret.key` away from them.** The nightly backup is a `.tar.gz` of the data folder (mode 0600) written to `ENTROPY_BACKUP_DIR`. The default, `DATA_DIR/backups`, is on the same disk, so point it at a mounted Azure Files share or another disk. `secret.key` is deliberately left out: keep one copy in Key Vault or a password manager. So a stolen backup alone cannot produce authenticator codes or re-seal the audit log, and a restore needs your saved copy of the key. Backups still hold vendor answers and evidence, so restrict who can read the share. Restore refuses archives with absolute or `..` paths and moves the current data aside instead of deleting it.
- **The export is not a backup and holds no secrets.** **Export everything** (admins only) has vendor records, documents and CSVs, but no password hashes, authenticator secrets, vendor link tokens or server key. It still holds customer data: hand it over the way you would hand over the documents themselves.
- **Delete all data is final.** It needs the phrase `DELETE ALL DATA`, is admin-only, and removes vendors, documents (and their Azure Blob copies when Azure storage is on), answers, stores, policy, notes, acceptances, org units, approvers, vendor links, earlier `before-restore-*` copies and the audit log (which restarts with one `audit_log_wiped` entry). People's accounts and `secret.key` stay. Backups on the server go too unless the box is unticked; copies elsewhere are yours to delete.
- **Email credentials.** `ENTROPY_SMTP_PASSWORD` is read from the environment only and never written to disk or the audit log. Use `starttls` or `ssl`; `none` is refused unless the mail server is on the same machine. Messages are plain text with no tracking and no links except this server's own. A vendor email's Reply-To is the security contact from Your environment, or else the analyst who issued the link. An emailed invite or vendor link is only as safe as the mailbox it lands in.
- **No calls to outside servers from the pages.** Pages use the operating system's own fonts (Segoe UI on Windows, San Francisco on Apple devices) and load no font files. No page loads anything from Google Fonts or any other host, and the CSP (`font-src 'self'`, `style-src 'self'`) would block it. The server's own outbound calls are the ones you configure: the model provider and vendor sites (AI on), your identity provider (SSO), ServiceNow or Jira, and your mail server.
- **Treat uploaded files as untrusted.** The app checks type and size but does not scan for malware. Open them in a sandbox, not on a machine with production access.
- **Vendor answers are untrusted text.** They are escaped everywhere, and Grok integration (if you wire it) must treat them, and any uploaded document, as untrusted input that could carry instructions aimed at the model. See `docs/GROK_INTEGRATION.md`.
- **Know what goes to the model provider.** The AI questionnaire sends the vendor's public pages, the vendor record's description and your "how we plan to use it" note to the configured provider (xAI today). Keep customer secrets out of that note. Rotate the API key if it is ever exposed.
- **The server fetches web pages.** Research only follows public `http`/`https` addresses on ports 80 and 443. Every redirect is checked too, so loopback, private ranges and the cloud metadata service (169.254.169.254) are refused. A host that changes its DNS answer between the check and the fetch is a known residual gap.
- **Vendors can upload files.** On an AI questionnaire with document requests, the vendor link accepts uploads. They get the same checks as analyst uploads (type allow-list, content matches the extension, 25 MB per submission) and are recorded as `vendor:<slug>` in the audit log. Anyone holding a valid link can upload, so treat vendor files as untrusted.
- **Model output is untrusted.** It is validated against a fixed shape, and cited sources must be pages that were actually read. An analyst approves every question before a vendor sees it, and the model cannot change a score, clear a flag or sign anything.
- **Legacy links stop working.** Tokens from the earlier version were stored raw and are ignored. Re-issue vendor links.

## Known limits

- The Azure Blob and Easy Auth code paths have not been run against a live Azure account. They are small, but test them before you rely on them.
- Login throttling and CSRF secrets are per process and reset on restart if `ENTROPY_SECRET` is not set and the data folder is read-only.
- `X-Forwarded-For` is trusted for the audit-log IP and throttling. That is right behind App Service or Caddy, and spoofable if the app is exposed directly.
- Email is optional and needs your own SMTP server or service. Vendors use magic links, not SSO. Roles are admin, approver and view-only; any other signed-in analyst can do everything else.
- Signed acceptances and audit entries are protected against edits and deletes by database triggers. Someone with shell access to the data folder can still alter the file. The audit seals show a change made without the server secret; a change made with it is caught only by comparing with a head seal you recorded outside the server.
- JSON files do not scale past a few thousand vendors and do not support more than one writer process.

## Tests

`python -m unittest discover -s tests -v` starts the real server on a random port with a temporary data folder and checks each fix above (XSS, traversal, CSRF, upload limits, headers, token lifecycle, auth modes, follow-up logic), plus the risk acceptance rules (approval thresholds, tier floor, expiry, frozen rows, admin-only screens, no self-escalation).

The suite is 281 tests. Later additions cover the page shell, light and dark appearance and no outside requests and the public-repo checks (`test_ui_shell.py`), per-person accounts and sign-in lockout (`test_accounts.py`), authenticator secrets encrypted at rest (`test_totp_at_rest.py`), OpenID Connect sign-in against a fake identity provider (`test_oidc.py`), `ENTROPY_AI=off` (`test_ai_off.py`), live access file import (`test_access_import.py`), declared vs observed scopes (`test_drift.py`), the findings worklist and ServiceNow and Jira push against local fakes (`test_findings.py`), the integrations, shadow IT and control objective layers (`test_integrations.py`, `test_data_layer.py`), the threat model and its exports (`test_threat_model.py`), view-only accounts and the sealed audit log (`test_roles_audit.py`), finding due dates, trend and the NERC CIP objectives (`test_deadlines.py`), email, backup and restore, export, sample-data removal and delete-all (`test_ops_mail.py`), regression tests for review findings such as the audit chain across processes and restore safety (`test_review_fixes.py`), and a clean-install pilot (`test_pilot.py`) that starts the real server as a separate process on an empty data folder, walks the main flows, and ends with remove sample data, export and delete all.
