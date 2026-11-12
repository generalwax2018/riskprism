# Data layer: environment, control objectives, anticipated connections, catalog, shadow IT, executive view, findings

Everything here is built from the customer's own setup and records, using fixed rules and no model.

## Your environment (`/environment`)

These are the systems the customer runs or rents: its identity provider, each SaaS tenant, cloud accounts, on-premises sites, endpoint fleet, network edge, security tools, and the data stores that hold sensitive data.

- **Guided setup.** The customer picks its identity provider, collaboration suite, ITSM, HR system, CRM, endpoint management, SIEM, internet edge, secrets store, clouds, and where sensitive data lives. Setup also sets the organisation name, the security contact shown to vendors (an email address), the customer's own sensitive-data labels (for example "Restricted" or "claims data"), the default secret rotation period, and how many days high, medium and low findings may stay open (default 30, 90 and 180). Every rule in RiskPrism then uses these personal settings. The organisation name and security contact appear on the vendor form and in the vendor message, so a vendor can tell who is asking and check before answering.
- **Import.** A CMDB or asset list in CSV or JSON. A ServiceNow CMDB export works as is.
- **Manual.** Add a system by hand.
- **Tenants map to vendors.** A tenant points at the vendor that hosts it. Integrations recorded against that vendor land on the main tenant there, not on every system the vendor hosts.
- **Drill-down.** The environment map has three columns: core systems, SaaS tenants, and outside vendors. Lines are coloured by the worst finding, and every box is clickable. Each system page shows who can reach it, the grants held in it, and the integration detail.

## Control objectives (`/controls`, vendor Controls tab)

- **Built in.** 20 objectives, 16 of them on by default, mapped to NIST 800-53, ISO 27001, SOC 2, PCI DSS, HIPAA, NERC CIP and AI frameworks (NIST AI RMF, ISO/IEC 42001, and EU AI Act Art. 25 and 26). The 16 are checked against evidence dates, the factsheet, live access, integrations, threat models and risk acceptances.
- **NERC CIP.** The CIP column references CIP-004, CIP-005, CIP-007, CIP-010, CIP-011 and CIP-013, and the framework selector on `/controls` includes **NERC CIP**. Requirement numbers are given without a version suffix: confirm them against the version you are audited to.
- **CIP-013 vendor commitments (off by default).** CO-17 to CO-20 cover the CIP-013 R1.2 items RiskPrism cannot observe for itself: vendor incident notification (R1.2.1), coordinated incident response (R1.2.2), software integrity and authenticity (R1.2.5), and vendor remote access controls (R1.2.6). They ship switched off and are attested by hand. An electric-sector customer switches them on under **Manage objectives**.
- **Results.** Met, partly met, not met, unknown or not applicable. Unknown is never treated as a pass.
- **Company settings.** The company can switch objectives off, scope them to vendor tiers, name an owner, and add its own objectives, either built from the same checks or attested by hand.
- **Attestation.** An analyst can attest one vendor's result, with a required note. The automatic result stays visible next to it.
- **Fair attribution.** A vendor answers only for integrations it starts, or that reach it from the customer's own systems. Another vendor's app in your tenant counts against that other vendor.

## Anticipated connections (vendor Integrations tab)

- **Inputs.** The vendor's category (set at intake), crossed with Your environment.
- **Connections.** Predicts single sign-on and provisioning through your identity provider, and the permissions a vendor of that kind usually asks for. Permissions are named the way your platform names them (Microsoft Graph, Google, Okta, AWS, Azure or GCP roles). Each comes with a narrower option, the data that would move, and the question to ask.
- **Their stack.** Lists what a vendor of that kind runs on (hosting, model provider, email delivery and so on), marked declared or not declared.
- **Confirming.** One click turns a prediction into a planned integration.

## Product catalog

- **Built-in profiles.** Common products, with their APIs, integration types, domains and app names.
- **Learned profiles.** Built from the customer's confirmed integrations (active and reviewed).
- **Export.** `/integrations/catalog.json` exports what was learned without owners, identities, tenant names, purposes or dates. Another deployment can import that file.

## Shadow IT (`/shadow`)

- **Inputs.** An organisation-wide connected-app export (Entra, Okta or Google), and a proxy, firewall or secure web gateway export of domains.
- **What it finds.** Unknown apps, apps from vendors that are not authorized, connections to approved vendors that were never recorded, and known SaaS products in use but not tracked.
- **Actions.** Start tracking an item, which creates a not-authorized vendor (for an app, with the app as its live access). Or mark it as known, which requires a note.

## Executive summary (`/executive`)

- **On the page.** A one-paragraph headline, a trend line, and summary counts including **Findings overdue**, then "What needs a decision", worst first, with each line linked to the engineer's detail. Below that, critical systems and who can reach them, and vendors by tier with their controls result.
- **Board pack.** `/executive/board.pdf` produces a PDF of the same content, with the trend line and a findings open (overdue) row. It also prints the audit log's head seal and entry count; file the PDF and you have a record outside the server to check the log against later.

## Findings worklist (`/findings`)

- **One list.** Integration findings, control objectives not met, open shadow IT items, and vendor flags (expired evidence, overdue reviews, live-access findings), worst first, filterable by source.
- **Stable keys.** Each finding has a key such as `F-3f9a1c0d2e`, built from where it came from. The same problem keeps the same key, so a ticket is raised once and its number shows on the worklist until someone clears it.
- **Deadlines.** Each finding records the day it was first seen and gets a due date from the customer's rule in Your environment (fix high, medium and low within N days; defaults 30, 90 and 180). The worklist shows days open, the due date or days overdue on each row, and an **Overdue** tile, and lists the most overdue first within each severity. A finding that goes away and comes back within 14 days keeps its original date; after that it starts again.
- **Trend.** One line of counts (total, high, medium, low, overdue, ticketed) is kept per day for 400 days in `data/findings_state.json`. The worklist, executive summary and board pack compare today with about 30 days ago and say what opened and closed since. Until there is a week of history it says so instead.
- **ServiceNow.** With `ENTROPY_SNOW_*` set, ticked findings become records in the chosen table (default `incident`) through the Table API, with impact and urgency from the severity, the finding key in `correlation_id`, and `due_date` from the finding's due date.
- **Jira.** With `ENTROPY_JIRA_*` set, they become issues in the chosen project through the REST API, labelled `riskprism`, `severity-<level>` and the key. `ENTROPY_JIRA_DUEDATE=1` also sets `duedate`; leave it off unless the project's create screen has Due date. The description of both carries first seen and due.
- **Without either.** Download the CSV (it imports into ServiceNow Import Sets and Jira's CSV import; it includes First seen, Due and Days overdue), then record each ticket number by hand. Cells that start with `=`, `+`, `-` or `@` are quoted so a spreadsheet does not run them.
- Credentials live only in environment variables. Ticketing addresses must be `https://`, and redirects are refused.

## Declared vs observed (vendor Integrations tab)

Each recorded integration with an app ID is shown side by side with what the identity provider export says that app holds:

- **Green:** declared and granted.
- **Red:** granted but never declared. This is drift and also raises the `scope_drift` finding.
- **Amber:** declared but not granted. It can usually be removed from the record, or consent was never given.

Apps in the vendor's live access that no integration records are listed as **not recorded**. A retired integration whose app still shows in live access is flagged **retired, still live**.
