# Integrations data layer

RiskPrism records every connection between your SaaS tenants, your vendors and your own systems: who it acts as, what it was granted, and what data moves. The record sits under each vendor (the **Integrations** tab) and rolls up to one dashboard (**Integrations** in the sidebar).

One integration connects two parties. A party is a tracked vendor, meaning your tenant or instance at that vendor, or **Your organisation** (your network, people and on-premises systems). For example, "ServiceNow Entra ID spoke" runs from ServiceNow to Microsoft 365, because ServiceNow calls Microsoft Graph with permissions granted in your Entra tenant.

## What each integration records

- **Mechanism:** single sign-on, SCIM provisioning, app-only OAuth, delegated OAuth, a vendor-built connector, API key, inbound or outbound webhook, on-premises agent, email, or file transfer.
- **Authentication:** the method, the identity it acts as (an app registration, a service account, or each user), the roles that identity holds, the credential, where it is stored, and when it was last rotated.
- **Scopes:** each permission exactly as the platform names it. Each one is marked as granted to the app itself (application), on behalf of a user (delegated), or as a role in the target.
- **Data flows:** for each flow, from, to, the data, when it moves, and the endpoint.
- **Network:** outbound domains, inbound endpoints, whether inbound calls are verified, and whether IP allow-listing is in place.
- **Ownership:** the owner, the status (active, planned or retired), and the last review date.

Integrations are stored in `data/integrations.json`, because one integration touches two vendors.

## Findings (fixed rules, no model)

| Finding | Severity |
|---|---|
| A permission that administers the tenant (for example `Directory.ReadWrite.All`) | High |
| An app-only write permission across the whole tenant (`*.ReadWrite.All`) | High |
| The integration signs in as an admin identity | High |
| Sensitive data (email, chat, HR, personal, health, payment, credentials, tickets) going to a vendor that is not authorized or is offboarded | High |
| Live access shows scopes that were never declared, or a retired integration is still live | High |
| An app-only send or act permission (for example `Mail.Send` as the application) | Medium |
| An elevated role (for example `user_admin` or `itil`) | Medium |
| A secret past its rotation period, or with no rotation date | Medium |
| Inbound calls not verified | Medium |
| No named owner | Medium |
| A static secret, refresh tokens (`offline_access`), no IP allow-list, or not reviewed in 12 months | Low |

The scope classes (admin, write, read, session, identity) come from rules on the permission name. `*.OwnedBy` permissions are not treated as tenant-wide.

## Making sure every vendor is covered

- **At intake**, the onboarding form asks whether the vendor will connect to your systems, and which ones.
- **The vendor questionnaire** always includes "E. Integrations and permissions": what it connects to and how, every permission exactly as named and why, whether it needs admin or tenant-wide write, whether a permission can be narrowed, credentials and rotation, data each way, inbound endpoints and how calls are signed, domains to allow-list, and onward parties. The renewal questionnaire asks what changed.
- **The AI questionnaire** always includes a required integrations question. An analyst can reword it but cannot remove it.
- **Follow-ups** are raised automatically when the vendor connects but lists no permissions or credentials, needs admin rights, exposes an endpoint without saying how calls are signed, or is unsure whether it connects.
- **Coverage:** the dashboard lists vendors that connect but have no integration recorded, and vendors that have not been asked yet.
- **Drafts:** on the vendor's Integrations tab, "Draft an integration from these answers" creates a planned integration. It copies the scope names, domains and credential type as written, nothing more. The owner then answers the listed questions for the owner, and the integration moves from Planned to Active once confirmed.
- **Observed access:** imported Entra, Okta or Google exports are compared with what was declared.

## Dashboard

The dashboard shows summary counts, a map of parties coloured by the worst finding, findings worst first, onward paths for sensitive data, vendors not covered yet, all integrations, every scope and role granted (most powerful first), and every data flow. You can filter it by vendor. In a local or demo run, "Load sample integrations" adds Microsoft 365, ServiceNow and Workday examples and two fictional vendors.

## Onward paths

For each flow that carries sensitive data, the dashboard follows any further flow out of the destination, up to three hops. This shows what is reachable, not what is proven to move. It answers questions such as "HR data from Workday can reach an AI note-taker through ServiceNow and Microsoft 365".
