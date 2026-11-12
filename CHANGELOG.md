# Changelog

## 0.9.0 — 2026-11-11

First public release, as open source under the MIT license. Beta: one instance per organisation.

- Portfolio with inherent and residual tiers, a "waiting on a human" gate, evidence clocks and a flag queue.
- Vendor questionnaires over expiring links, including an optional AI-drafted questionnaire built from the vendor's published security pages (analyst approves every question; `ENTROPY_AI=off` removes it).
- Live access and shadow IT from identity-provider exports, with declared vs observed drift.
- Integrations, your environment, control objectives mapped to NIST 800-53, ISO 27001, SOC 2, PCI DSS, HIPAA, NERC CIP and AI frameworks, threat models and an executive summary with a board pack.
- Findings with due dates from your own rule, overdue counts and a trend, raised as ServiceNow or Jira tickets or exported as CSV.
- Risk acceptance by org unit, approver tier and expiry.
- Per-person accounts with authenticator MFA, single sign-on (OIDC), admin and view-only roles.
- Tamper-evident audit log (HMAC seal chain in SQLite).
- Optional email (vendor links, invites, weekly digest), nightly backups and restore, a full export, sample data removal and delete-all.
- Glass interface that follows the system light or dark setting; no page loads anything from another host.
- 281 tests.

Earlier history is in the git log.
