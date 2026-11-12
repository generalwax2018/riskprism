# Live access module (v1)

Questionnaires go stale the day they are signed. This module records what a vendor
actually holds in the environment (OAuth apps, enterprise apps, service principals,
roles, tokens) and flags where that disagrees with what was assessed.

Same app, same vendor JSON. No SIEM. No second process. No new dependencies.

File import and the shadow IT queue have shipped. Queued UI work (portfolio glyphs, Accept the risk from the declared vs observed panel) lives in [docs/DESIGN_QUEUE.md](DESIGN_QUEUE.md).

## Data shape

`live_access[]` on `data/vendors/<slug>.json`, normalized by `access_store.normalize_row()`:

```
id, kind, source, display_name, app_id, scopes[], last_seen, first_seen, owner, status, notes
```

| Field | Values |
|---|---|
| `kind` | `oauth_app` \| `enterprise_app` \| `service_principal` \| `role` \| `token` |
| `source` | `demo` \| `manual` \| `entra` \| `okta` \| `google` \| `saas_audit` |
| `status` | `active` \| `stale` \| `revoked` |

Unknown keys are dropped, strings are length-capped, scopes are capped at 40.
`live_access_synced_at` is set when rows are replaced through `access_store.replace_rows()`.

## Importing an export (shipped, `access_import.py`)

Analysts can attach a real export to a tracked vendor: **Import CSV → Import live access**.

- Pick the vendor and where the export came from (Entra ID, Okta, Google Workspace, a SaaS audit, or a hand-made list). Upload CSV or JSON (a list of apps, or an object with a list under `value`, `items`, `apps` or `data`).
- Columns are matched by name, ignoring case, spaces and punctuation. Recognised names include application or display name, app ID or client ID, permissions or scopes, last sign-in, owner, type and status. The full list is in `access_import.ALIASES`.
- The app name column is required. A file without one is refused, and the error lists the columns it found.
- The import **replaces** the vendor's live access list with the file's contents, so upload the full list each time. Rows missing from the new file disappear.
- Rows with no name, duplicate apps, or unusable data are skipped and counted by reason. Limits: 1,000 rows and 2 MB per file.
- Dates are kept as written. The importer never invents a sign-in date.
- Each import writes an audit entry with the file name, row count and previous count.

The importer makes no API calls and stores no user records. Flags recompute on the next page load.

The same parser reads the organisation-wide export on the shadow IT page (`/shadow`). There the apps are not attached to one vendor; see `docs/DATA_LAYER.md`.

## Rules (`access_flags.findings`)

Deterministic. No model calls.

| Code | When | Severity |
|---|---|---|
| `access_after_offboard` | Vendor is offboarded or blocked and still has `active` access rows | high |
| `access_blind` | `authorization = authorized` and no live access on file | medium |
| `access_write_scope` | An active row holds write-class scopes (mail send, file/directory/app write, full control) and the questionnaire never mentioned write or mail access | medium |

Access flags appear on `/alerts` next to evidence-clock flags. `access_after_offboard`
is the one flag that still shows for an offboarded vendor, because live access after
offboarding is exactly what a human must see. The row button opens follow-up questions.
Signing a residual does not clear these flags.

## Where it shows

- **Renewals & evidence** (`/alerts`): the flag queue.
- **Vendor → Overview → Live access**: each access row (name, kind, source, last seen, scopes, status) plus the flags it raises. Read-only in v1.
- **Vendor → Integrations → Declared vs observed**: the scopes declared on each recorded integration against what the imported export shows for the same app ID, plus live apps no integration records. See `docs/INTEGRATIONS.md`.
- **Shadow IT** (`/shadow`): apps in an organisation-wide export that match no tracked vendor. **Start tracking** creates a not-authorized vendor with the app as its live access. See `docs/DATA_LAYER.md`.
- Queued: Grant glyph on the portfolio; Accept the risk from the declared vs observed panel.

## What v1 does not do

- Change a score, resolve a follow-up, sign a residual, or write `authorization`.
- Revoke anything. Offboard still only revokes vendor magic links; live access after offboard is a high flag for a person. The IdP revokes.
- Call Grok, Entra, Okta or Google. There is no live connector: rows come from a file you upload or from sample data. A connector is queued (see DESIGN_QUEUE §7).

## Try it locally

```
python serve.py
```

Open `/alerts` → **Load sample clocks**. The samples include live access on
**SiteCam Field** (Slack) and **LeaseAI Abstract** (an unregistered AI assistant with
`Files.ReadWrite.All` and `Mail.Send`). Open either vendor to see the Live access card.

`access_demo.seed_first_tracked()` can attach the same sample rows to the first tracked
vendor from a Python shell; there is no button or route for it.

## Next

See the roadmap in [docs/DESIGN_QUEUE.md](DESIGN_QUEUE.md). Done: file import of an Entra / Okta / Google app export into this list, the shadow IT queue with Start tracking, and the declared vs observed panel. Still to do:

1. Portfolio Grant glyph, and Accept the risk from the declared vs observed panel.
2. AI factsheet Unknowns feed the AI questionnaire's gap questions (NIST AI RMF, EU AI Act, ISO 42001 addendum on Start tracking).
3. Grok on click only: classify an unknown app, draft the vendor email.
4. Live Entra connector, once the file import has seen real use.
