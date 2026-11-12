# Risk acceptance

A named approver accepts one detection on one vendor, for one org unit, until a date.
Nothing is permanent. When the date passes, the detection is open again.

Same process, no new dependencies. Org units and acceptances live in
`DATA_DIR/riskprism.db` (stdlib `sqlite3`), next to the notes, accounts and audit
tables. Only `risk_store.py` reads and writes these tables, and writes take the same
process-wide lock as the vendor files.

## Tables

| Table | Columns |
|---|---|
| `org_units` | `id, name, parent_id, accountable_owner, needs_review, merged_into, created_at, created_by` |
| `org_aliases` | `alias_key` (casefolded, whitespace collapsed), `raw` (Entra's spelling), `org_unit_id, first_seen, last_seen` |
| `approvers` | `principal` (lowercase sign-in name), `level`: `director` \| `vp` \| `ciso`, `set_by, set_at` |
| `acceptances` | `vendor_slug, vendor_name, detection_code, detection_text, org_unit_id, accepter, accepter_level, risk_tier, justification, compensating_controls, expires_on, risk_snapshot` (JSON), `signed_at, recorded_by, status`: `active` \| `expired` \| `superseded`, `status_at, legacy_ref` |

Signed rows are append-only, enforced by triggers. Only `status` can change, and only
from `active` to closed. Rows cannot be deleted. `expires_on` is required. The one
exception is **Delete all data** on the admin Data and audit page, which drops these
tables when you finish with an instance (the export taken before it has `risk_acceptances.csv`).

## Rules (`risk_rules.py`)

| Tier | Who may sign |
|---|---|
| Low, Medium | director, VP or CISO |
| High, Critical | VP or CISO |

- The tier can never go below the detection's own floor. A high flag is at least High,
  and the whole-vendor residual maps T1 to Critical, T2 to High, T3 to Medium and T4 to Low.
  So nobody can relabel a High as Medium to avoid the VP rule.
- The accepter is the signed-in identity. It is not a typed name.
- In `password` mode nobody can sign, because one shared password cannot say who accepted. `accounts` mode (including OpenID Connect sign-in), `easyauth`, and `none` on a laptop can sign.
- `expires_on` is required, cannot be in the past, and is capped at `ENTROPY_ACCEPT_MAX_DAYS`
  (default 365).
- A new acceptance for the same vendor and detection supersedes the active one.
- The snapshot records the detection, vendor fields, tiers, clocks, all current flags,
  open follow-ups and live access at the moment of signing.

## Expiry

An acceptance counts only while `status = 'active'` and `expires_on >= today`. That check
happens on read, so an expired acceptance stops covering its flag on the day after it
expires, even if nothing else runs. On each authenticated page load, `sweep_expired()`
stamps lapsed rows as `expired` and writes an `acceptance_expired` line to the audit log.

On `/alerts`, a covered flag stays in the list as **Accepted**, in blue (its own indigo,
not the Low blue; never green, because an acceptance is an exception, not a pass). It is
excluded from the red counts and the badge. When it expires, it goes red and counts again.
On the vendor page an acceptance shows blue, and amber in its last 30 days.

## Choosing the expiry

The signer always sets the date. Under the date field the form offers chips that fill it:

- 30 / 60 / 90 / 180 days. The one for the chosen tier is marked suggested
  (`risk_rules.SUGGEST_DAYS`: Critical 30, High 60, Medium 90, Low 180).
- Next security review and End of contract (`contract_end`, set with the other dates),
  when they fall inside the allowed range.
- **Ask AI for a date** (only when a model is configured and `ENTROPY_AI` is not `off`). `expiry_ai.suggest()` sends the
  detection, tier, the vendor's dates, open follow-ups and its answers (marked as vendor
  text) and gets back one date and a one-line reason. The date is range-checked with
  `expiry_problem()`; out-of-range or malformed replies are dropped. The suggestion only
  re-renders the form with an extra chip. It stores nothing and signs nothing; the call is
  audit-logged as `expiry_suggested`.

## Entra import

This is a file upload, not a live Microsoft Graph connection. It is separate from the Entra, Okta or Google app exports used for live access and shadow IT.

`/import`, **Import Entra users**. Upload the CSV from Entra ID (Users, then Download users).
Only the `department` column is read and no people are stored.

- A department string that is already known keeps its unit.
- An unknown string that matches a live unit's name (case-insensitive) maps to that unit.
- Any other unknown string creates a unit with `needs_review = 1`.
- Blank departments are counted and skipped. The import never stops on an unmapped value.

## Admin (`/admin/orgs`)

Admins are listed in `ENTROPY_ADMINS`, or, in `accounts` mode, marked admin on the People page. With `ENTROPY_AUTH=none`, everyone is an admin. A view-only person is never an admin, even if listed in `ENTROPY_ADMINS`, and cannot sign an acceptance.

- Edit a unit's name, parent and accountable owner. Saving clears **Needs review**.
  Parent cycles are refused.
- Merge unit A into B. A's aliases and children move to B. Signed acceptances keep A
  and roll up to B through `merged_into`.
- Re-point one department string to another unit.
- Set or remove approvers. Outside `none` mode, an admin cannot change their own level.

## Dashboard (`/risk`)

This page shows each unit in tree order, with its owner and its accepted, High+,
expiring-within-30-days and reopened-within-90-days counts. The counts include the units
underneath it. `?org=<id>` narrows the page to one subtree.

## Migration

On startup, `serve.main()` runs `risk_rules.migrate_legacy()`. Each old `exception` or
`exceptions[]` entry becomes a whole-vendor acceptance on **Unassigned (legacy
acceptances)**, with tier `unrated` and level `legacy`. The migration is idempotent on
`legacy_ref`. Vendor JSON is left untouched.
