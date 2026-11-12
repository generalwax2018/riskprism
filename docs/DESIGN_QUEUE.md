# Roadmap

Planned work, roughly in order. Items marked SHIPPED are done and stay here as history. A change should bring its docs and tests in the same pull request. Want to take one on? Open an issue first (see `CONTRIBUTING.md`).

Product test: a stranger sees one vendor and says “the questionnaire and the grant don’t match” without a voiceover.

## 1. Portfolio glyphs + red on disagreement (queued)

**Files:** `portfolio.py`, `views.py`, `ui.html`, `static/app.css`, tests.

Three glyphs on every portfolio row:

- Clock — overdue / missing evidence (`alerts.py` clocks)
- Grant — any live-access flag (`access_flags.py`)
- Spark — AI factsheet has Unknown on a required field, or vendor is an unregistered AI app being tracked

If any glyph is active, the row is visually red / “disagreement” — not only when residual is High.
Glyph click goes to that panel on the vendor page (`#clocks`, `#drift`, `#factsheet`).

Home should also show **Waiting on a human: N** (draft tier, unsigned residual, T1 trial clock).

## 2. Drift split panel + typed “sign anyway” — PARTLY SHIPPED

**Shipped:** a Declared vs observed panel on the vendor Integrations tab (`integrations.drift()`, `integrations_views.drift_card`). It shows each recorded integration's declared scopes against what the imported identity-provider export holds for the same app ID, plus live apps no integration records. See `docs/INTEGRATIONS.md` and `docs/DATA_LAYER.md`.
**Still queued:** **Accept the risk** and the typed “sign anyway” straight from that panel, the three-column Overview layout, and the sentence flags between the columns. The text below is the original design for the queued part.

**Files:** `views.py`, vendor record template, `followup.py`, `access_flags.py` (sentences only).

Vendor → Overview becomes three columns / stacked on mobile:

- Left: assessment facts that matter for access (read vs write, mail, files, training default).
- Right: `live_access[]` rows (name, kind, source, last seen, scopes, status).
- Between: the three rules as sentences a person can paste.
  Example: `Offboarded 12 Sep. LeaseAI still active with Files.ReadWrite.All.`

Actions: **Ask follow-up** (existing) and **Accept the risk** (the existing risk acceptance: approver by tier, why, controls, expiry). Accepting does not clear the flag; it turns it blue until the expiry date (`docs/WORKFLOWS.md` §5a).
Empty live access: “Upload an Entra / Okta / Google export” pointing at item 4.

Do not add charts.

## 3. Unregistered board + Start tracking — SHIPPED

Lives at `/shadow` (`shadow.py`, `shadow_views.py`), not `/unregistered`. It imports an organisation-wide Entra, Okta or Google connected-app export and a proxy domain CSV, and sorts items into unknown app, vendor not authorized, approved vendor with the connection not recorded, and shadow SaaS. **Start tracking** creates a not-authorized vendor with the app as its live access. **Mark as known** needs a note. There is no “Ignore 30 days” or “It’s us” action. See `docs/DATA_LAYER.md`.

The text below is the original design, kept as history.

**New route** e.g. `/unregistered` (Find in the loop).

Rows that are *not* yet vendors: display name, scopes, first seen, source.
Actions: **Start tracking** (creates vendor JSON, authorization=not_authorized, attaches live_access) / **Ignore 30 days** / **It’s us (internal)**.

Sample data: keep LeaseAI Abstract as the demo of an AI assistant with write + mail scopes and no prior vendor record.

Update `docs/ACCESS_MODULE.md` and `docs/WORKFLOWS.md` §1 when this ships.

## 4. File import into `live_access[]` — SHIPPED

Lives in `access_import.py` (Import CSV → Import live access). See `docs/ACCESS_MODULE.md`.

CSV or JSON upload. Columns map to `access_store.normalize_row()`.
Sources: `entra` | `okta` | `google` | `saas_audit` | `manual`.
Replace rows through `access_store.replace_rows()`; set `live_access_synced_at`.
No API to the IdP. Cap rows. Reject unknown keys (already the store contract).

This is what makes glyphs and the drift panel real in your own tenant.

## 5. Gap-only questionnaire + factsheet Unknowns (queued)

Questionnaire pack generated from product_description + evidence gaps + factsheet Unknowns.
Prefill known answers; lock them on the vendor portal (“we already have SOC 2 through Mar 2027”).
Factsheet is toggles/enums only. Each field: Known / Unknown / Evidence id.
A model may draft; it cannot set Unknown to No.
Unknown on required AI fields keeps `human_required`.

## 6. Trial strip on T1 / AI-unknown (queued)

`engagement_stage` + trial dates from `docs/PRODUCT_SCOPE.md`.
Bar: Day 0 · 30 · 60 · 90.
Day 30: T1 or AI-01/08/10 unknown → human extend or kill. Agents remind; they do not extend.
Day 60: SOC 2 / pentest still missing on T1/T2 → residual High.
Day 90: no signed residual → default reject for production data.
Bar never auto-greens.

## 7. Then email, then IdP API

Email: SHIPPED (2026-11-11), optional, through your own SMTP server (`mailer.py`): vendor links from the share page, invite links, a weekly digest. Reminders before evidence or acceptances expire are still queued.
A live Entra/Okta/Google connector comes after the file import has seen real use. The file import has shipped; the connector is still queued.

## Tests expected

- Glyph / disagreement classification on sample vendors (SiteCam Field, LeaseAI Abstract).
- Access-after-offboard still appears for offboarded vendors.
- Import normalizes and replaces; flags recompute.
- Start tracking from the shadow IT queue creates one vendor file and does not invent architecture (`test_track_and_decide` in `tests/test_data_layer.py`).
- Factsheet Unknown blocks auto-pass.
- Trial day-30 cannot be extended by a model path (there must be no such path).

## Docs to touch in the same work

`README.md` · `docs/STATUS.md` · `docs/WORKFLOWS.md` · `docs/ACCESS_MODULE.md` · `docs/PRODUCT_SCOPE.md`.
