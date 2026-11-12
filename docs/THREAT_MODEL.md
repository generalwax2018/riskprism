# Vendor threat model

Each vendor has one threat model. It lives in a **Threat model** tab on the vendor record, next to Overview, Questionnaire and Activity. It is built from the vendor record on every view, so it is never out of date and there is no generate or refresh step. Analysts add only their decisions, and those are stored. Nothing in the model is scored by a model.

## What the tab shows

Every section is computed from the record as it is now:

1. Document control: version, status, last review, what changed since that review, and the history of reviewed versions
2. Scope summary: from the vendor record
3. Proposed target design: a statement an analyst writes, next to the facts the record holds
4. System inventory: the vendor service, your tenant, each active connected app from live access, the model provider and sub-processors, as declared
5. Data flow and trust boundaries: an architecture diagram of the zones, systems, flows and boundaries, then each flow with the trust boundary it crosses
6. Trust boundaries: seven fixed types (customer data intake; vendor access to your tenant; data leaving the service; vendor staff access; sub-processors and model providers; location and transfers; exit and deletion), each known or unknown from the record
7. Threat table: fixed STRIDE prompts per boundary, with a LINDDUN privacy prompt where personal data is involved. AI prompts apply only when AI touches your data
8. Open questions: one per unknown boundary, plus each factsheet gap, each with an owner and an answer
9. Sign-off: accepted threats and the review record

Threat and question IDs are stable (`TB-1.spoof_link`, `Q-…`), so a decision stays attached to its threat when the record changes.

## Architecture diagram

Every vendor gets the same diagram, drawn from the record each time the tab opens. It has four zones: your organisation (the people who submit data, your tenant and identity provider, each connected app, and where exports land), the vendor (its service and its staff), sub-processors and AI providers, and hosting and exit (data at rest and copies after the contract ends). Arrows are the flows F-1 to F-7. Each flow carries an orange `TB-n` marker where it crosses a trust boundary.

A solid blue arrow is a flow the record supports. A red dashed arrow crosses a boundary the record has not confirmed, and the box it points to says so. Answering that boundary's open question confirms it and turns the arrow solid. Long lists of apps or sub-processors are shortened to "+ n more", and the full list stays in the system inventory.

The diagram is in the tab, can be downloaded as SVG, and is in both exports on its own landscape page. The PDF draws it as vector graphics. The Word file embeds it as SVG, which Word 2016 and later display. Older versions of Word show a plain picture of the shapes without labels.

## What an analyst does

Each threat gets a scenario, a likelihood and an impact from 1 to 5, a disposition (open, mitigate, accept, transfer, eliminate), mitigations (one per line, required to mitigate) and a reason for the rating. The rating is likelihood times impact: 20 or more is Critical, 12 to 19 High, 6 to 11 Medium, 5 or less Low.

Accepting a threat uses the same rule as risk acceptance. The approver must be registered for the rating's tier (Low and Medium: director, VP or CISO; High and Critical: VP or CISO), and the expiry must be a future date within `ENTROPY_ACCEPT_MAX_DAYS`. When an acceptance passes its expiry, the threat goes back to needing a decision.

Review records the model as it stands today as a numbered version. It is blocked while any threat needs a decision. The review records who reviewed it, when, a note, and the counts.

## When the model needs review

After a review, the tab marks the version **Needs review** when something it depends on has changed. The tab lists what changed: authorization, stage, delivery, hosting, AI use, model provider, sub-processors, SSO, data collected, connected apps, factsheet gaps, new threats that apply now, and accepted threats past expiry. Reviewing again records a new version. Earlier versions stay in the history.

A threat that no longer applies (for example AI prompts after a vendor stops using AI) is not shown in the threat table. A decision made on it is kept and listed as no longer applying.

## Export

Export Word (`.docx`) or PDF from the tab. Both files are generated on request from the current record and decisions, so they match what the tab shows. The Word file uses real tables and a page-number footer. The PDF uses standard fonts and repeats table headers on each page. Both are written without any extra software on the server. A model that has not been reviewed is labelled as a draft.

## Audit

Every decision, acceptance, question answer, design change, review and export writes an audit line with the analyst's identity.

## Not in this version

- Editing systems and flows by hand. They come from the record; analysts add context through the design statement and open questions.
- Scoring likelihood or impact from data. Ratings are judgment.
- A library of threats from outside sources.
- Diagrams.
- AI-drafted scenario wording. It can be added later as an explicit, labelled click, like the questionnaire drafts.
