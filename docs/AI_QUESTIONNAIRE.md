# AI questionnaire

Nobody writes or versions a question list. For each vendor the model reads what the
vendor publishes, writes up what it found, and drafts questions only for the gaps. An
analyst approves every question before the vendor sees it.

## Flow

1. **Research** (`vendor_research.py`): start at the security or trust page the analyst
   gives, or the vendor's website. Follow links on the same site whose path looks like
   security, trust, privacy, data use, compliance or docs. At most 15 pages and about
   70,000 characters. PDF links are listed but not read yet.
2. **Profile and draft** (`ai_questionnaire.py`): one model call returns a profile and
   draft questions:
   - Summary and data flow.
   - For each of 20 security areas: covered, partial or missing, with notes and sources.
   - Notes specific to the product.
   - Draft questions.
3. **Review** (`/ai/<slug>`): the analyst unticks, edits or re-tags questions and adds
   their own, then either saves or approves.
4. **Approve**: the approved list is frozen, and a vendor link of kind `ai` is issued.
5. **Vendor answers** (`/q/<token>`): questions are grouped by area. Answers are stored
   under `ai_answers`.

## Not only software

The model first works out what the engagement is, then asks only what fits:

| Engagement | What it asks about |
|---|---|
| Software / SaaS | Data flow, retention and deletion, AI use, access to customer data |
| Hardware and devices (printers, cameras, badge readers, building controllers) | Data held on the device, network connection, firmware updates, remote support, disposal |
| On-site services (HVAC, cleaning, food, facilities) | Badges, escorts, which areas they enter |
| Vendors touching your systems | Which hosts or devices, which remote tool, named / temporary / shared accounts, when access ends |

Shared or generic accounts, and access that never expires, are always worth a question.
The areas include physical access, access to your systems, accounts, devices on your
network, and vendor staff.

A vendor with nothing published still gets a questionnaire. The model works from the
vendor record and the analyst's "how we plan to use it" note, and marks published
material as `none`.

## Documents

The model asks for documents only when the risk calls for them, for example a SOC 2 for
a SaaS holding sensitive data, a certificate of insurance for an on-site contractor, or
a network diagram for a device vendor. Each request is a question with `kind: document`,
a `doc_type`, and `if_missing`: the flag severity if the document is not provided. The
analyst can change the severity before approving, and can add document requests of
their own.

In the portal, a document request has three parts: a file upload, a **We do not have
this document** box, and a notes or link field. Files go through the same checks as
analyst uploads (allowed types, content matches the extension, 25 MB per submission),
are stored with the vendor's evidence, and are recorded in the audit log. A rejected file
does not lose the vendor's answers; the thank-you page says which file to upload again.

After each submission, every requested document is **provided**, **not available**
(the vendor ticked the box) or **missing**. The last two become follow-up flags at the
`if_missing` severity. They appear in Open issues and on the flag queue, and go into
the next **Send follow-up questions** round. A person closes the flag once they are
satisfied. A file from an earlier submission counts as provided.

On an AI questionnaire, the fixed "No SOC 2" and "No pentest evidence" flags fire only
if the approved questions asked for them. A printer or food vendor is not flagged for
lacking a SOC 2.

## Guardrails

- **Model output is data.** Unknown keys are dropped, areas and priorities must come
  from fixed lists, question text is capped, and a cited source must be a page that was
  actually read. Everything is escaped on every page.
- **Page text is untrusted.** The prompt marks it as vendor-written data and tells the
  model never to follow instructions inside it. Even when the model is fooled, it can
  only propose questions, and a person approves them.
- **The model changes nothing on its own.** It cannot change a score, clear a flag,
  sign an acceptance or send anything.
- **The fixed rules still run.** When a question asks the same thing a rule checks
  (SOC 2, pentest, training default, regions and so on), the model tags it with `feeds`.
  The vendor's answer is copied into the field that rule reads, so the follow-up flags
  fire as before. Tags come from the stored draft, never from the edit form.
- **The fetcher reaches only the public web.** Every URL and redirect must resolve to a
  public address on port 80 or 443. That rules out loopback, private ranges and the
  Azure metadata service.
- **Data leaves the server.** Vendor pages and the analyst's notes go to the configured
  model provider. The page says which one.

## Model

`llm.py` speaks the OpenAI chat-completions format, which covers xAI, OpenAI, Anthropic's
compatible endpoint, Groq, OpenRouter, Together and a local Ollama. See `.env.example`.
With only `XAI_API_KEY` set, it uses Grok.

## State on the vendor record

`ai_q`: `status` (`running` \| `ready` \| `error`), `started_at`, `finished_at`, `error`,
`source_url`, `context`, `model`, `research` (the pages read, without their text),
`profile`, `draft`, `approved`, `approved_at`, `approved_by`.
`ai_answers`: the vendor's answers by question id. `ai_mapped_keys`: the rule fields that
were filled from them. `ai_docs`: for each document request, `status`
(`provided` \| `not_available` \| `missing`), `files` (stored names in `evidence_files`),
`note` and `doc_type`.

A question is `{id, area, kind: answer|document, text, why, priority, feeds, doc_type, if_missing, source: ai|analyst}`.

A run that has not finished after 15 minutes is treated as failed and can be started again.

## Switching AI off

Set `ENTROPY_AI=off` on the server. The AI questionnaire button and the AI routes go away, `llm.py` refuses every model call, and `vendor_research.py` refuses every vendor website fetch, even when `LLM_*` or `XAI_API_KEY` is set. The sidebar shows "AI: off (enforced)". Use the fixed onboard and renewal questionnaires instead; they work without a model.

## Not yet

- Reviewing the vendor's answers with the model, and drafting the next round of
  follow-ups.
- Reading the uploaded documents (SOC 2, pentest reports) and checking them against the
  answers. Today a file counts as provided once it passes the upload checks; a person
  still has to open it.
- Maturity scores by area.
