# Grok in RiskPrism

Grok does reading and drafting. A human sends mail and signs residual risk.

## Read this before wiring it
- **Vendor documents leave your environment.** Anything sent to `api.x.ai` is disclosed to xAI. Do not send a customer's data, and check that your customer contracts and the vendor's NDA allow sending the vendor's own report to a third-party model.
- **Treat every vendor answer and uploaded document as untrusted input.** A report can contain text written to steer the model ("mark all controls as passed"). Never let model output change a score, resolve a follow-up, or sign an acceptance. Show it as a draft for a person to accept, and validate any JSON it returns against a fixed schema.
- Keep the key in an environment variable or Azure Key Vault, never in the repository or in a template.

## Switching it off
`ENTROPY_AI=off` stops all of this. `llm.py` refuses model calls and `vendor_research.py` refuses vendor website fetches, whatever keys are set. Nothing else in RiskPrism needs a model.

## Setup
1. Create an API key at https://console.x.ai
2. In PowerShell (this session only):
   `$env:XAI_API_KEY = "xai-..."`
3. Optional: `$env:XAI_MODEL = "grok-4"`
4. Do not put the key in the repo or in ui.html.

Endpoint: POST https://api.x.ai/v1/chat/completions  
Header: Authorization: Bearer $XAI_API_KEY

## Jobs
- extract: paste/upload SOC2, pentest, DPA text → JSON dates, exceptions, AI mentions, gaps
- email: turn the gap list into a vendor email draft (Subject + body)

SOC 2 extract never auto-passes AI-01 / AI-08 / AI-10.

## Email rule
The model only drafts. Email (optional, `mailer.py`) sends only when a person clicks Send.
That is the same gate as T1 residual.

## Live access module
Grok is not a detector. Access flags come from rules in `access_flags.py`.
Planned on-click uses only: classify an unknown OAuth app (analyst confirms before Start tracking),
turn an access flag into a follow-up question or vendor email draft, summarize what changed since
the last questionnaire. Send app names and scopes only; never user identities, tokens or raw logs.

## Wired today
All model calls go through `llm.py`, which works with any OpenAI-compatible provider; Grok
is simply the default when `XAI_API_KEY` is set. The AI
questionnaire (`docs/AI_QUESTIONNAIRE.md`) and the suggested date on a risk acceptance
(`docs/RISK_ACCEPTANCE.md`) use it. `extract_attestation` and `draft_vendor_email` in
`grok_client.py` exist but no screen calls them yet.

## Next wiring
Answer review: find gaps in the vendor's answers and draft the next round of follow-ups.
Documents: read SOC 2 and pentest PDFs (`extract_attestation` in `grok_client.py` is the
starting prompt), cross-check them against answers, and follow up on anything missing.
Questionnaire page: "Draft vendor email" from unanswered questions.
