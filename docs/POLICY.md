# Customer policy (`policy.json`)

This file is **the customer's rules**, not RiskPrism's.

- `restricted_models` — substrings in the vendor's model list that should flag (edit per tenant).
- `restricted_regions` — only evaluated when data is **critical**.
- `required_region_if_critical` — if true, missing region on critical data is a high follow-up.

Standard / sensitive data does not require region pin questions to pass.
AI always requires a named model list when a model touches content.

The copy in the repository is the default. Edits on the Policy page are saved to `DATA_DIR/policy.json` for this tenant. The checks are fixed rules, so they work with `ENTROPY_AI=off`.
