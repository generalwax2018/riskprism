# Contributing

Thanks for helping. RiskPrism is small on purpose: Python standard library only (3.10 and newer), server-rendered pages, no build step, and nothing that loads from another host.

## Before you open an issue

- Do not paste real vendor answers, documents, `secret.key`, session cookies, vendor links, audit exports or anything from a live data folder. Describe the steps and use made-up names.
- Security problems go through a private advisory, not an issue. See [SECURITY.md](SECURITY.md).

## Changes

1. Open an issue first for anything larger than a fix, so we can agree on the shape. The roadmap is [docs/DESIGN_QUEUE.md](docs/DESIGN_QUEUE.md).
2. Keep the product rules at the end of the README. In short: unknown is never a pass, a named person signs every risk decision, and a model may draft but never changes a score, resolves a flag or offboards a vendor.
3. No new dependencies. Optional integrations talk HTTP with `urllib`, as the ServiceNow, Jira, OIDC and model clients do.
4. Escape by default. Templates use `{{x}}`; `{{!x}}` is only for fragments already built with `esc()`. Every POST carries the CSRF token. Use the colour tokens in `static/app.css`, never fixed colours, so light and dark both work.
5. Add a test. Run `python3 -m unittest discover -s tests -v` before you push. The tests use a temporary data folder and need no network.
6. Update the docs the change touches, and add a line to `CHANGELOG.md`.

By contributing you agree your work is released under the MIT license.
