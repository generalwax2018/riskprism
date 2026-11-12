"""Tiny HTML templating that escapes by default.

  {{name}}   value is HTML-escaped (use this for anything a person typed)
  {{!name}}  value is inserted as-is (only for HTML this program built itself)

Templates are plain files next to this module and are re-read on every request,
so an edit shows up without restarting.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

BASE = Path(__file__).resolve().parent
_PLACEHOLDER = re.compile(r"\{\{(!?)([a-zA-Z0-9_]+)\}\}")
_POST_FORM = re.compile(r'(<form\b[^>]*\bmethod="post"[^>]*>)', re.IGNORECASE)


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def read(name: str) -> str:
    return (BASE / name).read_text(encoding="utf-8")


def fill(template: str, **vals) -> str:
    def sub(m):
        raw, key = m.group(1) == "!", m.group(2)
        v = vals.get(key, "")
        return "" if v is None else (str(v) if raw else esc(v))
    return _PLACEHOLDER.sub(sub, template)


def render(name: str, **vals) -> str:
    return fill(read(name), **vals)


def add_csrf(page_html: str, token: str) -> str:
    field = '<input type="hidden" name="_csrf" value="' + esc(token) + '">'
    return _POST_FORM.sub(lambda m: m.group(1) + field, page_html)


def json_for_script(obj) -> str:
    """JSON that is safe inside a <script type="application/json"> block."""
    import json
    return json.dumps(obj).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
