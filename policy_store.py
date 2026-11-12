from __future__ import annotations

import json
from pathlib import Path

import config
from records import atomic_write

DEFAULT = Path(__file__).resolve().parent / "policy.json"
PATH = config.DATA_DIR / "policy.json"
_FALLBACK = {"restricted_models": [], "restricted_regions": [], "required_region_if_critical": True}


def load():
    """The tenant's saved policy, else the default shipped in the repo."""
    for p in (PATH, DEFAULT):
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                pass
    return dict(_FALLBACK)


def _clean(text: str) -> list[str]:
    out = []
    for ln in (text or "").splitlines()[:200]:
        ln = ln.strip()[:100]
        if ln and ln not in out:
            out.append(ln)
    return out


def save(models_text: str, regions_text: str, required: bool):
    data = load()
    data["restricted_models"] = _clean(models_text)
    data["restricted_regions"] = _clean(regions_text)
    data["required_region_if_critical"] = bool(required)
    atomic_write(PATH, json.dumps(data, indent=2))
    return data
