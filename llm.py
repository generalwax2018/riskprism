"""Model layer. Any provider that speaks the OpenAI chat-completions format works:
xAI (Grok), OpenAI, Anthropic's OpenAI-compatible endpoint, Groq, OpenRouter,
Together, Azure AI Foundry, or a local Ollama / LM Studio.

LLM_BASE_URL   e.g. https://api.x.ai/v1 (default when only XAI_API_KEY is set),
               https://api.openai.com/v1, http://127.0.0.1:11434/v1 for Ollama
LLM_API_KEY    falls back to XAI_API_KEY; may be empty for a local model
LLM_MODEL      falls back to XAI_MODEL, then grok-4
LLM_TIMEOUT    seconds per call (default 180)

Model output is untrusted. Callers get parsed JSON and must validate every field
against a fixed schema before it touches a record.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

import config


class LLMError(RuntimeError):
    pass


def settings() -> dict:
    key = (os.environ.get("LLM_API_KEY") or os.environ.get("XAI_API_KEY") or "").strip()
    base = (os.environ.get("LLM_BASE_URL") or "").strip().rstrip("/")
    if not base and os.environ.get("XAI_API_KEY"):
        base = "https://api.x.ai/v1"
    model = (os.environ.get("LLM_MODEL") or os.environ.get("XAI_MODEL") or "grok-4").strip()
    try:
        timeout = int(os.environ.get("LLM_TIMEOUT") or 180)
    except ValueError:
        timeout = 180
    return {"base": base, "key": key, "model": model, "timeout": timeout}


def enabled() -> bool:
    """False when the operator has switched AI off with ENTROPY_AI=off. Checked on every call."""
    return config.AI_ENABLED


def configured() -> bool:
    if not enabled():
        return False
    s = settings()
    return bool(s["base"]) and (bool(s["key"]) or s["base"].startswith(("http://127.0.0.1", "http://localhost")))


def describe() -> str:
    """Shown to analysts: which model is doing the work. Never includes the key."""
    if not enabled():
        return "AI switched off (ENTROPY_AI=off)"
    s = settings()
    if not configured():
        return "No model configured"
    host = re.sub(r"^https?://", "", s["base"]).split("/")[0]
    return "%s via %s" % (s["model"], host)


def chat(system: str, user: str, *, max_tokens: int = 8000, temperature: float = 0.2) -> str:
    if not enabled():
        raise LLMError(config.AI_OFF_MESSAGE)
    s = settings()
    if not configured():
        raise LLMError("No model is configured. Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL (or XAI_API_KEY).")
    payload = {
        "model": s["model"], "temperature": temperature, "max_tokens": max_tokens,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    headers = {"Content-Type": "application/json"}
    if s["key"]:
        headers["Authorization"] = "Bearer " + s["key"]
    req = urllib.request.Request(s["base"] + "/chat/completions", data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=s["timeout"]) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise LLMError("The model provider refused the request (HTTP %d): %s" % (e.code, detail))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise LLMError("Could not reach the model provider: %s" % e)
    except ValueError:
        raise LLMError("The model provider sent back something that is not JSON.")
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise LLMError("The model provider's reply had no message in it.")


def parse_json(text: str):
    """Pull one JSON object out of a model reply (tolerates code fences and chatter)."""
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    try:
        return json.loads(t)
    except ValueError:
        pass
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(t[start:end + 1])
        except ValueError:
            pass
    raise LLMError("The model did not return valid JSON.")


def chat_json(system: str, user: str, **kw):
    return parse_json(chat(system, user, **kw))
