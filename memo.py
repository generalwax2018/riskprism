"""Per-request memory for expensive read-only results.

One page often asks for the same thing several times (every vendor record, the integrations overview).
Inside a request, the first answer is kept and reused. It is thrown away when:
  - the request ends (so nothing is ever older than one page load, and date-based rules stay current), or
  - anything is written (records.atomic_write and delete_vendor bump a generation counter, so a page
    that saves and then re-renders always sees the saved data).

Outside a request (tests, the command line) nothing is cached and every call computes afresh.
Cached values are shared within the request: callers must treat them as read-only.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager

_local = threading.local()
_gen_lock = threading.Lock()
_generation = 0


def bump() -> None:
    """Something on disk changed: every cached answer, in every thread, is stale."""
    global _generation
    with _gen_lock:
        _generation += 1


@contextmanager
def request():
    _local.cache = {}
    try:
        yield
    finally:
        _local.cache = None


def cached(key, compute):
    cache = getattr(_local, "cache", None)
    if cache is None:
        return compute()
    gen = _generation
    hit = cache.get(key)
    if hit is not None and hit[0] == gen:
        return hit[1]
    value = compute()
    cache[key] = (gen, value)
    return value
