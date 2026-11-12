"""Sample live-access rows for local demo. Does not invent architecture."""
from __future__ import annotations

from access_store import replace_rows
from records import list_vendors, update_vendor

SAMPLES = [
    {
        "id": "demo-oauth-slack",
        "kind": "oauth_app",
        "source": "demo",
        "display_name": "Slack",
        "app_id": "slack-demo",
        "scopes": ["chat:write", "users:read"],
        "status": "active",
        "notes": "Sample row. Replace with a real connector later.",
    },
    {
        "id": "demo-oauth-unknown-ai",
        "kind": "oauth_app",
        "source": "demo",
        "display_name": "Unregistered AI assistant",
        "app_id": "shadow-ai-demo",
        "scopes": ["Files.ReadWrite.All", "Mail.Send"],
        "status": "active",
        "notes": "No vendor record matched this name — treat as shadow IT.",
    },
]


def seed_first_tracked() -> str | None:
    """Attach sample rows to the first non-offboarded tracked vendor."""
    for rec in list_vendors():
        slug = rec.get("slug")
        if not slug or rec.get("stage") == "offboarded":
            continue
        update_vendor(slug, lambda r: replace_rows(r, SAMPLES))
        return slug
    return None
