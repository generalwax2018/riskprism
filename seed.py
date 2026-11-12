from __future__ import annotations

from parse_answers import apply as parse_apply
from records import load_vendor, save_vendor, slugify

SAMPLES = [
    {
        "vendor": "SiteCam Field",
        "website": "https://example.com/sitecam",
        "business": "Jobsite photo SaaS",
        "authorization": "authorized",
        "stage": "contracted",
        "soc2_expires": "2026-06-01",
        "pentest_expires": "2026-11-01",
        "next_review": "2026-08-15",
        "ai_used": "yes",
        "live_access": [
            {
                "id": "demo-oauth-slack",
                "kind": "oauth_app",
                "source": "demo",
                "display_name": "Slack",
                "app_id": "slack-demo",
                "scopes": ["chat:write", "users:read"],
                "status": "active",
                "notes": "Sample row.",
            }
        ],
    },
    {
        "vendor": "YardOps Access",
        "website": "https://example.com/yardops",
        "business": "Gate and badge vendor",
        "authorization": "authorized",
        "stage": "renewal_due",
        "soc2_expires": "2027-01-15",
        "pentest_expires": "2025-12-01",
        "next_review": "2026-09-01",
        "ai_used": "no",
    },
    {
        "vendor": "BrokerBox",
        "website": "https://example.com/brokerbox",
        "business": "Broker deal room",
        "authorization": "authorized",
        "stage": "contracted",
        "soc2_expires": "2026-12-20",
        "next_review": "2027-01-10",
        "renewal_status": "sent",
    },
    {
        "vendor": "LeaseAI Abstract",
        "website": "https://example.com/leaseai",
        "business": "Lease abstraction with a model on contracts",
        "authorization": "trial_only",
        "stage": "inquiry",
        "ai_used": "yes",
        "data_class": "critical",
        "questionnaire_status": "submitted",
        "answers": {
            "data": "Executed leases and abstracts — customer classifies as critical",
            "data_class": "critical",
            "hosting": "",
            "soc2": "Type I last year, cannot share full report under NDA",
            "ai_used": "yes we use a model on the lease text",
            "ai_models": "",
            "ai_train": "default on to improve the model",
            "ai_provider": "",
            "ai_region": "",
            "pentest_current": "Executive summary only, no findings attached",
        },
        "live_access": [
            {
                "id": "demo-oauth-unknown-ai",
                "kind": "oauth_app",
                "source": "demo",
                "display_name": "Unregistered AI assistant",
                "app_id": "shadow-ai-demo",
                "scopes": ["Files.ReadWrite.All", "Mail.Send"],
                "status": "active",
                "notes": "No matching vendor integration claimed on the questionnaire.",
            }
        ],
    },
]


def run():
    n = 0
    for row in SAMPLES:
        slug = slugify(row["vendor"])
        rec = load_vendor(slug) or {}
        rec.update(row)
        rec["slug"] = slug
        rec["source"] = "seed"
        if rec.get("answers") or rec.get("renewal_answers"):
            rec = parse_apply(rec)
        save_vendor(rec)
        n += 1
    return n
