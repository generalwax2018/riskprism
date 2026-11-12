#!/usr/bin/env python3
import json
from datetime import date
from pathlib import Path

OUT = Path(__file__).resolve().parent / "out"


def cls(t):
    if t.startswith("T1"):
        return "t1"
    if t.startswith("T2"):
        return "t2"
    if t.startswith("T3"):
        return "t3"
    return "t4"


def main():
    data = json.loads((OUT / "portfolio.json").read_text(encoding="utf-8"))
    data = sorted(data, key=lambda r: (-int(r["inherent_score"]), r["vendor"]))
    human = sum(1 for r in data if r["human_required"])
    ai = sum(1 for r in data if r["ai_in_scope"])
    t1 = sum(1 for r in data if r["inherent_tier"].startswith("T1"))
    rows = []
    for r in data:
        gate = "HUMAN" if r["human_required"] else "auto"
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td class='{}'>{}</td><td class='{}'>{}</td><td>{}</td><td>{}</td></tr>".format(
                r["vendor"],
                r["product"],
                r["inherent_score"],
                cls(r["inherent_tier"]),
                r["inherent_tier"],
                cls(r["residual_tier"]),
                r["residual_tier"],
                "yes" if r["ai_in_scope"] else "no",
                gate,
            )
        )
    summary = "{} | {} vendors | {} human gates | {} AI | {} T1".format(
        date.today().isoformat(), len(data), human, ai, t1
    )
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>TPRM</title>",
        "<style>body{font-family:Segoe UI,sans-serif;background:#F4F1EA;margin:24px}",
        ".t1{background:#F8D4D4}.t2{background:#FDE9C9}.t3{background:#D9E8F5}.t4{background:#D8F3E4}",
        "table{border-collapse:collapse;background:#fff}th,td{padding:8px;border-bottom:1px solid #ddd;text-align:left}",
        "th{background:#0F6E6B;color:#fff}</style></head><body>",
        "<h1>Third-party portfolio</h1>",
        "<p>" + summary + "</p>",
        "<table><tr><th>Vendor</th><th>Product</th><th>Score</th><th>Inherent</th><th>Residual</th><th>AI</th><th>Gate</th></tr>",
        "".join(rows),
        "</table></body></html>",
    ]
    OUT.mkdir(exist_ok=True)
    dest = OUT / "portfolio.html"
    dest.write_text("".join(parts), encoding="utf-8")
    print(dest)


if __name__ == "__main__":
    main()
