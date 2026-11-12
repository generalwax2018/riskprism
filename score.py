#!/usr/bin/env python3
"""Inherent + residual TPRM scorer. Methodology v0.1."""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

WEIGHTS = {
    "data_sensitivity": 20,
    "data_volume": 10,
    "access_level": 18,
    "criticality": 15,
    "ai_involvement": 15,
    "blast_radius": 10,
    "substitutability": 7,
    "regulatory": 5,
}
FACTOR_LABELS = {
    "data_sensitivity": "F1 Data sensitivity",
    "data_volume": "F2 Data volume",
    "access_level": "F3 Access level",
    "criticality": "F4 Business criticality",
    "ai_involvement": "F5 AI / model involvement",
    "blast_radius": "F6 Connectivity / blast radius",
    "substitutability": "F7 Substitutability",
    "regulatory": "F8 Regulatory overlay",
}
AI_CONTROLS = [
    "AI-01", "AI-02", "AI-03", "AI-04", "AI-05", "AI-06", "AI-07", "AI-08",
    "AI-09", "AI-10", "AI-11", "AI-12", "AI-13", "AI-14", "AI-15", "AI-16",
]
AUTO_HIGH_FAILS = {"AI-01", "AI-08", "AI-10"}
LIGHT_AI = {"AI-01", "AI-02", "AI-05", "AI-06", "AI-14"}


def clamp_factor(v) -> int:
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        n = 5
    return max(0, min(5, n))


def inherent_raw(factors: dict[str, int]) -> int:
    return sum(WEIGHTS[k] * factors[k] for k in WEIGHTS)


def inherent_score(factors: dict[str, int]) -> int:
    return round(inherent_raw(factors) / 5)


def inherent_tier(score: int, factors: dict[str, int]) -> str:
    if score >= 70 or factors["data_sensitivity"] == 5 or factors["criticality"] == 5:
        return "T1 Critical"
    if score >= 50:
        return "T2 High"
    if score >= 30:
        return "T3 Moderate"
    return "T4 Low"


def ai_in_scope(factors: dict[str, int]) -> bool:
    return factors["ai_involvement"] >= 3


def normalize_verdict(v: str) -> str:
    v = (v or "Unknown").strip()
    mapping = {
        "pass": "Pass",
        "partial": "Partial",
        "fail": "Fail",
        "unknown": "Unknown",
        "n/a": "n/a",
        "na": "n/a",
    }
    return mapping.get(v.lower(), "Unknown")


def residual(inherent: str, factors: dict[str, int], controls: dict[str, str]):
    issues = []
    human = inherent.startswith("T1")
    fails = []
    unknowns = []
    if ai_in_scope(factors):
        required = AI_CONTROLS if inherent.startswith(("T1", "T2")) else sorted(LIGHT_AI)
        for cid in required:
            ver = normalize_verdict(controls.get(cid, "Unknown"))
            if ver == "n/a":
                continue
            if ver == "Fail":
                fails.append(cid)
            if ver == "Unknown":
                unknowns.append(cid)
        auto = [c for c in fails if c in AUTO_HIGH_FAILS]
        if auto:
            issues.append("Automatic High: fail on " + ", ".join(auto))
            human = True
        if unknowns:
            issues.append("Unknown treated as fail: " + ", ".join(unknowns))
        if fails:
            issues.append("Failed controls: " + ", ".join(fails))
    order = ["T4 Low", "T3 Moderate", "T2 High", "T1 Critical"]
    idx = order.index(inherent)
    if fails or unknowns:
        residual_idx = min(idx + 1, 3)
        if any(c in AUTO_HIGH_FAILS for c in fails):
            residual_idx = max(residual_idx, 2)
    else:
        if idx == 0:
            residual_idx = 0
        elif idx == 3:
            residual_idx = 2
            issues.append("T1 cannot drop below T2 without a signed exception")
            human = True
        else:
            residual_idx = idx - 1
    residual_name = order[residual_idx]
    if residual_name in ("T2 High", "T1 Critical"):
        human = True
    return residual_name, issues, human


def decision_label(human: bool) -> str:
    if human:
        return "HUMAN GATE — do not auto-approve"
    return "Agent may close (T3/T4 path)"


@dataclass
class Result:
    vendor: str
    product: str
    website: str
    notes: str
    factors: dict
    inherent_score: int
    inherent_tier: str
    residual_tier: str
    ai_in_scope: bool
    controls: dict
    issues: list
    human_required: bool
    decision: str


def load_csv(path: Path) -> list:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def score_vendor(row: dict, control_row: dict | None) -> Result:
    factors = {k: clamp_factor(row.get(k, 5)) for k in WEIGHTS}
    controls = {}
    if control_row:
        for cid in AI_CONTROLS:
            controls[cid] = normalize_verdict(control_row.get(cid, "Unknown"))
    score = inherent_score(factors)
    itier = inherent_tier(score, factors)
    rtier, issues, human = residual(itier, factors, controls)
    return Result(
        vendor=row.get("vendor", "").strip(),
        product=row.get("product", "").strip(),
        website=row.get("website", "").strip(),
        notes=row.get("notes", "").strip(),
        factors=factors,
        inherent_score=score,
        inherent_tier=itier,
        residual_tier=rtier,
        ai_in_scope=ai_in_scope(factors),
        controls=controls,
        issues=issues,
        human_required=human,
        decision=decision_label(human),
    )


def md_report(r: Result) -> str:
    factor_lines = ["| Factor | Score (0-5) | Weight |", "|---|---|---|"]
    for k, label in FACTOR_LABELS.items():
        factor_lines.append(f"| {label} | {r.factors[k]} | {WEIGHTS[k]}% |")
    ctrl_lines = ["| Control | Verdict |", "|---|---|"]
    if r.ai_in_scope and r.controls:
        for cid in AI_CONTROLS:
            ctrl_lines.append(f"| {cid} | {r.controls.get(cid, 'Unknown')} |")
    else:
        ctrl_lines.append("| - | AI set not in scope |")
    issues = "\n".join(f"- {i}" for i in r.issues) if r.issues else "- None recorded"
    return (
        f"# Vendor risk assessment\n"
        f"Vendor: {r.vendor}\nProduct: {r.product}\nWebsite: {r.website}\n"
        f"Date: {date.today().isoformat()}\nAssessor: agent v0.1 (unsigned)\n\n"
        f"## Decision\n"
        f"- Inherent tier: {r.inherent_tier} ({r.inherent_score} / 100)\n"
        f"- Residual tier: {r.residual_tier}\n"
        f"- Decision: {r.decision}\n"
        f"- Human required: {'YES' if r.human_required else 'no'}\n"
        f"- Signer: _pending_\n\n"
        f"## Scope\n{r.notes or 'See factor scores.'}\n"
        f"AI features in scope: {'yes' if r.ai_in_scope else 'no'}\n\n"
        f"## Inherent risk\n" + "\n".join(factor_lines) + "\n\n"
        f"## AI controls\n" + "\n".join(ctrl_lines) + "\n\n"
        f"## Open issues\n{issues}\n\n"
        f"## Residual rationale\n"
        f"Scored with Methodology v0.1. Unknown controls count as fail.\n"
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--vendors", default="vendors.demo.csv")
    p.add_argument("--controls", default="controls.demo.csv")
    p.add_argument("--out", default="out")
    args = p.parse_args()
    base = Path(__file__).resolve().parent
    vpath = Path(args.vendors) if Path(args.vendors).is_file() else base / args.vendors
    cpath = Path(args.controls) if Path(args.controls).is_file() else base / args.controls
    out = Path(args.out)
    if not out.is_absolute():
        out = base / out
    out.mkdir(parents=True, exist_ok=True)
    vendors = load_csv(vpath)
    controls_map = {}
    if cpath.is_file():
        for row in load_csv(cpath):
            controls_map[row.get("vendor", "").strip()] = row
    results = [score_vendor(row, controls_map.get(row.get("vendor", "").strip())) for row in vendors]
    summary_rows = []
    for r in results:
        (out / f"{r.vendor.replace(' ', '_')}.md").write_text(md_report(r), encoding="utf-8")
        summary_rows.append({
            "vendor": r.vendor,
            "product": r.product,
            "inherent_score": r.inherent_score,
            "inherent_tier": r.inherent_tier,
            "residual_tier": r.residual_tier,
            "ai_in_scope": r.ai_in_scope,
            "human_required": r.human_required,
            "decision": r.decision,
            "issues": "; ".join(r.issues),
        })
    with (out / "portfolio.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        w.writeheader()
        w.writerows(summary_rows)
    (out / "portfolio.json").write_text(json.dumps(summary_rows, indent=2), encoding="utf-8")
    print(f"{'Vendor':22} {'Inh':>4} {'Inherent':14} {'Residual':14} Gate")
    print("-" * 72)
    for r in results:
        gate = "HUMAN" if r.human_required else "auto"
        print(f"{r.vendor[:22]:22} {r.inherent_score:4} {r.inherent_tier:14} {r.residual_tier:14} {gate}")
    print(f"\nWrote {len(results)} assessments -> {out}")


if __name__ == "__main__":
    main()
