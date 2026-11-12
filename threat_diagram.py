"""Architecture diagram for a vendor's threat model: zones, systems, data flows, trust boundaries.

Drawn from the same live model as the Threat model tab, so every vendor gets one and it
changes when the record changes. Standard library only.

layout(rec, model) returns a list of drawing primitives on a fixed canvas. Three renderers
use that one list, so the app, the Word file and the PDF show the same picture:

  svg(d)          inline SVG for the tab and for Word (Word 2016 and later draw SVG)
  png_fallback(d) a plain raster of the shapes for older Word versions (no text)
  threat_export draws the primitives as PDF vector graphics

Conventions:
  tinted box with a title     a zone (who controls what is inside it)
  white box                   a system
  solid blue arrow            a data flow the record supports
  red dashed arrow            a flow across a boundary the record has not confirmed
  orange dashed bar + TB-n    the trust boundary that flow crosses
"""
from __future__ import annotations

import re
import struct
import zlib
from datetime import date

import threat_export as tx
import threat_model as tm
from tpl import esc

W, H = 1200, 790

INK = "#1f2937"
SUB = "#374151"
FLOW = "#24476b"
UNCONFIRMED = "#c0392b"
BOUNDARY = "#e07020"
STATUS = "#8a5a00"

ZONES = {
    "org":    {"x": 16,  "y": 16,  "w": 452, "h": 690, "fill": "#eef3f9", "stroke": "#9fb3c8"},
    "vendor": {"x": 520, "y": 16,  "w": 340, "h": 430, "fill": "#fbf1e6", "stroke": "#d9b48f"},
    "subs":   {"x": 912, "y": 16,  "w": 272, "h": 430, "fill": "#f7ecec", "stroke": "#d4a5a5"},
    "store":  {"x": 520, "y": 498, "w": 664, "h": 208, "fill": "#eef6ee", "stroke": "#a8c8a8"},
}
GAP_X_ORG_VENDOR = 494      # between "org" and "vendor"
GAP_X_VENDOR_SUBS = 886     # between "vendor" and "subs"
GAP_Y_VENDOR_STORE = 472    # between "vendor" and "store"
MAX_STACK = 4               # boxes in a stack before "+ n more"


# ------------------------------------------------------------------ primitives
def _rect(x, y, w, h, fill="#ffffff", stroke=FLOW, dash=False, width=1.6, rx=6):
    return {"k": "rect", "x": x, "y": y, "w": w, "h": h, "fill": fill, "stroke": stroke, "dash": dash, "width": width, "rx": rx}


def _text(x, y, s, size=12, bold=False, color=INK, anchor="start", italic=False):
    return {"k": "text", "x": x, "y": y, "s": s, "size": size, "bold": bold, "color": color, "anchor": anchor, "italic": italic}


def _line(points, color=FLOW, width=2.0, dash=False, arrow=True):
    return {"k": "line", "pts": points, "color": color, "width": width, "dash": dash, "arrow": arrow}


def _split(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"[;,\n]+", text or "") if p.strip()]


def _box(prims, x, y, w, h, title, lines=(), status="", dash=False):
    """A system box: bold title, detail lines and an optional status, wrapped to fit."""
    prims.append(_rect(x, y, w, h, stroke=FLOW if not dash else UNCONFIRMED, dash=dash))
    inner = w - 18
    rows = [(l, 13.5, True, INK, False) for l in tx._wrap(title, 13.5, True, inner)[:2]]
    for line in lines:
        rows += [(l, 11.5, False, SUB, False) for l in tx._wrap(line, 11.5, False, inner)]
    if status:
        rows += [(l, 11, False, STATUS, True) for l in tx._wrap(status, 11, False, inner)]
    max_rows = max(1, int((h - 12) // 15))
    if len(rows) > max_rows:
        rows = rows[:max_rows]
        text, size, bold, color, italic = rows[-1]
        rows[-1] = (text.rstrip(".") + "...", size, bold, color, italic)
    total = sum(17 if r[2] else 15 for r in rows)
    cy = y + (h - total) / 2 + 12
    for text, size, bold, color, italic in rows:
        prims.append(_text(x + w / 2, cy, text, size, bold, color, "middle", italic))
        cy += 17 if bold else 15


def _stack(prims, x, y, w, h_each, gap, items, max_n, empty_title, empty_status):
    """Boxes stacked top to bottom. Returns the centre points (for arrows)."""
    centres = []
    if not items:
        _box(prims, x, y, w, h_each, empty_title, status=empty_status, dash=True)
        return [(x, y + h_each / 2)]
    shown = items if len(items) <= max_n else items[:max_n - 1]
    for i, (title, detail) in enumerate(shown):
        top = y + i * (h_each + gap)
        _box(prims, x, top, w, h_each, title, [detail] if detail else [])
        centres.append((x, top + h_each / 2))
    if len(items) > max_n:
        top = y + (max_n - 1) * (h_each + gap)
        _box(prims, x, top, w, h_each, "+ %d more" % (len(items) - (max_n - 1)), ["Listed in the system inventory"])
        centres.append((x, top + h_each / 2))
    return centres


def _cross_x(p1, p2, gx):
    (x1, y1), (x2, y2) = p1, p2
    t = (gx - x1) / (x2 - x1)
    return (gx, y1 + t * (y2 - y1))


def _cross_y(p1, p2, gy):
    (x1, y1), (x2, y2) = p1, p2
    t = (gy - y1) / (y2 - y1)
    return (x1 + t * (x2 - x1), gy)


def _badge(prims, x, y, label):
    w = tx._tw(label, 11, True) + 12
    prims.append(_rect(x - w / 2, y - 10, w, 19, fill=BOUNDARY, stroke=BOUNDARY, width=1, rx=3))
    prims.append(_text(x, y + 4, label, 11, True, "#ffffff", "middle"))


def _flow_label(prims, p1, p2, label, at=0.3, dx=0, dy=-8):
    x = p1[0] + (p2[0] - p1[0]) * at + dx
    y = p1[1] + (p2[1] - p1[1]) * at + dy
    w = tx._tw(label, 11.5, True) + 8
    prims.append(_rect(x - w / 2, y - 11, w, 16, fill="#ffffff", stroke="#ffffff", width=0.5, rx=2))
    prims.append(_text(x, y + 1, label, 11.5, True, FLOW, "middle"))


# ------------------------------------------------------------------ layout
def layout(rec: dict, model: dict | None = None) -> dict:
    model = model or tm.build(rec)
    inp = model["inputs"]
    vendor = rec.get("vendor") or "Vendor"
    status = {b["id"]: b["status"] for b in model["boundaries"]}
    tb = tm.TB_ID
    unknown = "Not confirmed in the record"
    p: list[dict] = []

    # Zones
    titles = {"org": "Your organisation", "vendor": "%s (vendor)" % vendor,
              "subs": "Sub-processors and AI", "store": "Hosting and exit"}
    for key, z in ZONES.items():
        p.append(_rect(z["x"], z["y"], z["w"], z["h"], fill=z["fill"], stroke=z["stroke"], width=1.2, rx=4))
        title = tx._wrap(titles[key], 15, True, z["w"] - 28)[0]
        p.append(_text(z["x"] + 14, z["y"] + 26, title, 15, True, "#24476b"))

    # Your organisation
    _box(p, 36, 60, 412, 92, "People who submit data",
         ["Data: %s" % (inp["data_classes"] or "not recorded")], "" if inp["data_classes"] else unknown)
    _box(p, 36, 186, 190, 112, "Your tenant and identity provider",
         ["SSO: %s" % (inp["sso"] or "not recorded")], "" if inp["sso"] else unknown)
    apps = [(s["name"].replace("Connected app: ", ""), s["does"]) for s in model["systems"] if s["id"].startswith("S-app-")]
    app_points = _stack(p, 246, 186, 202, 64, 12, apps, MAX_STACK, "No connected apps on file",
                        "Import live access to show them")
    _box(p, 36, 572, 412, 100, "Exports, API and downloads",
         ["Where our data lands when it leaves the service"],
         "" if status[tb["egress"]] == "known" else unknown, dash=status[tb["egress"]] != "known")

    # Vendor
    _box(p, 548, 60, 284, 84, "Vendor staff", ["Support and operations access"],
         "" if status[tb["personnel"]] == "known" else unknown, dash=status[tb["personnel"]] != "known")
    detail = ["Delivery: %s" % tm.mode_label(rec.get("mode"))]
    if inp["tenancy"]:
        detail.append("Tenancy: %s" % inp["tenancy"])
    if inp["ai_used"]:
        detail.append("AI on our data: %s" % inp["ai_used"])
    _box(p, 548, 200, 284, 130, "%s service" % vendor, detail)

    # Sub-processors and model providers
    targets = []
    y = 60
    if inp["model_provider"] or inp["ai_used"] not in ("no", ""):
        trains = {"yes": "yes", "no": "no"}.get(str(inp["trains"]).lower(), "not recorded")
        _box(p, 928, y, 240, 104, inp["model_provider"] or "Model provider",
             ["Models: %s" % (inp["models"] or "not recorded"), "Trains on our data: %s" % trains],
             "" if inp["model_provider"] else unknown, dash=not inp["model_provider"])
        targets.append((928, y + 52))
        y += 118
    subs = [(name, "") for name in _split(inp["subprocessors"])]
    room = max(1, int((ZONES["subs"]["y"] + ZONES["subs"]["h"] - 12 - y) // 64))
    targets += _stack(p, 928, y, 240, 54, 10, subs, min(MAX_STACK, room), "No sub-processors declared", unknown)

    # Hosting and exit
    _box(p, 548, 548, 284, 110, "Data at rest", ["Hosting: %s" % (inp["hosting"] or "not recorded")],
         "" if inp["hosting"] else unknown, dash=not inp["hosting"])
    _box(p, 900, 548, 268, 110, "Backups and copies at exit", ["Deletion when the contract ends"],
         "" if status[tb["exit"]] == "known" else unknown, dash=status[tb["exit"]] != "known")

    # Flows. Each: id, boundary key, start, end(s), where it crosses.
    crossings: dict[tuple, list] = {}

    def flow(fid, key, a, b, gap, label_at=0.3, dy=-8, dx=0):
        known = status[tb[key]] == "known"
        p.append(_line([a, b], FLOW if known else UNCONFIRMED, 2.0, dash=not known))
        if gap[0] == "x":
            pt = _cross_x(a, b, gap[1])
        elif gap[0] == "y":
            pt = _cross_y(a, b, gap[1])
        else:
            pt = ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
        crossings.setdefault((tb[key], gap[0], gap[1] if gap[0] != "mid" else pt), []).append(pt)
        if fid:
            _flow_label(p, a, b, fid, label_at, dx=dx, dy=dy)

    flow("F-1", "intake", (448, 106), (548, 236), ("x", GAP_X_ORG_VENDOR), 0.84, -10)
    first_app = app_points[0]
    flow("F-2", "admin", (548, 266), (448, first_app[1] + 4), ("x", GAP_X_ORG_VENDOR), 0.2, 12)
    flow("F-3", "egress", (548, 312), (448, 600), ("x", GAP_X_ORG_VENDOR), 0.75, -2)
    flow("F-4", "personnel", (690, 144), (690, 200), ("mid",), 0.5, 0, dx=-34)
    for i, t in enumerate(targets[:4]):
        flow("F-5" if i == 0 else "", "subprocessor", (832, 236 + i * 12), (t[0], t[1]), ("x", GAP_X_VENDOR_SUBS), 0.22, -10)
    flow("F-6", "jurisdiction", (700, 330), (700, 548), ("y", GAP_Y_VENDOR_STORE), 0.78, 0)
    flow("F-7", "exit", (790, 330), (990, 548), ("y", GAP_Y_VENDOR_STORE), 0.78, -4)

    # Boundary bars and badges, one per boundary per gap
    for (tb_id, axis, where), pts in crossings.items():
        if axis == "x":
            ys = [pt[1] for pt in pts]
            y1, y2 = min(ys) - 22, max(ys) + 22
            p.append(_line([(where, y1), (where, y2)], BOUNDARY, 2.6, dash=True, arrow=False))
            _badge(p, where, y1 - 11, tb_id)
        elif axis == "y":
            xs = [pt[0] for pt in pts]
            x1, x2 = min(xs) - 26, max(xs) + 26
            p.append(_line([(x1, where), (x2, where)], BOUNDARY, 2.6, dash=True, arrow=False))
            _badge(p, x1 - 26, where, tb_id)
        else:
            x, y = where
            p.append(_line([(x - 30, y), (x + 30, y)], BOUNDARY, 2.6, dash=True, arrow=False))
            _badge(p, x + 58, y, tb_id)

    # Legend
    p.append(_text(16, 732, "Solid arrow = data flow the record supports.   Red dashed = flow across a boundary the record "
                            "has not confirmed.   Orange dashed bar = trust boundary (TB).", 12, False, SUB))
    p.append(_text(16, 752, "Flow and boundary IDs match the tables. Drawn from the vendor record on %s; it changes when the "
                            "record changes." % date.today().isoformat(), 12, False, SUB))
    unk = [b["id"] for b in model["boundaries"] if b["status"] != "known"]
    if unk:
        p.append(_text(16, 772, "Not confirmed yet: %s. See the open questions." % ", ".join(unk), 12, False, UNCONFIRMED))
    return {"w": W, "h": H, "prims": p,
            "caption": "Data flows and trust boundaries for %s, drawn from the vendor record." % vendor}


# ------------------------------------------------------------------ SVG
def _arrow_head(pts, size=9):
    (x1, y1), (x2, y2) = pts[-2], pts[-1]
    dx, dy = x2 - x1, y2 - y1
    n = (dx * dx + dy * dy) ** 0.5 or 1
    ux, uy = dx / n, dy / n
    bx, by = x2 - ux * size, y2 - uy * size
    return [(x2, y2), (bx - uy * size * 0.5, by + ux * size * 0.5), (bx + uy * size * 0.5, by - ux * size * 0.5)]


def svg(d: dict, title: str = "") -> str:
    out = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s" '
           'font-family="Helvetica, Arial, sans-serif">' % (d["w"], d["h"], d["w"], d["h"], esc(title or d["caption"])),
           '<rect x="0" y="0" width="%d" height="%d" fill="#ffffff"/>' % (d["w"], d["h"])]
    for e in d["prims"]:
        if e["k"] == "rect":
            out.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%s" fill="%s" stroke="%s" stroke-width="%s"%s/>' % (
                e["x"], e["y"], e["w"], e["h"], e["rx"], e["fill"], e["stroke"], e["width"],
                ' stroke-dasharray="6 4"' if e["dash"] else ""))
        elif e["k"] == "line":
            pts = e["pts"]
            end = pts
            if e["arrow"]:  # stop the line short of the tip so the head is clean
                head = _arrow_head(pts)
                (x1, y1), (x2, y2) = pts[-2], pts[-1]
                n = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5 or 1
                end = pts[:-1] + [(x2 - (x2 - x1) / n * 7, y2 - (y2 - y1) / n * 7)]
            out.append('<polyline points="%s" fill="none" stroke="%s" stroke-width="%s"%s/>' % (
                " ".join("%.1f,%.1f" % pt for pt in end), e["color"], e["width"],
                ' stroke-dasharray="%s"' % ("7 5" if e["color"] != BOUNDARY else "6 5") if e["dash"] else ""))
            if e["arrow"]:
                out.append('<polygon points="%s" fill="%s"/>' % (" ".join("%.1f,%.1f" % pt for pt in head), e["color"]))
        elif e["k"] == "text":
            out.append('<text x="%.1f" y="%.1f" font-size="%s" fill="%s" text-anchor="%s"%s%s>%s</text>' % (
                e["x"], e["y"], e["size"], e["color"], e["anchor"], ' font-weight="bold"' if e["bold"] else "",
                ' font-style="italic"' if e["italic"] else "", esc(e["s"])))
    out.append("</svg>")
    return "".join(out)


# ------------------------------------------------------------------ PNG (fallback for Word 2013 and older)
def _hex(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def png_fallback(d: dict, scale: float = 0.5) -> bytes:
    """Shapes and arrows only. Word 2016 and later show the SVG instead."""
    w, h = int(d["w"] * scale), int(d["h"] * scale)
    px = bytearray(b"\xff" * (w * h * 3))

    def put(x, y, rgb):
        if 0 <= x < w and 0 <= y < h:
            i = (y * w + x) * 3
            px[i:i + 3] = bytes(rgb)

    def seg(x1, y1, x2, y2, rgb, thick=1):
        steps = int(max(abs(x2 - x1), abs(y2 - y1))) + 1
        for s in range(steps + 1):
            t = s / steps
            x, y = int(x1 + (x2 - x1) * t), int(y1 + (y2 - y1) * t)
            for ox in range(thick):
                for oy in range(thick):
                    put(x + ox, y + oy, rgb)

    for e in d["prims"]:
        if e["k"] == "rect":
            x, y, rw, rh = (int(v * scale) for v in (e["x"], e["y"], e["w"], e["h"]))
            fill = _hex(e["fill"])
            for yy in range(max(0, y), min(h, y + rh)):
                row = (yy * w + max(0, x)) * 3
                px[row:row + 3 * max(0, min(w, x + rw) - max(0, x))] = bytes(fill) * max(0, min(w, x + rw) - max(0, x))
            col = _hex(e["stroke"])
            for a, b in (((x, y), (x + rw, y)), ((x + rw, y), (x + rw, y + rh)), ((x, y + rh), (x + rw, y + rh)), ((x, y), (x, y + rh))):
                seg(*a, *b, col)
        elif e["k"] == "line":
            pts = [(pt[0] * scale, pt[1] * scale) for pt in e["pts"]]
            for a, b in zip(pts, pts[1:]):
                seg(a[0], a[1], b[0], b[1], _hex(e["color"]), 2)

    raw = b"".join(b"\x00" + bytes(px[r * w * 3:(r + 1) * w * 3]) for r in range(h))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
