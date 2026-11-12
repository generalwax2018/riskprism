"""Export a vendor threat model to Word (.docx) and PDF. Standard library only.

Both writers take the same neutral block list, so the two files always say the same thing:

  ("title", text) ("h1", text) ("h2", text) ("p", text) ("meta", text)
  ("table", {"head": [...], "rows": [[...]], "widths": [...]})

blocks(rec, model) turns a vendor record and its threat model into that list. Nothing
in the output comes from outside RiskPrism's own records.

Word: a plain WordprocessingML package (zip of XML) with real tables, heading styles
and a page-number footer. PDF: a hand-written PDF 1.4 file using the standard Helvetica
fonts (no embedding), word-wrapped text, ruled tables that repeat their header on
each page, and page numbers.
"""
from __future__ import annotations

import io
import re
import zipfile
from xml.sax.saxutils import escape

import threat_model as tm

# ----------------------------------------------------------------- content
DISPOSITION_LABEL = tm.DISPOSITIONS_LABEL
STATE_LABEL = {"none": "Not generated", "draft": "Draft (not reviewed)",
               "current": "Reviewed and current", "needs_review": "Reviewed; needs review"}


def _text(v) -> str:
    return str(v if v is not None else "").strip()


def _label(v: str) -> str:
    v = _text(v).replace("_", " ")
    return v[:1].upper() + v[1:] if v else "Not recorded"


def _rating_cell(t: dict) -> str:
    if not t.get("rating"):
        return "Unrated"
    return "%s (%sx%s)" % (tm.rating_label(t["rating"]), t.get("likelihood"), t.get("impact"))


def _boundary_name(tb_id: str) -> str:
    key = next((k for k, v in tm.TB_ID.items() if v == tb_id), "")
    return tm.BOUNDARY_BY_KEY[key]["name"] if key in tm.BOUNDARY_BY_KEY else tb_id


def _stride_cell(t: dict) -> str:
    codes = t.get("stride") or ""
    names = ", ".join(tm.stride_label(c) for c in codes) if codes else "n/a"
    if t.get("lens") == "privacy":
        names += "\n(privacy lens, LINDDUN)"
    return names


def _threat_rows(model: dict, active_only: bool = True) -> list[list[str]]:
    rows = []
    for t in model.get("threats") or []:
        if active_only and t.get("retired"):
            continue
        accepted = ("%s until %s" % (t.get("accepted_by") or "?", t.get("accepted_until") or "?")
                    if t.get("disposition") == "accept" else "")
        rows.append([
            t["id"], _boundary_name(t["boundary"]), _stride_cell(t), t.get("scenario") or t.get("text", ""),
            _rating_cell(t), DISPOSITION_LABEL.get(t.get("disposition"), "Open"),
            "\n".join("- " + m for m in t.get("mitigations") or []) or "None yet", accepted,
        ])
    return rows


def blocks(rec: dict, model: dict, info: dict, vendor_name: str) -> list[tuple]:
    """Everything the export says, in order. model is threat_model.build(rec); info is model["status"]."""
    state = info.get("state", "draft")
    reviewed = bool(model.get("reviewed_at"))
    snap = model["inputs"]
    out: list[tuple] = []
    out.append(("title", "Threat model: %s" % vendor_name))
    out.append(("meta", "Status: %s. Built from the vendor record in RiskPrism. Every rating, disposition "
                        "and acceptance is set by an analyst; nothing here is a finished assessment until it is "
                        "reviewed." % STATE_LABEL.get(state, state)))

    # 1. Document control
    out.append(("h1", "1. Document control"))
    changes = "; ".join(info.get("changes") or []) or "None"
    out.append(("table", {"head": ["Item", "Value"], "widths": [1, 2.4], "rows": [
        ["Vendor", vendor_name],
        ["Version", ("%s (reviewed)" % model.get("version")) if reviewed else "Draft, not yet reviewed"],
        ["Status", STATE_LABEL.get(state, state)],
        ["Generated", "%s, from the live vendor record" % tm.when(tm._now())],
        ["Last reviewed", ("%s by %s" % (tm.when(model.get("reviewed_at")), model.get("reviewed_by") or "?")) if reviewed else "Not yet"],
        ["Changes since last review", changes],
    ]}))
    history = model.get("history") or []
    if history:
        out.append(("h2", "Change log"))
        out.append(("table", {"head": ["Version", "Reviewed", "By", "Note", "Threats", "Accepted", "Open questions"],
                              "widths": [0.7, 1.4, 1.2, 2.2, 0.8, 0.8, 0.9], "rows": [
            [str(h["version"]), tm.when(h["reviewed_at"]), h["reviewed_by"], h.get("note") or "",
             str(h["summary"]["threats"]), str(h["summary"]["accepted"]), str(h["summary"]["open_questions"])]
            for h in reversed(history)]}))

    # 2. Scope
    out.append(("h1", "2. Scope summary"))
    out.append(("table", {"head": ["Item", "Recorded"], "widths": [1, 2.4], "rows": [
        ["Business context", _text(rec.get("business")) or "Not recorded"],
        ["Authorization", _label(rec.get("authorization"))],
        ["Stage", _label(rec.get("stage"))],
        ["Delivery", tm.mode_label(rec.get("mode"))],
        ["Data classes", _text(snap.get("data_classes")) or "Not recorded"],
        ["Hosting regions", _text(snap.get("hosting")) or "Not recorded"],
        ["Next review", _text(rec.get("next_review")) or "Not set"],
        ["Contract end", _text(rec.get("contract_end")) or "Not set"],
    ]}))

    # 3. Target design
    out.append(("h1", "3. Proposed target design"))
    design = _text(model.get("design_statement"))
    out.append(("p", design or "Not yet written. An analyst describes how the vendor's service is built and used, "
                                "then reviews this section."))
    out.append(("table", {"head": ["Design fact", "Recorded"], "widths": [1, 2.4], "rows": [
        ["Tenancy", _label(snap.get("tenancy"))],
        ["Single sign-on and MFA", _text(snap.get("sso")) or "Not recorded"],
        ["AI used on our data", _label(snap.get("ai_used"))],
        ["Model provider", _text(snap.get("model_provider")) or "Not recorded"],
        ["Models", _text(snap.get("models")) or "Not recorded"],
        ["Trains on customer content", _label(str(snap.get("trains") or ""))],
    ]}))

    # 4. Systems
    out.append(("h1", "4. System inventory"))
    out.append(("table", {"head": ["ID", "System", "Owner", "What it does", "Authentication", "Status"],
                          "widths": [0.7, 1.7, 1.2, 2.2, 1.2, 0.8], "rows": [
        [s["id"], s["name"], s.get("owner", ""), s.get("does", ""), s.get("auth", ""), _label(s.get("status"))]
        for s in model.get("systems") or []]}))

    # 5. Data flow, with the architecture diagram drawn from the same model
    import threat_diagram  # imported here: threat_diagram imports this module
    out.append(("diagram", {"heading": "5. Data flow and trust boundaries", "d": threat_diagram.layout(rec, model)}))
    out.append(("h2", "Flows"))
    out.append(("table", {"head": ["ID", "From", "To", "Data", "Crosses"], "widths": [0.7, 1.6, 1.8, 2.2, 1.2], "rows": [
        [f["id"], f["from"], f["to"], f["data"], _boundary_name(f["boundary"])] for f in model.get("flows") or []]}))

    # 6. Trust boundaries
    out.append(("h1", "6. Trust boundaries"))
    out.append(("table", {"head": ["ID", "Boundary", "What crosses it", "Status"], "widths": [0.7, 1.8, 3, 0.9], "rows": [
        [b["id"], b["name"], b["crosses"], _label(b["status"])] for b in model.get("boundaries") or []]}))

    # 7. Threats
    out.append(("h1", "7. Threat table"))
    rows = _threat_rows(model)
    retired = len(model.get("retired") or [])
    if rows:
        out.append(("table", {"head": ["ID", "Boundary", "STRIDE", "Scenario", "Rating", "Decision",
                                       "Mitigations", "Accepted"],
                              "widths": [1.9, 1.0, 1.15, 2.3, 0.95, 0.95, 1.75, 1.0], "rows": rows}))
    else:
        out.append(("p", "No threats on the model."))
    if retired:
        out.append(("meta", "%d threat%s no longer apply after a refresh and are kept in the record, not shown here."
                    % (retired, "" if retired == 1 else "s")))

    # 8. Open questions
    out.append(("h1", "8. Open questions"))
    qs = model.get("questions") or []
    if qs:
        out.append(("table", {"head": ["ID", "Question", "Owner", "Affects", "Answer", "Status"],
                              "widths": [0.9, 2.6, 1.0, 0.9, 2.2, 0.8], "rows": [
            [q["id"], q["text"], q.get("owner") or "Vendor", ", ".join(q.get("relates_to") or []) or "All",
             q.get("answer") or "", _label(q.get("status"))] for q in qs]}))
    else:
        out.append(("p", "None. Every boundary is known and the factsheet has no gaps."))

    # 9. Sign-off
    out.append(("h1", "9. Sign-off"))
    accepted = [t for t in model.get("threats") or [] if t.get("disposition") == "accept" and not t.get("retired")]
    if accepted:
        out.append(("p", "Accepted threats. Each was signed by an approver for its rating band with an expiry date."))
        out.append(("table", {"head": ["ID", "Scenario", "Rating", "Accepted by", "Until"],
                              "widths": [1.6, 3.0, 1.0, 1.5, 1.0], "rows": [
            [t["id"], t.get("scenario") or "", _rating_cell(t), t.get("accepted_by") or "", t.get("accepted_until") or ""]
            for t in accepted]}))
    else:
        out.append(("p", "No threats are accepted."))
    if reviewed:
        out.append(("table", {"head": ["Review", "Recorded"], "widths": [1, 2.4], "rows": [
            ["Reviewed by", model.get("reviewed_by") or ""],
            ["Reviewed at", tm.when(model.get("reviewed_at"))],
            ["Version", str(model.get("version"))],
            ["Signature", ""],
        ]}))
    else:
        out.append(("p", "Not signed. The model has not been reviewed. Review it once every threat is decided and rated."))
    return out


# ----------------------------------------------------------------- Word (.docx)
_W_NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
         'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
         'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
         'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
         'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"')
_TEXT_W = 9638  # A4 width minus 2 cm margins, in twips
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _xml(s) -> str:
    return escape(_CTRL.sub("", str(s if s is not None else "")))


def _wpara(text: str, style: str | None = None, bold: bool = False, size: int | None = None) -> str:
    ppr = '<w:pPr><w:pStyle w:val="%s"/></w:pPr>' % style if style else ""
    rpr = ""
    if bold or size:
        rpr = "<w:rPr>%s%s</w:rPr>" % ("<w:b/>" if bold else "", '<w:sz w:val="%d"/>' % size if size else "")
    return '<w:p>%s<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r></w:p>' % (ppr, rpr, _xml(text))


def _wtable(head: list[str], rows: list[list[str]], fracs: list[float]) -> str:
    total = sum(fracs)
    ws = [int(_TEXT_W * f / total) for f in fracs]
    grid = "".join('<w:gridCol w:w="%d"/>' % w for w in ws)

    def row(cells, header=False):
        trpr = "<w:trPr><w:tblHeader/></w:trPr>" if header else "<w:trPr><w:cantSplit/></w:trPr>"
        tcs = []
        for w, cell in zip(ws, cells):
            shade = '<w:shd w:val="clear" w:color="auto" w:fill="E8EEF5"/>' if header else ""
            paras = "".join(_wpara(line, bold=header, size=17) for line in (_text(cell) or " ").split("\n"))
            tcs.append('<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/>%s</w:tcPr>%s</w:tc>' % (w, shade, paras))
        return "<w:tr>%s%s</w:tr>" % (trpr, "".join(tcs))

    body = row(head, header=True) + "".join(row(r) for r in rows)
    return ('<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="%d" w:type="dxa"/>'
            '<w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>%s</w:tblGrid>%s</w:tbl>') % (_TEXT_W, grid, body)


_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles %s>
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="20"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:spacing w:after="200"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="36"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/></w:tblBorders><w:tblCellMar><w:left w:w="70" w:type="dxa"/><w:right w:w="70" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>""" % _W_NS

_FOOTER = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr %s><w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:t xml:space="preserve">Page </w:t></w:r><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:t>1</w:t></w:r><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>""" % _W_NS

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Default Extension="svg" ContentType="image/svg+xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
</Types>"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
%s</Relationships>"""
_IMAGE_RELS = ('<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/diagram.png"/>'
               '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/diagram.svg"/>')
_MARGINS = '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/>'
_SECT_PORTRAIT = ('<w:sectPr><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="11906" w:h="16838"/>'
                  + _MARGINS + '</w:sectPr>')
_SECT_LANDSCAPE = ('<w:sectPr><w:footerReference w:type="default" r:id="rId2"/>'
                   '<w:pgSz w:w="16838" w:h="11906" w:orient="landscape"/>' + _MARGINS + '</w:sectPr>')
_EMU_PER_IN = 914400


def _wpicture(d: dict) -> str:
    """The diagram as a picture: SVG for Word 2016 and later, a PNG of the shapes for older versions."""
    max_w, max_h = 10.1 * _EMU_PER_IN, 5.5 * _EMU_PER_IN  # landscape A4 inside the margins, leaving room for text
    scale = min(max_w / d["w"], max_h / d["h"])
    cx, cy = int(d["w"] * scale), int(d["h"] * scale)
    return (
        '<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:drawing>'
        '<wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="%d" cy="%d"/>'
        '<wp:docPr id="1" name="Architecture diagram" descr="%s"/>'
        '<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
        '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="diagram.png"/><pic:cNvPicPr/></pic:nvPicPr>'
        '<pic:blipFill><a:blip r:embed="rId3"><a:extLst><a:ext uri="{96DAC541-7B7A-43D3-8B79-37D633B846F1}">'
        '<asvg:svgBlip xmlns:asvg="http://schemas.microsoft.com/office/drawing/2016/SVG/main" r:embed="rId4"/>'
        '</a:ext></a:extLst></a:blip><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>'
        '</a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'
        % (cx, cy, _xml(d["caption"]), cx, cy))


def docx_bytes(blocks_: list[tuple]) -> bytes:
    body = []
    diagram = None
    for kind, val in blocks_:
        if kind == "title":
            body.append(_wpara(val, "Title"))
        elif kind == "h1":
            body.append(_wpara(val, "Heading1"))
        elif kind == "h2":
            body.append(_wpara(val, "Heading2"))
        elif kind == "meta":
            body.append(_wpara(val, size=17))
        elif kind == "p":
            body.append(_wpara(val))
        elif kind == "table":
            body.append(_wtable(val["head"], val["rows"], val["widths"]))
            body.append(_wpara(""))
        elif kind == "diagram":
            # Its own landscape page: end the portrait section, draw, end the landscape section.
            import threat_diagram
            diagram = val["d"]
            body.append('<w:p><w:pPr>%s</w:pPr></w:p>' % _SECT_PORTRAIT)
            body.append(_wpara(val["heading"], "Heading1"))
            body.append(_wpicture(diagram))
            body.append(_wpara(diagram["caption"], size=17))
            body.append('<w:p><w:pPr>%s</w:pPr></w:p>' % _SECT_LANDSCAPE)
    sect = _SECT_PORTRAIT
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document %s><w:body>%s%s</w:body></w:document>'
                % (_W_NS, "".join(body), sect))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("word/document.xml", document)
        z.writestr("word/_rels/document.xml.rels", _DOC_RELS % (_IMAGE_RELS if diagram else ""))
        if diagram:
            z.writestr("word/media/diagram.svg", threat_diagram.svg(diagram))
            z.writestr("word/media/diagram.png", threat_diagram.png_fallback(diagram))
        z.writestr("word/styles.xml", _STYLES)
        z.writestr("word/footer1.xml", _FOOTER)
    return buf.getvalue()


# ----------------------------------------------------------------- PDF
PAGE_W, PAGE_H = 595.0, 842.0
MARGIN_L, MARGIN_R, MARGIN_T, MARGIN_B = 50.0, 50.0, 56.0, 56.0
TEXT_W = PAGE_W - MARGIN_L - MARGIN_R

# Helvetica advance widths (per 1000 em), ASCII range. Others use 556.
_HW = {}
for _k, _v in {
    " ": 278, "!": 278, '"': 355, "#": 556, "$": 556, "%": 889, "&": 667, "'": 191, "(": 333, ")": 333,
    "*": 389, "+": 584, ",": 278, "-": 333, ".": 278, "/": 278, ":": 278, ";": 278, "<": 584, "=": 584,
    ">": 584, "?": 556, "@": 1015, "[": 278, "\\": 278, "]": 278, "^": 469, "_": 556, "`": 333, "{": 334,
    "|": 260, "}": 334, "~": 584,
}.items():
    _HW[_k] = _v
for _ch, _w in zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                   [667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,
                    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611]):
    _HW[_ch] = _w
for _ch, _w in zip("abcdefghijklmnopqrstuvwxyz",
                   [556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833,
                    556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500]):
    _HW[_ch] = _w
for _ch in "0123456789":
    _HW[_ch] = 556

_REPLACE = {"–": "-", "—": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
            "…": "...", "•": "-", " ": " "}


def _clean(s) -> str:
    s = _CTRL.sub("", str(s if s is not None else ""))
    for a, b in _REPLACE.items():
        s = s.replace(a, b)
    return s.encode("cp1252", "replace").decode("cp1252")


def _tw(s: str, size: float, bold: bool = False) -> float:
    total = sum(_HW.get(ch, 556) for ch in s)
    return total * size / 1000.0 * (1.08 if bold else 1.0)


def _wrap(text: str, size: float, bold: bool, max_w: float) -> list[str]:
    out: list[str] = []
    for para in _clean(text).split("\n"):
        line = ""
        for word in para.split(" "):
            cand = (line + " " + word) if line else word
            if _tw(cand, size, bold) <= max_w:
                line = cand
                continue
            if line:
                out.append(line)
                line = ""
            while _tw(word, size, bold) > max_w and len(word) > 1:
                cut = len(word)
                while cut > 1 and _tw(word[:cut], size, bold) > max_w:
                    cut -= 1
                out.append(word[:cut])
                word = word[cut:]
            line = word
        out.append(line)
    return out


def _pdf_str(s: str) -> bytes:
    raw = s.encode("cp1252", "replace")
    return b"(" + raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


class _Pdf:
    def __init__(self, running_title: str):
        self.running_title = _clean(running_title)
        self.pages: list[tuple] = []  # (ops, (width, height))
        self.ops: list[bytes] = []
        self.size = (PAGE_W, PAGE_H)
        self.y = 0.0
        self.header_row = None  # callable that redraws a table header on a new page
        self._new_page()

    def _new_page(self, landscape: bool = False):
        if self.ops or self.pages:
            self.pages.append((self.ops, self.size))
        self.ops = []
        self.size = (PAGE_H, PAGE_W) if landscape else (PAGE_W, PAGE_H)
        self.y = self.size[1] - MARGIN_T
        self._text(MARGIN_L, self.size[1] - 34, self.running_title, 7.5, False, grey=True)
        if self.header_row and self.pages:
            self.header_row()

    def ensure(self, h: float):
        if self.y - h < MARGIN_B:
            self._new_page()

    def _text(self, x, baseline, s, size, bold, grey=False):
        font = b"/F2" if bold else b"/F1"
        color = b"0.35 g " if grey else b"0 g "
        self.ops.append(b"BT " + color + font + b" %.2f Tf %.2f %.2f Td " % (size, x, baseline)
                        + _pdf_str(s) + b" Tj ET")

    def _rect(self, x, y, w, h, fill=None):
        if fill:
            self.ops.append(b"%s rg %.2f %.2f %.2f %.2f re f" % (fill, x, y, w, h))
        self.ops.append(b"0.62 G 0.4 w %.2f %.2f %.2f %.2f re S" % (x, y, w, h))

    def heading(self, text: str, size: float):
        self.y -= size * 0.9
        self.ensure(size * 1.6 + 70)  # a heading never ends a page alone
        lh = size * 1.3
        self.y -= lh
        self._text(MARGIN_L, self.y + lh * 0.25, text, size, True)
        self.y -= size * 0.3

    def para(self, text: str, size: float = 9.5, bold: bool = False):
        lh = size * 1.32
        for line in _wrap(text, size, bold, TEXT_W):
            self.ensure(lh)
            self.y -= lh
            self._text(MARGIN_L, self.y + lh * 0.25, line, size, bold)
        self.y -= 5

    def table(self, head: list[str], rows: list[list[str]], fracs: list[float], size: float = 7.6):
        total = sum(fracs)
        widths = [TEXT_W * f / total for f in fracs]
        lh = size * 1.32
        pad = 3.0
        max_h = self.size[1] - MARGIN_T - MARGIN_B - 6

        def row_height(cells, bold):
            n = max(len(_wrap(c or " ", size, bold, w - 2 * pad)) for c, w in zip(cells, widths))
            return n * lh + 2 * pad

        # Keep the heading row with at least the first data row, so a header never ends a page alone.
        first = min(row_height(rows[0], False), max_h - lh * 2) if rows else 0
        self.ensure(row_height(head, True) + first)

        def draw(cells, bold, fill):
            cols = [_wrap(c or " ", size, bold, w - 2 * pad) for c, w in zip(cells, widths)]
            n = max(len(c) for c in cols)
            h = n * lh + 2 * pad
            if h > max_h:  # a single very long cell: keep what fits and say so
                keep = int((max_h - 2 * pad) / lh) - 1
                cols = [c[:keep] + ["... (full text in the Word export)"] if len(c) > keep else c for c in cols]
                n = max(len(c) for c in cols)
                h = n * lh + 2 * pad
            top = self.y
            x = MARGIN_L
            for col, w in zip(cols, widths):
                self._rect(x, top - h, w, h, fill)
                for i, line in enumerate(col):
                    self._text(x + pad, top - pad - (i + 1) * lh + lh * 0.25, line, size, bold)
                x += w
            self.y = top - h

        def head_row():
            self.ensure(lh + 2 * pad)
            draw(head, True, b"0.91 0.93 0.96")

        self.header_row = head_row
        head_row()
        for r in rows:
            cols_needed = max(len(_wrap(c or " ", size, False, w - 2 * pad)) for c, w in zip(r, widths))
            h = cols_needed * lh + 2 * pad
            if self.y - min(h, max_h) < MARGIN_B:
                self._new_page()
            draw(r, False, None)
        self.header_row = None
        self.y -= 8

    def diagram(self, d: dict, heading: str):
        """The architecture diagram on its own landscape page, as vector graphics."""
        import threat_diagram
        self._new_page(landscape=True)
        self.heading(heading, 12.5)
        pw, _ph = self.size
        avail_w = pw - MARGIN_L - MARGIN_R
        avail_h = self.y - MARGIN_B - 26
        s = min(avail_w / d["w"], avail_h / d["h"])
        ox = MARGIN_L + (avail_w - d["w"] * s) / 2
        top = self.y

        def X(x):
            return ox + x * s

        def Y(y):
            return top - y * s

        def rgb(hexc):
            hexc = hexc.lstrip("#")
            return b"%.3f %.3f %.3f" % tuple(int(hexc[i:i + 2], 16) / 255 for i in (0, 2, 4))

        ops = [b"q"]
        for e in d["prims"]:
            if e["k"] == "rect":
                ops.append(b"%s rg %s RG %.2f w %s %.2f %.2f %.2f %.2f re B" % (
                    rgb(e["fill"]), rgb(e["stroke"]), e["width"] * s, b"[4 3] 0 d" if e["dash"] else b"[] 0 d",
                    X(e["x"]), Y(e["y"] + e["h"]), e["w"] * s, e["h"] * s))
            elif e["k"] == "line":
                pts = list(e["pts"])
                head = None
                if e["arrow"]:
                    head = threat_diagram._arrow_head(pts)
                    (x1, y1), (x2, y2) = pts[-2], pts[-1]
                    n = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5 or 1
                    pts[-1] = (x2 - (x2 - x1) / n * 7, y2 - (y2 - y1) / n * 7)
                path = b" ".join(b"%.2f %.2f %s" % (X(x), Y(y), b"m" if i == 0 else b"l") for i, (x, y) in enumerate(pts))
                ops.append(b"%s RG %.2f w %s %s S" % (rgb(e["color"]), e["width"] * s,
                                                      b"[4 3] 0 d" if e["dash"] else b"[] 0 d", path))
                if head:
                    tri = b" ".join(b"%.2f %.2f %s" % (X(x), Y(y), b"m" if i == 0 else b"l") for i, (x, y) in enumerate(head))
                    ops.append(b"%s rg %s h f" % (rgb(e["color"]), tri))
            elif e["k"] == "text":
                size = e["size"] * s
                text = _clean(e["s"])
                x = X(e["x"]) - (_tw(text, size, e["bold"]) / 2 if e["anchor"] == "middle" else 0)
                ops.append(b"BT %s rg %s %.2f Tf %.2f %.2f Td " % (rgb(e["color"]), b"/F2" if e["bold"] else b"/F1", size, x, Y(e["y"]))
                           + _pdf_str(text) + b" Tj ET")
        ops.append(b"Q")
        self.ops.extend(ops)
        self.y = top - d["h"] * s - 8
        self.para(d["caption"], size=8.5)
        self._new_page()

    def finish(self, title: str) -> bytes:
        self.pages.append((self.ops, self.size))
        n = len(self.pages)
        for i, (ops, size) in enumerate(self.pages, start=1):
            label = "Page %d of %d" % (i, n)
            ops.append(b"BT 0.35 g /F1 7.5 Tf %.2f 26.00 Td " % (size[0] / 2 - _tw(label, 7.5) / 2)
                       + _pdf_str(label) + b" Tj ET")
        objs: list[bytes] = []
        objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        kids = " ".join("%d 0 R" % (6 + 2 * k) for k in range(n))
        objs.append(b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids.encode(), n))
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        objs.append(b"<< /Title " + _pdf_str(_clean(title)) + b" /Producer (RiskPrism) >>")
        for ops, size in self.pages:
            content = b"\n".join(ops)
            objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] "
                        b"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>" % (size[0], size[1], len(objs) + 2))
            objs.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objs, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
        return bytes(out)


def pdf_bytes(blocks_: list[tuple], title: str = "Threat model") -> bytes:
    pdf = _Pdf(title)
    for kind, val in blocks_:
        if kind == "title":
            pdf.heading(val, 17)
        elif kind == "h1":
            pdf.heading(val, 12.5)
        elif kind == "h2":
            pdf.heading(val, 10.5)
        elif kind == "meta":
            pdf.para(val, size=8.5)
        elif kind == "p":
            pdf.para(val)
        elif kind == "table":
            pdf.table(val["head"], val["rows"], val["widths"])
        elif kind == "diagram":
            pdf.diagram(val["d"], val["heading"])
    return pdf.finish(title)
