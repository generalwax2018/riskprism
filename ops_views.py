"""Admin page: Data and audit. Backups, export, audit log seals, sample data, email and delete-all."""
from __future__ import annotations

from urllib.parse import quote

import config
import ops
from tpl import esc


def _size(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "bytes" else ("%.1f %s" % (n, unit))
        n /= 1024
    return str(n)


def page(error: str = "", ok: str = "", verify: dict | None = None) -> str:
    import audit
    import environment
    import mailer
    from views import _when, notice
    st = ops.status()
    sample = ops.sample_present()

    # audit
    if verify is None:
        check = ('<p class="muted small">Checking walks every entry (about 2 seconds per 200,000 entries).</p>'
                 '<form method="post" action="/admin/data/verify" class="inline"><button class="btn ghost small-btn" type="submit">'
                 'Check the seals now</button></form>')
    elif verify["ok"]:
        check = '<div class="notice ok">Intact: all %d entries check out against the server key.</div>' % verify["count"]
    else:
        check = '<div class="notice error">Broken: %s</div>' % esc(verify["reason"])
    audit_card = (
        '<section class="card"><div class="card-head"><h2>Audit log</h2><a class="gold small" href="/admin/data/audit.csv">Download CSV</a></div>'
        '<p>%d entries. Each one is sealed to the one before it, so a change, a removal or a reordering shows up when you check.</p>'
        '<div class="label">Latest seal</div><p class="mono small dl-seal">%s</p>'
        '<p class="muted small">Write the latest seal down outside this server now and then (the board pack prints it). It is how you '
        'prove later that the log was not rebuilt or shortened.</p>%s</section>' % (audit.count(), esc(audit.head()), check))

    # backups
    b = st["backup"]
    if b["mode"] == "off":
        sched = "Automatic backups are off (ENTROPY_BACKUP=off)."
    else:
        sched = "A backup is made every night after %d:00 server time and the newest %d are kept in %s." % (
            ops.BACKUP_HOUR, b["keep"], b["dir"])
    inside = str(b["dir"]).startswith(str(config.DATA_DIR))
    warn = ('<div class="notice">Backups are on the same disk as the data. Set ENTROPY_BACKUP_DIR to a mounted Azure Files share or '
            'another disk, so losing this VM does not lose its backups.</div>') if inside else ""
    err = ('<div class="notice error">Last backup failed: %s</div>' % esc(st["last_backup_error"])) if st["last_backup_error"] else ""
    rows = "".join('<tr><td class="mono small">%s</td><td>%s</td><td>%s</td><td><a class="gold" href="/admin/data/backup/%s">Download</a></td></tr>' % (
        esc(x["name"]), esc(_when(x["at"])), esc(_size(x["bytes"])), esc(quote(x["name"]))) for x in st["backups"][:14])
    backup_card = (
        '<section class="card"><div class="card-head"><h2>Backups</h2>'
        '<form method="post" action="/admin/data/backup" class="inline"><button class="btn primary small-btn" type="submit">Back up now</button></form></div>'
        '<p>%s</p>%s%s<p class="muted small"><b>secret.key is not in the backups.</b> Keep one copy of it somewhere safe and separate: '
        'without it, restored authenticator apps stop working and the audit seals no longer check out. A backup holds everything else, '
        'including people\'s password hashes, so store and share it like a password vault.</p>'
        '<table class="tm-table"><thead><tr><th>File</th><th>Made</th><th>Size</th><th></th></tr></thead><tbody>%s</tbody></table>'
        '<p class="muted small">To restore: stop the service, run <span class="mono">python3 ops.py restore FILE --force</span> on the server, '
        'start it again. The current data is moved aside, not deleted.</p></section>' % (
            esc(sched), warn, err, rows or '<tr><td colspan="4" class="muted">No backups yet.</td></tr>'))

    # export
    export_card = (
        '<section class="card"><div class="card-head"><h2>Export everything</h2>'
        '<a class="btn ghost small-btn" href="/admin/data/export.zip">Download export (.zip)</a></div>'
        '<p>Every vendor record and document, your environment, integrations, control objectives, findings, risk acceptances, '
        'notes, org units, people and the audit log, as JSON and CSV files. Use it to move to another server or to hand the data back when you are done. '
        'It contains no passwords, authenticator secrets, vendor link tokens or the server key.</p></section>')

    # sample data
    if sample["any"]:
        what = []
        if sample["vendors"]:
            what.append("%d sample vendors (%s)" % (len(sample["vendors"]), ", ".join(s.replace("_", " ") for s in sample["vendors"][:6])))
        if sample["integrations"]:
            what.append("%d sample integrations" % sample["integrations"])
        if sample["environment"]:
            what.append("the sample environment (Northwind Health)")
        if sample["shadow"]:
            what.append("the sample shadow IT imports")
        if sample["demo_access_rows"]:
            what.append("%d sample live-access rows" % sample["demo_access_rows"])
        sample_card = (
            '<section class="card"><div class="card-head"><h2>Sample data</h2></div><p>This server holds %s.</p>'
            '<form method="post" action="/admin/data/sample" class="inline"><button class="btn ghost small-btn" type="submit">'
            'Remove sample data</button></form><p class="muted small">Only the sample records go. Vendors and data you added stay.</p></section>'
            % esc("; ".join(what)))
    else:
        sample_card = '<section class="card"><div class="card-head"><h2>Sample data</h2></div><p class="muted">No sample data on this server.</p></section>'

    # email
    if st["email"]:
        s = mailer.settings()
        digest = ("A weekly digest goes out on Monday mornings to: %s." % ", ".join(st["digest_to"])) if st["digest"] == "weekly" and st["digest_to"] \
            else "The weekly digest has no recipients yet: make someone an admin or set ENTROPY_DIGEST_TO." if st["digest"] == "weekly" \
            else "The weekly digest is off (ENTROPY_DIGEST=off)."
        last = ("Last digest: %s." % _when(st["last_digest"])) if st["last_digest"] else ""
        derr = ('<div class="notice error">Last digest failed: %s</div>' % esc(st["last_digest_error"])) if st["last_digest_error"] else ""
        email_card = (
            '<section class="card"><div class="card-head"><h2>Email</h2></div><p>Sending from %s through %s.</p><p>%s %s</p>%s'
            '<div class="row-inline"><form method="post" action="/admin/data/test-email" class="inline row-inline">'
            '<input name="to" type="email" required maxlength="200" placeholder="you@yourco.com">'
            '<button class="btn ghost small-btn" type="submit">Send a test</button></form>'
            '<form method="post" action="/admin/data/digest" class="inline"><button class="btn ghost small-btn" type="submit">Send the digest now</button></form>'
            '</div></section>' % (esc(s["from"]), esc(s["host"]), esc(digest), esc(last), derr))
    else:
        email_card = ('<section class="card"><div class="card-head"><h2>Email</h2></div><p class="muted">Email is off. Set ENTROPY_SMTP_HOST and '
                      'ENTROPY_SMTP_FROM (see the README) to email vendor links, invites and a weekly digest.</p></section>')

    org = environment.org_name()
    delete_card = (
        '<section class="card danger-zone"><div class="card-head"><h2>Delete all data</h2></div>'
        '<p>For when you are finished with this instance. Removes every vendor, document, questionnaire answer, integration, environment setting, finding, '
        'note, risk acceptance, org unit and the audit log for %s. People\'s accounts stay so you can still sign in, and the audit log '
        'starts again with one entry recording this. It cannot be undone. Download the export first if the customer wants a copy.</p>'
        '<form method="post" action="/admin/data/delete" class="form">'
        '<label class="check"><input type="checkbox" name="backups" value="1" checked> Also delete the backups on this server</label>'
        '<label for="dl-confirm">Type <b>%s</b> to confirm</label><input id="dl-confirm" name="confirm" autocomplete="off" required maxlength="40">'
        '<p><button class="btn danger" type="submit">Delete all data</button></p></form></section>' % (esc(org), esc(ops.DELETE_PHRASE)))

    return ('<header class="page-head"><div><h1 class="big">Data and audit</h1><p class="lede">Backups, the customer\'s export, '
            'audit log seals, sample data, email, and deleting everything when you are done. Admins only.</p></div></header>'
            + notice("error", error) + notice("ok", ok)
            + '<div class="two-col">' + backup_card + audit_card + '</div>'
            + '<div class="two-col">' + export_card + sample_card + '</div>'
            + email_card + delete_card)
