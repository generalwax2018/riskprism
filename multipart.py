"""multipart/form-data parsing with the standard library's email parser.

The previous hand-rolled splitter mis-handled boundaries that appear in file
contents. This uses email.parser, which implements the MIME rules properly.
"""
from __future__ import annotations

from email import policy
from email.parser import BytesParser


class BadMultipart(ValueError):
    pass


def parse(body: bytes, content_type: str) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes]] = {}
    if "multipart/form-data" not in (content_type or "").lower() or "boundary=" not in (content_type or ""):
        raise BadMultipart("not multipart")
    header = b"Content-Type: " + content_type.encode("latin-1", "replace") + b"\r\nMIME-Version: 1.0\r\n\r\n"
    msg = BytesParser(policy=policy.HTTP).parsebytes(header + body)
    if not msg.is_multipart():
        raise BadMultipart("no parts")
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files[str(name)] = (str(filename), payload)
        else:
            fields[str(name)] = payload.decode("utf-8", errors="replace")
    return fields, files
