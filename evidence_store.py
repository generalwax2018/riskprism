"""Evidence files (SOC 2 reports, pentests). Local disk always; Azure Blob optional.

Azure options, in order of preference:
  ENTROPY_AZURE_ACCOUNT_URL=https://<account>.blob.core.windows.net
      uses DefaultAzureCredential, i.e. the app's managed identity. No keys anywhere.
  ENTROPY_AZURE_CONNECTION=<connection string>
      works, but the key then lives in an environment variable.
Both need `pip install azure-storage-blob azure-identity`. This module has not been
run against a live storage account; test it once in your subscription before relying on it.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

import config
import documents
from records import BadSlug, _path, valid_slug

LOCAL = config.EVIDENCE_DIR
CONTAINER = os.environ.get("ENTROPY_AZURE_CONTAINER") or "evidence"

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_MAGIC = {
    ".pdf": (b"%PDF-",),
    ".png": (b"\x89PNG",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".docx": (b"PK\x03\x04",),
    ".xlsx": (b"PK\x03\x04",),
    ".pptx": (b"PK\x03\x04",),
}


class UploadRejected(ValueError):
    pass


def _client():
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        return None
    url = os.environ.get("ENTROPY_AZURE_ACCOUNT_URL")
    conn = os.environ.get("ENTROPY_AZURE_CONNECTION") or os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    try:
        if url:
            from azure.identity import DefaultAzureCredential
            return BlobServiceClient(account_url=url, credential=DefaultAzureCredential())
        if conn:
            return BlobServiceClient.from_connection_string(conn)
    except Exception:
        return None
    return None


def azure_configured() -> bool:
    return bool(os.environ.get("ENTROPY_AZURE_ACCOUNT_URL") or os.environ.get("ENTROPY_AZURE_CONNECTION")
                or os.environ.get("AZURE_STORAGE_CONNECTION_STRING"))


def azure_ready() -> bool:
    return azure_configured() and _client() is not None


def azure_status() -> str:
    if not azure_configured():
        return "not configured. Files stay on this server's disk."
    return "connected" if azure_ready() else "configured but the Azure SDK or credentials are not working."


def safe_name(filename: str) -> str:
    base = Path((filename or "").replace("\\", "/")).name
    base = _SAFE.sub("_", base).strip("._") or "upload.bin"
    return base[-120:]


def validate(filename: str, data: bytes) -> str:
    name = safe_name(filename)
    ext = Path(name).suffix.lower()
    if ext not in config.ALLOWED_UPLOAD_EXT:
        raise UploadRejected("File type %s is not allowed." % (ext or "(none)"))
    if not data:
        raise UploadRejected("The file is empty.")
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise UploadRejected("The file is larger than %d MB." % (config.MAX_UPLOAD_BYTES // (1024 * 1024)))
    magic = _MAGIC.get(ext)
    if magic and not data.startswith(magic):
        raise UploadRejected("The file contents do not match its %s extension." % ext)
    return name


def store(slug: str, filename: str, data: bytes, kind: str, actor: str = "", meta_in: dict | None = None) -> dict:
    """Check and store one file. meta_in carries documents.clean_meta() fields (period, validity, description)."""
    if not valid_slug(slug):
        raise BadSlug("invalid record id")
    name = validate(filename, data)
    file_id = secrets.token_hex(6)
    folder = LOCAL / slug
    folder.mkdir(parents=True, exist_ok=True)
    stored = "%s_%s" % (file_id, name[-100:])
    path = (folder / stored).resolve()
    if path.parent != folder.resolve():
        raise BadSlug("invalid file name")
    path.write_bytes(data)
    meta = {
        "id": file_id, "filename": name, "stored_as": stored, "bytes": len(data),
        "kind": documents.valid_kind(kind),
        "sha256": hashlib.sha256(data).hexdigest(),
        "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "uploaded_by": actor, "azure": None,
        "period_end": "", "valid_until": "", "description": "", "reviewed_by": "", "reviewed_at": "",
    }
    meta.update({k: v for k, v in (meta_in or {}).items() if k in documents.META_FIELDS})
    client = _client() if azure_configured() else None
    if client is not None:
        blob = "%s/%s" % (slug, stored)
        client.get_blob_client(container=CONTAINER, blob=blob).upload_blob(data, overwrite=False)
        meta["azure"] = "%s/%s" % (CONTAINER, blob)
    return meta


def local_path(slug: str, stored_as: str) -> Path | None:
    if not valid_slug(slug) or not re.fullmatch(r"[A-Za-z0-9._-]{1,140}", stored_as or "") or ".." in stored_as:
        return None
    folder = (LOCAL / slug).resolve()
    path = (folder / stored_as).resolve()
    if path.parent != folder or not path.is_file():
        return None
    return path
