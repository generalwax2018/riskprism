"""Read a vendor's published security material from their own website.

Starts at the security page an analyst gives (or the vendor's website), then
follows links on the same site whose path looks like security, trust, privacy,
data use, compliance or docs. Plain HTTP fetch and the stdlib HTML parser, so a
site that only renders in JavaScript comes back thin; the profile says so and the
questionnaire asks instead.

The server fetches addresses people type in, so every URL, and every redirect,
must resolve only to public internet addresses. Loopback, private ranges,
link-local (the Azure metadata service at 169.254.169.254) and the rest are
refused. Only ports 80 and 443. A host that re-resolves between the check and the
connect (DNS rebinding) is a known residual gap; the port and address rules keep
the reachable set to public web servers.

Page text is untrusted: it is data for the model, never instructions.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse

import config

def user_agent() -> str:
    """Says what is fetching and, when ENTROPY_BASE_URL is set, which server, so a vendor can tell who asked."""
    base = (config.BASE_URL or "").strip()
    return "RiskPrism-research/1.0 (vendor security review%s)" % ("; +" + base if base.startswith("https://") else "")
MAX_PAGES = 15
MAX_BYTES = 1_500_000
MAX_TEXT_PER_PAGE = 12_000
MAX_TEXT_TOTAL = 70_000
MIN_TEXT = 200
TIMEOUT = 15
KEYWORDS = ("security", "trust", "privacy", "data", "compliance", "subprocessor", "gdpr", "soc", "iso", "architecture",
            "encryption", "dpa", "governance", "responsible", "enterprise", "retention", "deletion", "ai", "model",
            "infrastructure", "incident", "vulnerab", "pentest", "penetration", "access")
COMMON_PATHS = ("/security", "/trust", "/privacy", "/data-use", "/legal/security", "/subprocessors", "/legal/subprocessors",
                "/compliance", "/trust-center")
_LOCALE = re.compile(r"^/[a-z]{2}(?:-[a-z]{2})?(?=/)", re.I)
_SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|zip|mp4|mov|woff2?|ttf|xml|json)$", re.I)


class ResearchError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def public_url(url: str) -> str:
    """Return a cleaned URL, or raise ResearchError if it could reach anything but the public web."""
    url = (url or "").strip()
    if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I) and not re.match(r"^https?://", url, re.I):
        raise ResearchError("Only http and https web addresses can be read.")
    if url and not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ResearchError("Use a normal web address, like https://vendor.com/security.")
    if p.username or p.password:
        raise ResearchError("Web addresses with a user name or password are not allowed.")
    if p.port not in (None, 80, 443):
        raise ResearchError("Only standard web ports (80 and 443) are allowed.")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise ResearchError("%s does not resolve." % p.hostname)
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if not addr.is_global or addr.is_multicast:
            raise ResearchError("%s points at a private or internal address, so it will not be fetched." % p.hostname)
    return urldefrag(url)[0]


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _proxy_endpoints() -> set[tuple[str, int]]:
    """(host, port) of the outbound proxies urllib will use for http and https, if any."""
    out = set()
    for scheme in ("http", "https"):
        u = urlparse(urllib.request.getproxies().get(scheme) or "")
        if u.hostname:
            out.add((u.hostname.lower(), u.port or (443 if u.scheme == "https" else 80)))
    return out


def _guarded_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *args, **kwargs):
    """Connect only to a public address, checked at the moment of connecting. public_url() checks the name first,
    but the name is looked up again to connect, and a hostile DNS server can answer differently the second time
    (DNS rebinding). A configured outbound proxy is the one exception: it does the lookup itself."""
    host, port = address[0], address[1]
    if (str(host).lower(), int(port)) in _proxy_endpoints():
        return socket.create_connection(address, timeout, source_address)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise ResearchError("%s does not resolve." % host)
    for family, _t, _p, _c, sockaddr in infos:
        addr = ipaddress.ip_address(sockaddr[0].split("%")[0])
        if not addr.is_global or addr.is_multicast:
            raise ResearchError("%s points at a private or internal address, so it will not be fetched." % host)
    last = None
    for family, socktype, proto, _c, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            last = e
            sock.close()
    raise last or OSError("could not connect to %s" % host)


class _GuardedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _guarded_connection  # http.client sets this per instance


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _guarded_connection


class _GuardedHTTP(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_GuardedHTTPConnection, req)


class _GuardedHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_GuardedHTTPSConnection, req, context=self._context)


_OPENER = urllib.request.build_opener(_SafeRedirect, _GuardedHTTP, _GuardedHTTPS)


def fetch(url: str) -> tuple[str, str]:
    """(final url, decoded html). Raises ResearchError."""
    if not config.AI_ENABLED:
        raise ResearchError(config.AI_OFF_MESSAGE)
    url = public_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": user_agent(), "Accept": "text/html,text/plain;q=0.9"})
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as resp:
            ctype = resp.headers.get("Content-Type", "")
            if not ctype.startswith(("text/html", "text/plain", "application/xhtml")):
                raise ResearchError("Not a web page (%s)." % (ctype.split(";")[0] or "unknown type"))
            body = resp.read(MAX_BYTES)
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.geturl(), body.decode(charset, "replace")
    except urllib.error.HTTPError as e:
        raise ResearchError("HTTP %d" % e.code)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ResearchError(str(getattr(e, "reason", e))[:120])


class _Page(HTMLParser):
    _SKIP = {"script", "style", "noscript", "svg", "template"}
    _BLOCK = {"p", "div", "section", "article", "li", "br", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol", "header", "footer", "nav"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.links, self.title = [], [], ""
        self._skip, self._in_title = 0, False

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip:
            self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        lines = [" ".join(line.split()) for line in raw.split("\n")]
        return "\n".join(line for line in lines if line)


def parse(html_text: str) -> tuple[str, str, list[str]]:
    p = _Page()
    try:
        p.feed(html_text)
        p.close()
    except Exception:  # malformed markup should never stop research
        pass
    return " ".join(p.title.split())[:200], p.text(), p.links


def site_of(host: str) -> str:
    """cursor.com for docs.cursor.com; example.co.uk for www.example.co.uk."""
    labels = (host or "").lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "net", "ac", "gov", "edu"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _key(url: str) -> str:
    p = urlparse(url)
    return (p.hostname or "") + (_LOCALE.sub("", p.path).rstrip("/") or "/")


def _score(url: str) -> int:
    """How security-related a path looks: path words that start with a keyword."""
    words = [w for w in re.split(r"[^a-z0-9]+", urlparse(url).path.lower()) if w]
    return sum(1 for w in words if any(w.startswith(k) for k in KEYWORDS))


def research(start: str, website: str = "") -> dict:
    """Crawl a vendor's security material. Never raises for one bad page; raises only
    when the starting address itself is not allowed."""
    if not config.AI_ENABLED:
        raise ResearchError(config.AI_OFF_MESSAGE)
    first = public_url(start or website)
    site = site_of(urlparse(first).hostname)
    root = "%s://%s" % (urlparse(first).scheme, urlparse(first).hostname)
    queue = [first] + [root + p for p in COMMON_PATHS]
    if website:
        try:
            queue.append(public_url(website))
        except ResearchError:
            pass
    seen, pages, documents, errors = set(), [], [], []
    total = 0
    while queue and len(pages) < MAX_PAGES and total < MAX_TEXT_TOTAL:
        queue.sort(key=lambda u: -_score(u))
        url = queue.pop(0)
        k = _key(url)
        if k in seen:
            continue
        seen.add(k)
        try:
            final, html_text = fetch(url)
        except ResearchError as e:
            if url == first or not any(url.endswith(p) for p in COMMON_PATHS):
                errors.append({"url": url, "error": str(e)})
            continue
        seen.add(_key(final))
        title, text, links = parse(html_text)
        if len(text) >= MIN_TEXT:
            text = text[:MAX_TEXT_PER_PAGE]
            pages.append({"url": final, "title": title, "text": text})
            total += len(text)
        for href in links:
            u = urldefrag(urljoin(final, href.strip()))[0]
            p = urlparse(u)
            if p.scheme not in ("http", "https") or not p.hostname or site_of(p.hostname) != site:
                continue
            if p.path.lower().endswith(".pdf"):
                if u not in documents and _score(u):
                    documents.append(u)
                continue
            if _SKIP_EXT.search(p.path) or _key(u) in seen or not _score(u):
                continue
            queue.append(u)
    return {"fetched_at": _now(), "start": first, "pages": pages, "documents": documents[:20], "errors": errors[:20]}
