"""Dobles de prueba: DNS falso, crt.sh falso y respuestas HTTP falsas, para
que los tests no dependan de internet ni de dominios reales."""
from __future__ import annotations

import dns.resolver
import pytest

# ---------- datos de prueba ----------
FAKE_A = {
    "www.ejemplo.cl": ["93.184.216.10"],
    "api.ejemplo.cl": ["93.184.216.11"],
    "old-pages.ejemplo.cl": [],       # solo tiene CNAME, sin registro A propio
    "fallback.ejemplo.cl": ["93.184.216.13"],
    "admin.ejemplo.cl": ["93.184.216.14"],
    "api.comodin.cl": ["93.184.216.50"],
}
FAKE_CNAME = {
    "old-pages.ejemplo.cl": "ghost-project.github.io",
}
WILDCARD_DOMAINS = {"comodin.cl": "93.184.216.1"}

CRTSH_ENTRIES = {
    "ejemplo.cl": [
        {"name_value": "www.ejemplo.cl"},
        {"name_value": "api.ejemplo.cl\nold-pages.ejemplo.cl"},
        {"name_value": "fallback.ejemplo.cl"},
    ],
    "comodin.cl": [],
}

FAKE_HTTP = {
    ("https", "www.ejemplo.cl"):
        (200, {"Content-Type": "text/html", "Server": "nginx"},
         b"<html><head><title>Bienvenido</title></head></html>"),
    ("https", "api.ejemplo.cl"):
        (200, {"Content-Type": "application/json", "Server": "gunicorn"}, b'{"ok":true}'),
    ("https", "admin.ejemplo.cl"):
        (200, {"Content-Type": "text/html", "Server": "Apache"},
         b"<html><head><title>Admin</title></head></html>"),
    ("https", "old-pages.ejemplo.cl"):
        (404, {"Content-Type": "text/html"},
         b"<html><body>There isn't a GitHub Pages site here.</body></html>"),
    ("http", "fallback.ejemplo.cl"):
        (200, {"Content-Type": "text/html", "Server": "oldserver"},
         b"<html><head><title>Solo HTTP</title></head></html>"),
    ("https", "api.comodin.cl"):
        (200, {"Content-Type": "text/html", "Server": "nginx"},
         b"<html><head><title>Real API</title></head></html>"),
}


# ---------- dobles ----------
class FakeIPRecord:
    def __init__(self, ip):
        self.ip = ip

    def __str__(self):
        return self.ip


class FakeTarget:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name


class FakeCNAMERecord:
    def __init__(self, target_name):
        self.target = FakeTarget(target_name)


def fake_dns_resolve(qname, rtype, lifetime=None):
    qname = str(qname).rstrip(".")
    if rtype == "AAAA":
        raise dns.resolver.NoAnswer()
    if rtype == "A":
        if qname in FAKE_A:
            ips = FAKE_A[qname]
            if not ips:
                raise dns.resolver.NoAnswer()
            return [FakeIPRecord(ip) for ip in ips]
        for wdomain, wip in WILDCARD_DOMAINS.items():
            if qname == wdomain or qname.endswith("." + wdomain):
                return [FakeIPRecord(wip)]
        raise dns.resolver.NXDOMAIN()
    if rtype == "CNAME":
        if qname in FAKE_CNAME:
            return [FakeCNAMERecord(FAKE_CNAME[qname] + ".")]
        raise dns.resolver.NoAnswer()
    raise dns.resolver.NoAnswer()


class FakeCrtshResponse:
    def __init__(self, entries):
        self._entries = entries

    def raise_for_status(self):
        pass

    def json(self):
        return self._entries


def fake_requests_get(url, params=None, timeout=None):
    domain = params["q"][2:]  # quita el "%." inicial
    return FakeCrtshResponse(CRTSH_ENTRIES.get(domain, []))


class FakeRaw:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=None, decode_content=True):
        return self._body


class FakeHttpResponse:
    def __init__(self, status_code, headers, body: bytes):
        self.status_code = status_code
        self.headers = headers
        self.raw = FakeRaw(body)
        self._body = body

    @property
    def text(self):
        return self._body.decode("utf-8", errors="replace")

    def close(self):
        pass


def fake_try_scheme(host, scheme):
    entry = FAKE_HTTP.get((scheme, host))
    if entry is None:
        return None
    status, headers, body = entry
    return FakeHttpResponse(status, headers, body)


@pytest.fixture(autouse=True)
def fake_network(monkeypatch):
    monkeypatch.setattr(dns.resolver, "resolve", fake_dns_resolve)
    monkeypatch.setattr("subdomainenum.sources.crtsh.requests.get", fake_requests_get)
    monkeypatch.setattr("subdomainenum.liveness.try_scheme", fake_try_scheme)


@pytest.fixture
def wordlist_file(tmp_path):
    def _make(words: list[str]) -> str:
        path = tmp_path / "wl.txt"
        path.write_text("\n".join(words), encoding="utf-8")
        return str(path)
    return _make
