"""Comprueba si un subdominio descubierto responde por web: intenta HTTPS,
y si falla, reintenta por HTTP. Antes de conectarse a cualquier IP, valida
que no sea una red privada/interna (anti-SSRF), igual que WebScan."""
from __future__ import annotations

import requests
from bs4 import BeautifulSoup

from . import dns_utils
from .models import Subdomain
from .safety import UnsafeTargetError, assert_safe_ips

USER_AGENT = "SubdomainEnum/0.1 (diagnostico-seguridad-autorizado)"
TIMEOUT = 6.0
MAX_BODY_BYTES = 512 * 1024


def try_scheme(host: str, scheme: str) -> requests.Response | None:
    try:
        return requests.get(
            f"{scheme}://{host}/", timeout=TIMEOUT, allow_redirects=True,
            headers={"User-Agent": USER_AGENT}, stream=True, verify=(scheme == "https"))
    except requests.RequestException:
        return None


def check_live(host: str, allow_private: bool) -> Subdomain:
    ips = dns_utils.resolve_a(host)
    sub = Subdomain(host=host, source="", ips=ips)
    if not ips:
        return sub
    try:
        assert_safe_ips(host, ips, allow_private)
    except UnsafeTargetError:
        return sub  # resuelve a una IP privada/interna: no nos conectamos, queda "no vivo"

    for scheme in ("https", "http"):
        resp = try_scheme(host, scheme)
        if resp is None:
            continue
        body = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
        resp.close()
        sub.alive = True
        sub.scheme = scheme
        sub.status = resp.status_code
        sub.server = resp.headers.get("Server", "")
        if "html" in resp.headers.get("Content-Type", "").lower():
            title_tag = BeautifulSoup(body, "html.parser").find("title")
            sub.title = title_tag.get_text(strip=True)[:150] if title_tag else ""
        break
    return sub
