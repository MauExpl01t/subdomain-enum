"""Orquestador: valida el dominio, combina las fuentes de descubrimiento,
revisa cuáles están vivos y corre los chequeos que producen hallazgos."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import dns_utils, liveness
from .bruteforce import brute_force, load_wordlist
from .checks import Context, load_all
from .models import ScanResult, Subdomain
from .safety import normalize_domain
from .sources.crtsh import query_crtsh

DEFAULT_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "common.txt")
MAX_WORKERS = 15


def scan(domain: str, active: bool = False, allow_private: bool = False,
         wordlist_path: str | None = None) -> ScanResult:
    domain = normalize_domain(domain)
    result = ScanResult(domain=domain, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    passive_names, crtsh_error = query_crtsh(domain)
    if crtsh_error:
        result.errors.append(crtsh_error)

    sources: dict[str, str] = {name: "pasiva" for name in passive_names}
    sources.setdefault(domain, "pasiva")

    wildcard_ips = dns_utils.detect_wildcard(domain)
    result.wildcard_ips = sorted(wildcard_ips)

    if active:
        words = load_wordlist(wordlist_path or DEFAULT_WORDLIST)
        for host in brute_force(domain, words, wildcard_ips):
            sources.setdefault(host, "fuerza_bruta")

    def probe(host: str) -> Subdomain:
        sub = liveness.check_live(host, allow_private)
        sub.source = sources[host]
        return sub

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        result.subdomains = list(pool.map(probe, sources))

    ctx = Context(domain=domain, subdomains=result.subdomains, wildcard_ips=wildcard_ips)
    for name, check in load_all().items():
        try:
            result.findings.extend(check(ctx))
        except Exception as exc:  # un chequeo roto no debe tumbar el escaneo completo
            result.errors.append(f"Chequeo '{name}' falló: {type(exc).__name__}: {exc}")

    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result
