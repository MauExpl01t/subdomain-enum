"""Fuerza bruta por diccionario: prueba cada palabra de la wordlist como
subdominio y se queda con las que resuelven. Si el dominio tiene DNS
comodín, descarta los resultados cuya IP coincide con la IP 'atrapa-todo'
en vez de rendirse (así sigue sirviendo en dominios detrás de un CDN)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import dns_utils

MAX_WORKERS = 15


def load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def brute_force(domain: str, words: list[str], wildcard_ips: set[str]) -> dict[str, list[str]]:
    """Devuelve {host: [ips]} solo para los nombres que resuelven y cuyas
    IPs no son únicamente las del DNS comodín."""
    candidates = [f"{w}.{domain}" for w in words]
    found: dict[str, list[str]] = {}

    def probe(host: str) -> tuple[str, list[str]]:
        return host, dns_utils.resolve_a(host)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for host, ips in pool.map(probe, candidates):
            if not ips:
                continue
            real_ips = [ip for ip in ips if ip not in wildcard_ips]
            if real_ips or not wildcard_ips:
                found[host] = ips
    return found
