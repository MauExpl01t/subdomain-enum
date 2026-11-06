"""Utilidades DNS: resolver un host y detectar si el dominio tiene DNS
comodín (wildcard), que es lo que distingue una herramienta que sabe lo que
hace de una que reporta cientos de falsos positivos."""
from __future__ import annotations

import secrets

import dns.exception
import dns.resolver

TIMEOUT = 5.0


def resolve_a(host: str) -> list[str]:
    """IPs (A/AAAA) de un host. Lista vacía si no existe o no responde."""
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answer = dns.resolver.resolve(host, rtype, lifetime=TIMEOUT)
            ips.extend(str(r) for r in answer)
        except (dns.exception.DNSException, OSError):
            continue
    return ips


def resolve_cname(host: str) -> str | None:
    """Destino del registro CNAME de un host, si tiene uno, sin el punto final."""
    try:
        answer = dns.resolver.resolve(host, "CNAME", lifetime=TIMEOUT)
    except (dns.exception.DNSException, OSError):
        return None
    target = str(answer[0].target)
    return target.rstrip(".")


def detect_wildcard(domain: str, probes: int = 2) -> set[str]:
    """Resuelve un par de nombres aleatorios que casi seguro no existen.
    Si igual responden, el dominio tiene DNS comodín: devuelve el conjunto
    de IPs 'atrapa-todo'. Si no hay comodín, devuelve un conjunto vacío."""
    all_ips: set[str] = set()
    for _ in range(probes):
        probe_host = f"wsenum-{secrets.token_hex(6)}.{domain}"
        all_ips.update(resolve_a(probe_host))
    return all_ips
