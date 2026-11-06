"""Registro de verificadores que producen Finding. Mismo patrón que WebScan:
el descubrimiento (crt.sh, fuerza bruta, vivo/no vivo) es orquestado aparte
en scanner.py; acá solo van los dos chequeos que deciden 'esto está mal'."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..models import Finding, Subdomain


@dataclass
class Context:
    domain: str
    subdomains: list[Subdomain] = field(default_factory=list)
    wildcard_ips: set[str] = field(default_factory=set)


CheckFn = Callable[[Context], list[Finding]]
REGISTRY: dict[str, CheckFn] = {}


def register(name: str):
    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY[name] = fn
        return fn
    return deco


def load_all() -> dict[str, CheckFn]:
    from . import wildcard, takeover  # noqa: F401
    return REGISTRY
