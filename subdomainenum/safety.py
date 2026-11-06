"""Guardas de seguridad de la propia herramienta: validar el dominio pedido y
bloquear que la verificación de 'host vivo' se conecte a redes internas
(anti-SSRF), igual que hace WebScan."""
from __future__ import annotations

import ipaddress
import re

DOMAIN_RX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class UnsafeTargetError(ValueError):
    """El destino no está permitido por la política de la herramienta."""


def normalize_domain(raw: str) -> str:
    """Limpia esquema/ruta si viene pegada por error y valida la forma de dominio."""
    raw = (raw or "").strip().lower()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].rstrip(".")
    if not raw or not DOMAIN_RX.match(raw):
        raise UnsafeTargetError(f"'{raw}' no parece un dominio válido.")
    return raw


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or getattr(addr, "is_site_local", False)
    )


def assert_safe_ips(host: str, ips: list[str], allow_private: bool) -> None:
    """Igual que el anti-SSRF de WebScan, pero aplicado a CADA subdominio
    descubierto antes de conectarse a él, no solo al dominio pedido."""
    if allow_private or not ips:
        return
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise UnsafeTargetError(
            f"'{host}' resuelve a direcciones no públicas ({', '.join(bad)}). "
            "Usa --allow-private solo para sistemas propios en redes internas.")
