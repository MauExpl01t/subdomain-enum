"""Avisa cuando el dominio tiene DNS comodín: es informativo para quien lee
el reporte (explica por qué la fuerza bruta filtró tantos resultados)."""
from __future__ import annotations

from ..models import Finding, Severity
from . import Context, register


@register("wildcard")
def check_wildcard(ctx: Context) -> list[Finding]:
    if not ctx.wildcard_ips:
        return []
    return [Finding(
        "wildcard", f"DNS comodín (wildcard) detectado en {ctx.domain}", Severity.INFO,
        "Cualquier nombre de subdominio, exista o no, resuelve a una IP. Es una configuración "
        "válida (común detrás de un CDN), pero significa que la fuerza bruta por diccionario "
        "filtró automáticamente los resultados que coinciden con esta IP 'atrapa-todo' para "
        "no reportar cientos de subdominios falsos.",
        evidence="IP(s) atrapa-todo: " + ", ".join(sorted(ctx.wildcard_ips)))]
