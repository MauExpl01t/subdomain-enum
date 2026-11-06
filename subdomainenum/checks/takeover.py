"""Detecta subdominios cuyo CNAME apunta a un servicio externo que ya nadie
reclama (el recurso fue borrado pero el DNS del cliente lo sigue
mencionando). Es un hallazgo de alto impacto: cualquiera podría registrar
ese mismo recurso en el proveedor externo y quedarse con el subdominio.

Esta función SOLO reporta la coincidencia (CNAME + texto de 'no reclamado'
en la respuesta); nunca intenta registrar el recurso ni reclamar nada."""
from __future__ import annotations

from .. import dns_utils, liveness
from ..models import Finding, Severity
from . import Context, register

# Tabla pública y bien documentada (el mismo tipo de referencia que usa
# cualquier escáner de este tipo): proveedor, fragmento típico del CNAME,
# texto que esa página de error muestra cuando el recurso no está reclamado.
SIGNATURES = [
    ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
    ("Heroku", "herokuapp.com", "no-such-app"),
    ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
    ("Fastly", "fastly.net", "Fastly error: unknown domain"),
    ("Netlify", "netlify.app", "Not Found - Request ID"),
    ("Surge.sh", "surge.sh", "project not found"),
]
REFERENCE = "https://github.com/EdOverflow/can-i-take-over-xyz"


@register("takeover")
def check_takeover(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for sub in ctx.subdomains:
        cname = dns_utils.resolve_cname(sub.host)
        if not cname:
            continue
        match = next((s for s in SIGNATURES if s[1] in cname), None)
        if not match:
            continue
        provider, _, needle = match
        resp = liveness.try_scheme(sub.host, "https") or liveness.try_scheme(sub.host, "http")
        if resp is None:
            continue
        body = resp.text[:4000]
        resp.close()
        if needle.lower() not in body.lower():
            continue
        out.append(Finding(
            "takeover", f"Posible toma de control de subdominio ({provider}) en {sub.host}",
            Severity.CRITICAL,
            f"'{sub.host}' tiene un CNAME hacia {provider} ({cname}), pero el recurso ya no "
            "está reclamado — la página de error de confirmación aparece en vez del sitio "
            f"esperado. Cualquiera podría registrar ese mismo nombre en {provider} y servir "
            "contenido propio bajo este subdominio.",
            f"Elimina el registro CNAME si ya no se usa, o reclama de nuevo el recurso en {provider}.",
            evidence=f"CNAME {sub.host} -> {cname}", reference=REFERENCE))
    return out
