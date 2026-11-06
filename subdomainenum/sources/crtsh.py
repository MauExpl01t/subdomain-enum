"""Fuente pasiva: busca el dominio en los registros públicos de Certificate
Transparency vía crt.sh. Es información que ya es pública (cualquiera puede
consultarla en su navegador); si el servicio no responde, se degrada con
gracia y el escaneo sigue con lo que tenga de otras fuentes."""
from __future__ import annotations

import requests

URL = "https://crt.sh/"
TIMEOUT = 15.0


def query_crtsh(domain: str) -> tuple[set[str], str | None]:
    """Devuelve (subdominios encontrados, mensaje de error si falló)."""
    try:
        resp = requests.get(URL, params={"q": f"%.{domain}", "output": "json"}, timeout=TIMEOUT)
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return set(), f"crt.sh no respondió correctamente: {exc}"

    names: set[str] = set()
    for entry in entries:
        raw = entry.get("name_value", "")
        for name in raw.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(f".{domain}") or name == domain:
                names.add(name)
    return names, None
