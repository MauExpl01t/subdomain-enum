# SubdomainEnum

![Tests](https://github.com/MauExpl01t/subdomain-enum/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.12-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Enumerador de subdominios en Python, hermano de [WebScan](../webscan). Es el
paso de reconocimiento que hace cualquier pentester antes de probar nada:
mapear qué subdominios existen de un dominio antes de evaluar si algo falla.

> ⚠️ Analiza solo dominios propios o con **autorización escrita**. El CLI
> exige `--i-have-authorization`, y la fuerza bruta además `--active` +
> `--i-accept-active-risk`.

## Instalación (Windows / PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Uso

```powershell
# Solo descubrimiento pasivo (gratis, sin tocar al dueño del dominio)
python -m subdomainenum scan virec.cl --i-have-authorization

# + fuerza bruta por diccionario DNS (opt-in, doble confirmación)
python -m subdomainenum scan virec.cl --i-have-authorization --active --i-accept-active-risk

# Reporte en HTML o JSON
python -m subdomainenum scan virec.cl --i-have-authorization --format html -o reporte.html

# Wordlist propia en vez de la incluida
python -m subdomainenum scan virec.cl --i-have-authorization --active --i-accept-active-risk --wordlist mi_lista.txt

# Sistema propio en red interna
python -m subdomainenum scan miapp.local --i-have-authorization --allow-private
```

## Cómo descubre subdominios

| Fuente | Cómo funciona |
|---|---|
| **Pasiva** (siempre) | Consulta los registros públicos de Certificate Transparency (crt.sh): cada certificado HTTPS emitido alguna vez queda ahí para siempre. No toca el servidor del dueño del dominio. Si crt.sh no responde, el escaneo sigue con lo que tenga. |
| **Fuerza bruta** (`--active`) | Prueba una lista de ~100 nombres comunes (`admin`, `api`, `dev`...) contra el DNS del dominio. |

Antes de la fuerza bruta, detecta si el dominio tiene **DNS comodín**
(cualquier nombre resuelve a una IP, típico detrás de un CDN): si lo tiene,
sigue probando igual pero descarta los resultados cuya IP coincide con la
IP "atrapa-todo", en vez de reportar cientos de subdominios falsos.

Cada subdominio encontrado (de cualquier fuente) se visita para ver si está
**vivo**: intenta HTTPS, si falla reintenta HTTP, y guarda el código de
estado, el título de la página y la cabecera `Server`.

## Hallazgos de seguridad

Además del inventario de subdominios (que no son "hallazgos"), reporta dos
tipos de problema:

- **DNS comodín detectado** (informativo): explica por qué la fuerza bruta
  filtró resultados.
- **Posible toma de control de subdominio** (crítico): un subdominio con
  `CNAME` hacia un servicio externo (GitHub Pages, Heroku, Shopify, Fastly,
  Netlify, Surge.sh) que ya nadie reclama — cualquiera podría registrar ese
  mismo recurso y quedarse con el subdominio. Solo reporta la coincidencia,
  nunca intenta reclamar el recurso.

## Seguridad de la propia herramienta

- **Anti-SSRF**: antes de visitar cualquier subdominio descubierto, se
  valida que su IP no sea privada/interna/de metadatos cloud — igual que
  WebScan, pero aplicado a cada host encontrado, no solo al dominio pedido.
- Fuerza bruta con concurrencia acotada (15 hilos), sin reintentos
  agresivos — no es una herramienta de denegación de servicio.
- Reportes HTML escapan todo el contenido (títulos, evidencia).

## Pruebas

```powershell
python -m pytest -q
```

Todo corre contra DNS y HTTP simulados (sin depender de internet ni de
dominios reales), incluyendo un caso de dominio con wildcard y uno de
subdomain takeover.

## Ideas para siguientes versiones

- Resolución IPv6.
- Más fuentes pasivas además de crt.sh.
- Modo continuo/programado, conectado con el "monitor con historial" que
  se puede construir sobre esta serie de herramientas.
