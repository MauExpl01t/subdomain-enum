# SubdomainEnum — diseño

## Intención y por qué

Mariana está armando un portafolio de herramientas de ciberseguridad en Python
para GitHub (el primer proyecto, WebScan, ya está hecho: diagnóstico de
seguridad web pasivo + activo opt-in). Esta es la segunda herramienta de la
serie: un enumerador de subdominios, el paso de reconocimiento que cualquier
pentester hace antes de probar nada — mapear qué existe (`admin.dominio.cl`,
`api.dominio.cl`, etc.) antes de evaluar si algo falla.

Mariana pidió explícitamente que "quede robusto y con todas las mejoras que
se puedan aplicar": por eso este diseño no se limita a una sola fuente, sino
que combina varias técnicas estándar de la industria (ver Goals) y agrega
una comprobación de alto valor (subdomain takeover) que la mayoría de las
herramientas de nivel principiante no incluyen.

## Goals

- Descubrir subdominios de un dominio por **dos vías complementarias**:
  1. **Pasiva** (siempre activa, sin gate de autorización): Certificate
     Transparency logs vía la API pública de crt.sh. Es información ya
     pública — cualquiera puede consultarla — así que no hace falta pedir
     autorización para esta parte, igual que WebScan no la pide para leer
     cabeceras HTTP públicas.
  2. **Activa, por diccionario** (opt-in con `--active`, mismo patrón de
     doble confirmación que WebScan: `--i-have-authorization` +
     `--active` + `--i-accept-active-risk`): prueba una wordlist de
     nombres de subdominio comunes contra el DNS del dominio.
- **Detección de DNS comodín (wildcard)** antes de la fuerza bruta: si
  `cualquier-cosa-random.dominio.cl` resuelve a una IP, el dominio tiene
  wildcard DNS y la fuerza bruta daría cientos de falsos positivos (todo
  "existe"). Hay que detectarlo y avisar, no solo lanzar la wordlist a
  ciegas — esto es lo que separa una herramienta amateur de una robusta.
- Para cada subdominio encontrado (de cualquiera de las dos fuentes),
  **verificar que esté "vivo"**: resolver su IP, y si responde HTTP(S),
  capturar código de estado, título de la página y cabecera `Server` —
  reutilizando el mismo `HttpClient` anti-SSRF de WebScan (límite de
  tamaño, timeout, sin redes privadas salvo `--allow-private`).
- **Detección de subdomain takeover**: para cada subdominio cuyo registro
  DNS sea un `CNAME` hacia un servicio externo (GitHub Pages, S3, Heroku,
  Shopify, etc.), comprobar si ese servicio responde con una firma de
  "recurso no reclamado" (ej. "There isn't a GitHub Pages site here",
  "NoSuchBucket"). Es una vulnerabilidad real y de alto impacto: si el
  servicio externo ya no existe, cualquiera puede reclamarlo y quedarse
  con ese subdominio del dominio de la víctima.
- Reportes en **texto / JSON / HTML**, mismo estilo visual y de severidad
  que WebScan, para que ambas herramientas se vean como una serie
  coherente en el portafolio.
- Mismo nivel de pruebas automatizadas que WebScan: servidor DNS/HTTP
  falso en los tests, sin depender de internet para que `pytest` pase.

## Non-goals (de esta primera versión)

- No hace fuerza bruta de *rutas* dentro de cada subdominio encontrado
  (eso es trabajo de WebScan, no de esta herramienta).
- No intenta explotar el takeover que detecta (no reclama el recurso
  externo) — solo lo reporta, igual que WebScan nunca explota lo que
  encuentra.
- No hace resolución de IPv6 en la v1 (se puede agregar después).
- No incluye un modo "continuo/programado" (eso es la idea del "monitor
  con historial" que se habló por separado; se puede conectar más
  adelante).

## Anti-goals

- Que la fuerza bruta sea tan agresiva que parezca un ataque de
  denegación de servicio por volumen de consultas DNS. Se limita
  concurrencia y se usa una wordlist de tamaño razonable (cientos, no
  millones de entradas).
- Que falte el aviso de wildcard DNS y la herramienta reporte 500
  subdominios falsos — eso le quitaría toda la credibilidad al reporte.

## Constraints

- Mismo lenguaje y estilo que WebScan: Python 3, sin frameworks pesados,
  arquitectura de "checks" registrables donde tenga sentido.
- Misma carpeta madre: vive en
  `herramientas-ciberseguridad/subdomain-enum/`, como proyecto hermano de
  `herramientas-ciberseguridad/webscan/`.
- Reutiliza patrones ya probados de WebScan en vez de reinventarlos:
  anti-SSRF (`safety.py`), `HttpClient` con límites, estructura de
  `Finding`/`Severity`/reportes, el mismo texto legal de autorización.
- Fuente pasiva (crt.sh) es una API pública gratuita sin autenticación;
  si no responde o da error, la herramienta sigue con lo que tenga (igual
  que WebScan degrada con gracia cuando un chequeo falla).

## Decisiones de "cómo" resueltas tras la revisión del builder

(Estas 4 quedaron a criterio de quien construye, según el documento
original — las resuelvo acá explícitamente para que no se decidan a
mitad de la implementación.)

- **La lista de subdominios encontrados NO son `Finding`.** `ScanResult`
  gana un campo nuevo, `subdomains: list[Subdomain]` (host, IP(s),
  vivo/no, esquema que respondió, título, `Server`, fuente: pasiva o
  fuerza bruta). Los `Finding` (con severidad) quedan solo para lo que
  es un *problema*: el aviso de DNS comodín y cada takeover detectado.
  Así el puntaje y los "chips" de severidad no se diluyen con decenas de
  subdominios sanos — y el reporte (texto/JSON/HTML) muestra dos
  secciones: la tabla de subdominios descubiertos, y debajo los
  hallazgos de seguridad, igual de como WebScan ya separa "lo que
  encontró" de "lo que está mal".
- **El patrón `checks/` de WebScan se usa solo para los dos
  verificadores que producen hallazgos** (aviso de wildcard, takeover).
  El resto del flujo (consultar crt.sh → detectar wildcard → fuerza
  bruta → comprobar si vive) es una secuencia orquestada en un
  `scanner.py`, igual que WebScan separa su `scanner.py` (orquesta) de
  sus `checks/` (producen hallazgos).
- **Si hay DNS comodín, la fuerza bruta igual corre**, pero se descarta
  cualquier resultado cuya IP coincida con la IP "atrapa-todo" del
  comodín — así sigue siendo útil en dominios detrás de un CDN (el caso
  más común), en vez de rendirse apenas detecta el comodín. El aviso de
  wildcard se reporta siempre como hallazgo informativo, haya o no
  fuerza bruta activada.
- **Para la verificación de "¿está vivo?": primero intenta HTTPS: si
  falla la conexión, reintenta por HTTP** (no ambos en paralelo, para no
  duplicar peticiones). Se reporta qué esquema respondió. Es el mismo
  criterio que ya usa WebScan al normalizar una URL sin esquema.

## Decisiones de "cómo" ya tomadas

- CLI con subcomandos tipo `python -m subdomainenum scan <dominio>
  --i-have-authorization [--active --i-accept-active-risk] [--allow-private]
  [--format text|json|html] [-o archivo] [--wordlist archivo.txt]`.
- Wordlist por defecto: una lista curada de ~200-300 nombres de
  subdominio comunes, empaquetada con la herramienta (`wordlists/common.txt`);
  `--wordlist` permite reemplazarla por una propia.
- Firmas de takeover: una tabla curada (servicio → patrón de CNAME →
  texto que confirma "no reclamado"), empezando con los servicios más
  comunes (GitHub Pages, S3, Heroku, Shopify, Fastly, Netlify) y
  documentada como fácil de extender (mismo patrón que `SENSITIVE` en
  `exposure.py` de WebScan).
- Concurrencia acotada (p. ej. un `ThreadPoolExecutor` con límite bajo,
  10-20 hilos) para la fuerza bruta y las verificaciones de vida, para no
  saturar ni el DNS del objetivo ni la red de quien corre la herramienta.

## Qué queda a criterio de quien construya

- Nombres exactos de las funciones/módulos internos, siempre que seguir
  el patrón de `checks/` de WebScan donde aplique.
- Lista exacta de las ~200-300 palabras de la wordlist por defecto (debe
  ser una lista pública/estándar de la industria, no inventada a mano).
- Mensajes de error y textos exactos del reporte (deben seguir el tono y
  formato ya establecido por WebScan — español simple, con severidad y
  recomendación por hallazgo).
- Estructura exacta de los tests (reutilizar el patrón de servidor local
  falso de `conftest.py` de WebScan, adaptado a DNS).
