# Nettle

[![PyPI](https://img.shields.io/pypi/v/nettle-html)](https://pypi.org/project/nettle-html/)
[![Python](https://img.shields.io/pypi/pyversions/nettle-html)](https://pypi.org/project/nettle-html/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**El toolkit de scraping que Python esperaba.** Una sola librería para parsear HTML, extraer datos limpios, llamar cualquier endpoint, descubrir APIs ocultas y sniffiear tráfico real de navegador — con **cero dependencias externas**.

Nettle existe porque el scraping real no termina en "seleccionar un nodo": termina peleando con `\xa0`, entidades crudas, JSON escondido en scripts, endpoints ocultos en JavaScript y sitios que te bloquean por parecer bot. Nettle resuelve **todo el pipeline**, no solo el primer paso.

- **Corre en todas partes**: Windows, Linux, macOS y Android (Termux). Python puro + stdlib, sin compilaciones ni binarios raros. El sniffing con navegador encuentra solo tu Chrome/Chromium/Edge/Brave en cualquier sistema.
- **Gratis y libre**: licencia MIT, uso comercial incluido.

```python
from nettle import fetch

doc = fetch("https://quotes.toscrape.com/")
data = doc.extract({
    "quotes": {
        "select": "div.quote",
        "each": {
            "text":  {"css": "span.text", "clean": "plain"},
            "author": {"css": "small.author", "clean": "plain"},
            "tags":  {"css": "a.tag", "all": True, "clean": "plain"},
        },
    }
})
```

Eso es todo. Sin `replace("\xa0", " ")`, sin `html.unescape`, sin `re.sub(r"\s+", ...)` por cada campo, sin armar dicts a mano. **Texto sucio entra, datos limpios salen.**

- Antes: `"Hello\xa0world&#39;s   &amp;  friends"`
- Con Nettle: `"Hello world's & friends"`

## Instalación

```bash
pip install nettle-html
```

O desde el código fuente:

```bash
git clone https://github.com/ldikay99/nettle.git
pip install ./nettle
```

Requiere **Python 3.9 o superior** y nada más — `pip install nettle-html` no instala una sola dependencia. Opcional: un navegador basado en Chromium (Chrome, Edge, Brave) si quieres capturar tráfico de red real; Nettle lo detecta solo en tu sistema.

## Por qué Nettle y no BeautifulSoup

| Dolor con BS4 + requests | Nettle |
|---|---|
| Texto sucio (`\xa0`, entidades, whitespace loco) — limpias a mano por cada campo | Limpieza integrada: `clean_text()` y `clean: "plain"` en cada extracción |
| Soup no habla HTTP — necesitas `requests` aparte | Cliente HTTP propio: `fetch()`, `request()`, sesiones con cookies y reintentos |
| Nada de endpoints — solo ves el HTML renderizado | `discover_endpoints()` los encuentra y verifica en una llamada |
| No ves el tráfico que genera la página | `sniff_network()` captura XHR/fetch con un Chrome real, como DevTools |
| Fingerprints de bot detectados | Rotación de perfiles de navegador reales con cabeceras `Sec-Ch-Ua`/`Sec-Fetch` coherentes |
| JSON embebido hay que sacarlo con regex frágiles | `sniff_embedded_json()` extrae cualquier `variable = {...}` que parsee como JSON |
| CSV/JSON los armas tú | `to_json()`, `to_csv()`, `to_dicts()` listos |
| Heurísticas fijas — si tu sitio no encaja, sufres | `nettle.registry`: enseñas tus convenciones en runtime, sin fork |

---

## 1. Scrape declarativo — describe el dato, no el proceso

`doc.extract(esquema)` mapea selectores CSS a diccionarios ya limpios. Anida, itera registros, saca atributos, absolutiza URLs:

```python
from nettle import fetch

doc = fetch("https://books.toscrape.com/")
libros = doc.extract({
    "libros": {
        "select": "article.product_pod",
        "each": {
            "titulo":  {"css": "h3 a", "attr": "title"},
            "precio":  {"css": ".price_color", "clean": "plain"},
            "stock":   {"css": ".instock.availability", "clean": "plain"},
            "link":    {"css": "h3 a", "attr": "href", "abs": True},
        },
    }
})["libros"]
```

Cada campo acepta `attr` (o lista de atributos fallback tipo `["data-src", "src"]` para imágenes lazy), `all=True` para listas, `abs=True` para URLs absolutas, `default=` para valores por defecto y `clean=` con los modos `plain`, `strict`, `keep_newlines` o `raw`.

Atajos rápidos: `doc.values("h1", ".precio")` para varios textos de una, `doc.record({...})` por elemento, `doc.table("table")` para tablas HTML → lista de dicts, `doc.lists()` para listas con items.

## 2. HTTP directo — cualquier método, cualquier endpoint

Si ya tienes la URL, la llamas. Nettle no asume rutas ni exige descubrir nada:

```python
from nettle import request, call_endpoint

request("POST", "https://tienda.example/catalog/load", json={"q": "zapatos"})
request("PUT", "https://tienda.example/items/42", json={"precio": 10})
call_endpoint("https://tienda.example/items/42", "DELETE")
call_endpoint("https://tienda.example/search", "GET", params={"page": 2})
```

GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS — con JSON, form-data, bytes o texto. La respuesta trae `.text`, `.json()`, `.status`, `.headers`, `.ok` y `.doc` (el HTML ya parseado). Los errores HTTP (401, 404, 500…) devuelven la respuesta para inspeccionarla; los fallos de red lanzan `FetchError` con reintentos y backoff exponencial incluidos.

Para varias llamadas relacionadas, `Session` mantiene cookies entre requests y hereda tus defaults globales.

## 3. Descubre endpoints con una llamada

No sabes dónde está la API? Pásale la página y Nettle te devuelve los endpoints ordenados por confianza, **cada uno con su evidencia**:

```python
from nettle import discover_endpoints

res = discover_endpoints("https://techcrunch.com/")
for e in res["endpoints"][:5]:
    print(e["score"], e.get("status"), e["url"], e["evidence"])
# 22 200 https://techcrunch.com/wp-json/ ['classified-api', 'probe:json-ok', ...]
```

Qué consulta: llamadas `fetch`/`axios`/`XHR`/`$.ajax` literales en el JavaScript, asignaciones de config (`baseURL = "..."`), JSON embebido, atributos `data-api`/`data-endpoint`, `link[rel=preload]`, descriptores estándar (`/openapi.json`, `/graphql`, `/v3/api-docs`...) y `robots.txt`. Luego verifica los mejores candidatos con un GET barato — un endpoint que responde JSON gana; uno que contesta 401/405 también puntúa, porque demuestra que existe. Con `probe=False` es análisis 100% estático: un solo request.

## 4. Tráfico real, como el panel Network de DevTools

Las URLs construidas en runtime y las SPAs no aparecen en el HTML. `sniff_network()` abre la página en un Chrome real vía CDP y captura todo lo que pasa por la red:

```python
from nettle import sniff_network

tráfico = sniff_network("https://www.bbc.com/news")
for req in tráfico["xhr_fetch"]:
    print(req["method"], req["url"], req["status"])
for j in tráfico["json"]:
    print(j["url"], j.get("body", "")[:80])
```

El tráfico lo genera un navegador de verdad — no hay fingerprint de bot que detectar. Con `scroll=True` (por defecto) hace scroll automático para disparar el lazy-load antes de capturar. Nettle lanza su propio navegador headless si no encuentra uno corriendo (perfil aislado), cierra su pestaña al terminar **y apaga el navegador que él mismo lanzó** — sin procesos zombis. Para varias capturas seguidas usa `keep_chrome=True` y cierra al final con `shutdown_chrome()`. Lo capturado viene agrupado en `xhr_fetch`, `json` y `media`.

## 5. JSON escondido en la página

Los datos que nunca llegan al DOM: estado de frameworks, JSON-LD, payloads precargados:

```python
from nettle import fetch, sniff_embedded_json

doc = fetch("https://cualquier-sitio.com/")
for blob in sniff_embedded_json(doc):
    print(blob["source"], "→", str(blob["data"])[:100])
```

Reconoce `script[type*=json]`, JSON-LD y **cualquier** asignación `nombre = {...}` que parsee como JSON — conoce los globales típicos (`__NEXT_DATA__`, `__NUXT__`, `initialState`, ...) pero no depende de ellos: cualquier framework que metas, lo encuentra.

## 6. URLs: encuéntralas, clasifícalas, fíltralas

```python
from nettle import fetch, find_urls, classify_url, filter_urls

doc = fetch("https://example.com/")
todas  = find_urls(doc)                          # hrefs, srcs, srcset, data-*, JSON-LD, meta og:, refresh...
apis   = find_urls(doc, kind="api")              # solo las que parecen endpoints
media  = filter_urls(todas, ext=[".png", ".webp"])
mias   = find_urls(doc, same_host=True)

classify_url("https://cdn.example.com/img.webp")  # "media"
classify_url("https://example.com/gql", use_hints=False)  # heurísticas off
```

Descubre URLs de `href`, `src`, `srcset`, atributos lazy (`data-src`, `data-original`...), meta tags Open Graph, meta refresh y strings dentro de scripts — todo absolutizado y deduplicado.

## 7. Exporta sin fricción

```python
from nettle import to_json, to_csv, write_json, write_csv

to_json(libros)                   # JSON string con unicode legible
write_csv(libros, "libros.csv")   # columnas deducidas de los dicts, UTF-8 garantizado
```

Los archivos siempre se escriben en UTF-8 con finales de línea normales — sin sorpresas de encoding en Windows.

## 8. Adáptalo a tu sitio — nada está quemado

Esta es la promesa central: si tu sitio usa convenciones que Nettle no conoce, **las enseñas tú en runtime**, sin fork ni monkey-patching:

```python
from nettle import registry

registry.add_api_hints("/tienda-service/", "/catalogo/")      # tus rutas de API
registry.add_state_globals("MI_APP_STATE")                    # tu framework
registry.add_url_keywords("shopApi")                          # tus configs JS
registry.add_data_endpoint_attrs("data-x-endpoint")           # tus atributos HTML
registry.add_media_exts(".weirdfmt")                          # tus formatos
registry.add_well_known("/api/swagger.json")                  # tus descriptores
registry.register_classifier(lambda u: "api" if "/loquesea" in u else None)
registry.add_discovery_skip_hosts("cdn.misitio.com")          # nunca proponer ese host

registry.http.update(timeout=10, retries=1, verify=False)     # defaults HTTP globales
registry.reset()                                              # volver a fábrica
```

Cada heurística de la librería consulta el registry **en cada llamada**, así que tus reglas aplican en todas partes: descubrimiento, clasificación, sniffing, CDP. Tus clasificadores corren antes que los built-in.

## 9. Anti-detección integrada

`fetch()` y `Session` se presentan como navegador real por defecto: rotación de perfiles Chrome (Windows/Linux/macOS) con cabeceras `User-Agent`, `Sec-Ch-Ua` y `Sec-Fetch-*` coherentes entre sí. Si necesitas control total: `Session(user_agent="...", headers={...})` o `registry.http["user_agent"]` para hacerlo global. Y cuando el sitio exige un navegador de verdad, `sniff_network()` lo ejecuta por ti.

## 10. Compatible con tu código de BeautifulSoup

Migrar desde bs4 no es reescribir: las llamadas típicas funcionan tal cual.

```python
from nettle import fetch

doc = fetch("https://example.com/")

# find_all con todo lo que bs4 acepta
doc.find_all("a", {"href": regex})     # dict de attrs posicional
doc.find_all("a", href=regex)          # kwargs con regex
doc.find_all(["a", "p"])               # lista de tags
doc.find_all("b", recursive=False)     # solo hijos directos
doc.find_all(string="precio")          # por texto directo

# get_text estilo bs4 (separador posicional) o estilo nettle
doc.get_text(" ")                      # bs4
doc.get_text(strip=True, sep=" ")      # nettle

# Navegación y cirugía de árbol
el.parent, el.parents, el.contents, el.string, el.stripped_strings
el.next_sibling, el.previous_sibling, el.next_element
el.decompose(), el.unwrap(), el.replace_with(n), el.wrap(w), el.clear()
doc.title, doc.head, doc.body

# Selectores estrictos: un selector mal escrito lanza SelectorError,
# nunca devuelve "todos los elementos" en silencio.
# Soporta :not(lista), :not(:has(...)), :is()/:where(), :nth-last-child,
# :only-child y [attr="valor" i] case-insensitive.
```

## 11. HTTP de mundo real

- **URLs con unicode funcionan**: `fetch("https://ja.wikipedia.org/wiki/東京都")` — percent-encoding automático de rutas no-ASCII (IRI → URI).
- **gzip/deflate transparente**: menos ancho de banda, y si un CDN fuerza compresión la respuesta se decodifica sola (antes: basura binaria).
- **TLS flexible**: `Session(verify=False)` o `registry.http["verify"] = False` para certs internos/self-signed.
- **Proxies**: `Session(proxies={"https": "http://..."})` o vía registry.
- **Control de tiempo**: `timeout=` por intento, `total_timeout=` como presupuesto de toda la operación (reintentos incluidos).
- **Redirects visibles**: `response.history` — la cadena completa; `response.raise_for_status()` estilo requests; `doc.response.status` desde el propio documento de `fetch()`.
- **registry.http manda de verdad**: `registry.http["timeout"] = 5` aplica a `request()`, `fetch()` y toda la librería.

---

## Cross-platform de verdad

Nettle es Python 100% puro — el mismo código corre idéntico en:

| Sistema | Estado |
|---|---|
| Linux | Soportado (desarrollo principal) |
| Windows | Soportado — rutas de navegador, temp dir y procesos nativos |
| macOS | Soportado — detecta Chrome/Chromium/Edge/Brave en `/Applications` |
| Android (Termux) | Soportado — detecta binarios bajo `$PREFIX` |

El único componente que toca el sistema es el opcional `sniff_network()`: Nettle encuentra navegadores Chromium en las rutas estándar de cada OS, y si el tuyo vive en un lugar raro, apúntalo con la variable de entorno `NETTLE_CHROME_BIN`. Todo lo demás — parse, select, extract, HTTP, descubrimiento, formato — es stdlib puro y funciona en cualquier parte donde corra Python 3.9+.

## Preguntas frecuentes

**¿Necesito instalar Chrome?** No. Solo para `sniff_network()` (captura de tráfico real). Todo lo demás funciona con Python solo.

**¿Qué dependencias instala?** Cero. Ni lxml, ni requests, ni bs4. Todo es stdlib — auditable, liviano y sin conflictos de versiones.

**¿Sirve para SPAs (React/Vue/Svelte)?** Sí: `discover_endpoints()` y `sniff_embedded_json()` encuentran los datos precargados, y `sniff_network()` captura el tráfico del navegador para lo que se carga dinámicamente.

**¿Me van a bloquear como bot?** El cliente HTTP imita navegadores reales por defecto (perfiles rotativos, cabeceras coherentes), y `sniff_network()` usa un navegador de verdad, así que no hay fingerprint de bot. Los sitios con protección extrema pueden seguir filtrando — para esos, el tráfico de navegador real es tu mejor arma.

**¿Licencia?** MIT — gratis para cualquier uso, comercial incluido. Ver [LICENSE](LICENSE).

## API en una mirada

| Quiero... | Usa |
|---|---|
| Parsear HTML | `parse(html)` o `fetch(url)` |
| Extraer datos limpios | `doc.extract(esquema)`, `doc.record()`, `doc.values()` |
| Tablas | `doc.table(selector)` |
| Llamar un endpoint | `request(método, url, json=...)`, `call_endpoint()` |
| Descubrir endpoints | `discover_endpoints(url)` |
| Ver tráfico real | `sniff_network(url)` |
| JSON embebido | `sniff_embedded_json(doc)` |
| URLs | `find_urls()`, `classify_url()`, `filter_urls()` |
| Exportar | `to_json()`, `to_csv(excel_safe=True)`, `write_csv()` |
| Navegar/cirugía estilo bs4 | `el.parents`, `el.string`, `el.decompose()`, `el.unwrap()`, `doc.title` |
| Apagar el navegador CDP | `shutdown_chrome()` |
| Enseñar mis reglas | `nettle.registry` |
