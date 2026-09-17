# Nettle

**El toolkit de scraping que Python esperaba.** Parsea, extrae, descubre endpoints, imita navegadores y sniffiea tráfico real — todo en una sola librería, con **cero dependencias externas**. Python puro, desde 3.9.

Nettle existe porque el scraping real no termina en "seleccionar un nodo": termina peleando con `\xa0`, entidades crudas, JSON escondido en scripts, endpoints ocultos en JavaScript y sitios que te bloquean por parecer bot. Nettle resuelve **todo el pipeline**, no solo el primer paso.

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

## Instalación

Cero `pip install` de nada — solo stdlib. Clona y usa:

```bash
git clone https://github.com/ldikay99/nettle.git
export PYTHONPATH=/ruta/a/nettle
python3 -c "from nettle import parse; print(parse('<b>ok</b>').text)"
```

O instálalo desde el repo:

```bash
pip install git+https://github.com/ldikay99/nettle.git
```

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

GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS — con JSON, form-data, bytes o texto. La respuesta trae `.text`, `.json()`, `.status`, `.headers`, `.ok` y `.doc` (el HTML ya parseado). Los errores HTTP (401, 404, 500…) devuelven la respuesta para inspeccionarla; solo los fallos de red lanzan excepción, con reintentos y backoff exponencial incluidos.

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

El tráfico lo genera un navegador de verdad — no hay fingerprint de bot que detectar. Nettle lanza su propio Chrome headless si no encuentra uno corriendo, y agrupa lo capturado en `xhr_fetch`, `json` y `media` para que no navegues a ciegas.

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

to_json(libros)          # JSON string con unicode legible
write_csv(libros, "libros.csv")   # columnas deducidas de los dicts
```

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

registry.http.update(timeout=10, retries=1)                   # defaults HTTP globales
registry.reset()                                              # volver a fábrica
```

Cada heurística de la librería consulta el registry **en cada llamada**, así que tus reglas aplican en todas partes: descubrimiento, clasificación, sniffing, CDP. Tus clasificadores corren antes que los built-in.

## 9. Anti-detección integrada

`fetch()` y `Session` se presentan como navegador real por defecto: rotación de perfiles Chrome (Windows/Linux/macOS) con cabeceras `User-Agent`, `Sec-Ch-Ua` y `Sec-Fetch-*` coherentes entre sí. Si necesitas control total: `Session(user_agent="...", headers={...})` o `registry.http["user_agent"]` para hacerlo global. Y cuando el sitio exige un navegador de verdad, `sniff_network()` lo ejecuta por ti.

---

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
| Exportar | `to_json()`, `to_csv()`, `write_csv()` |
| Enseñar mis reglas | `nettle.registry` |

## Requisitos

- Python 3.9+
- Nada más. Nettle no instala una sola dependencia — todo es stdlib.
- Opcional: Chrome/Chromium instalado para `sniff_network()` (Nettle lo detecta y lo lanza solo).

## Licencia

**MIT** — gratis para cualquier uso, comercial incluido. Copia, modifica, vende lo que construyas con esto. Ver [LICENSE](LICENSE).
