# Plan de implementación — Sistema unificado de embeds para Threat

Unificar los **45 embeds** del bot bajo un mismo constructor, paleta y vocabulario, de modo
que cualquier mensaje del bot sea reconocible como Threat.

> Plan anterior (F1–F10, bugs) ya implementado y validado. Este plan es alcance nuevo y no
> lo reemplaza: el rediseño se apoya en los `UrlResult`/`ImgUrlResult` NamedTuples y en
> `comprobar_antispam` que quedaron de aquel trabajo.

---

## Contexto

### Auditoría

45 embeds reales en 11 archivos, más 3 embeds "centinela" de caché que nunca se muestran.

| Dimensión | Estado actual | Problema |
|---|---|---|
| Icono de título | 6 distintos (🛡️ ⚠️ ✅ ❌ 📊 🔑) + **14 embeds sin icono** | Sin identidad |
| Color | 7 distintos: `blue()`, `green()`, `orange()`, `red()`, `gold()`, `dark_blue()`, hex `0x36393F` | `whitelist`/`settings` azul, `stats` oro, `eval` azul oscuro: arbitrario |
| Campos | 3 convenciones: `"URL"`/`"Hash"`/`"IP"` sin icono · `"{EMOJI} Valor"` con icono · **mixtas** en el log de guild (`"ID"` junto a `"{EMOJI_LINK} Servidor"`) | |
| Footer / thumbnail / autor | 1 de 45 / 1 de 45 / **0 de 45** | Casi nada identifica al bot |
| Títulos | Title Case (`"URL Maliciosa Detectada"`) mezclado con sentence case (`"Error al analizar URL"`) | |
| Títulos | 5 variantes para lo mismo: `"Error"` ×5, `"Error en análisis"`, `"Error al analizar URL"`, `"Error al subir archivo"`, `"Error al descargar archivo"` | |
| Títulos | Concordancia rota: `"Hash Malicioso Detectado"` (sin artículo) vs `"URL Maliciosa Detectada"`; `"Hash no encontrado"` vs `"IP no encontrada"` | |
| Truco `\u200b` | 6 usos para colgar un link bajo un campo block | Hack |

**Hallazgo de marca**: `landing/src/styles/global.css:11-40` ya define 9 tokens semánticos
(`--color-shield: #1A5AD8`, `--color-secure: #4ADE80`, `--color-threat: #DC2626`,
`--color-malicious: #F59E0B`, `--color-surface-600: #36393F`…) y el bot **no usa ninguno**.
`about.py:68` y `help.py:20` ya usan `0x36393F` de forma aislada.

### Restricción que define la arquitectura

Los embeds de resultado se cachean **ya renderizados** (`embed_json` en `core/analisis.db`,
TTL 7–30 días, más caché RAM de 1 h). Un cambio de diseño no toca lo ya cacheado, así que sin
intervención se verían embeds viejos y nuevos mezclados durante semanas — y justo en las URLs
más frecuentes, que son las más cacheadas.

---

## Decisiones ya tomadas

| # | Decisión | Consecuencia técnica |
|---|---|---|
| D1 | **Base gris `#36393F` + color solo por severidad** | Los embeds neutros (settings, whitelist, help, about, uptime, stats, eval) usan el gris de la UI del sitio. El color queda reservado para `seguro` / `malicioso` / `error` / `nsfw`. Estructura idéntica en todos, color únicamente informativo. |
| D2 | **Renderizar al leer, sin gastar cuota** | La caché guarda datos, no embeds. El embed se construye en `obtener_analisis_db` / `get_from_cache_mem`, siempre con el diseño vigente. Las entradas legacy (sin datos) devuelven su embed viejo hasta que expiran. No se toca la cuota de VT ni de SightEngine. |
| D3 | **Sentence case + vocabulario unificado** | Todos los títulos en minúscula salvo nombres propios (URL, IP, NSFW, Hash). Los 5 mensajes de error colapsan a 3. |

### Decisiones de diseño derivadas (no requieren confirmación)

| # | Decisión | Motivo |
|---|---|---|
| D4 | `ui/embed.py` **solo** importa `discord` + `core.config` | Evita ciclos: `core/cache.py` → `ui/embed.py` → `core.config`. El texto de antivirus ya se calcula en el write site y se guarda en `datos` (`obtener_top_antivirus` está en `core/utils.py:130` y no se necesita en render). |
| D5 | **Pie en todos** los embeds: `Threat · <contexto> · <YYYY-MM-DD HH:MM:SS UTC>` | Es el elemento que hace identificable al bot sin gastar altura. El `author` se descarta: añade una fila más a embeds que ya rozan los 600 px con 5 URLs + 5 archivos. |
| D6 | **🛡️ fijo** como prefijo de título | La severidad la comunica el color y el texto, no un segundo emoji. Un icono variable hacía el conjunto irreconocible. **Corregido en la implementación:** los emojis son personalizados del bot (`SM_Shield`, `SM_Guardian`…), no unicode, así que solo renderizan donde Threat está presente. Eso hace la marca más fuerte de lo previsto y refuerza D6. |
| D7 | **Vocabulario de campos cerrado**: `Elemento`, `Resultado`, `VirusTotal`, `Servidor`, `Usuario`, `Detalle`. Se elimina el truco `\u200b` | El link se integra en el campo `VirusTotal`, que solo se añade si hay `vt_link`. |
| D8 | **Sin `datos` → sin cambio de comportamiento** para las entradas legacy | D2 sin reanalizar. La versión no se versiona: con render-on-read un cambio de diseño futuro no requiere migrar nada. |
| D9 | Se **eliminan los 3 embeds centinela** | `guardar_analisis_db` ya acepta `embed=None` (columna nullable). La comprobación de existencia pasa de `embed is not None` a `datos is not None`. Verificado que `sightengine.py:20,28` es el único sitio que usa el embed como centinela. |

### Desviaciones respecto al plan original (detectadas al implementar)

| # | Plan original | Realidad | Motivo |
|---|---|---|---|
| **D10** | `set_cache_mem` recibe el tipo de análisis | Recibe el **veredicto** (`"malicioso"`/`"seguro"`), y `resultado()` necesita el **tipo de elemento** (`url`/`hash`/`ip`/`file`) para elegir título y color | El harness lo cazó: sin esto, cada cache hit de RAM renderizaba un embed genérico "Resultado del análisis". Se deduce del prefijo de la clave (`filehash:` → `file`) y se guarda en la tupla de RAM. El lado SQLite ya era correcto porque la columna `tipo` guarda el tipo de análisis |
| **D11** | Sentence case sin más | `Hash`, `Archivo`, `Error`… llevan mayúscula inicial | En sentence case la primera palabra **siempre** se capitaliza; solo el resto va en minúscula salvo siglas (`URL`, `IP`, `NSFW`, `API`). Se añadió `ACRONIMOS` para que el test lo verifique palabra por palabra |
| **D12** | El `ID` del usuario iba en el pie | Se mueve a un campo inline | Al reformatear el pie a formato de marca se perdía el `ID: <user>` que tenían los logs de amenaza, y quien modera lo necesita. Se conserva como campo compacto junto a `Usuario` y `Detalles` |
| **D13** | El log de guild lleva `ID` sin icono junto a campos con icono | Igual, pero se documentó | El caso ya existía y no era un bug de estilo grave; se mantuvo para no inflar el diff |

---

## Sistema de diseño

### Tokens (`core/config.py`)

```python
COLOR_NEUTRAL: int      = 0x36393F   # surface-600 del sitio: embeds informativos
COLOR_SEGURO: int       = 0x4ADE80   # --color-secure
COLOR_MALICIOSO: int    = 0xF59E0B   # --color-malicious (ámbar)
COLOR_ERROR: int        = 0xDC2626   # --color-threat
COLOR_NSFW: int         = 0xDC2626   # --color-nsfw
COLOR_TOPGG: int        = 0xFF3366   # --color-topgg (ya en uso en el prompt de reseña)
```

Modelo de color, explícito para evitar la confusión actual (`virustotal.py:153` usa `orange()`
para NSFW y `:159` usa `red()` para amenaza, mientras el log de amenaza usa `red()`):

| Color | Significado | Dónde |
|---|---|---|
| Gris | Informativo, sin veredicto | settings, whitelist, help, about, uptime, ping, stats, eval, join/leave |
| Verde | Analizado, sin amenazas | resultado `seguro` |
| Ámbar | Analizado, **malicioso** | resultado `malicioso` (el objeto es malo) |
| Rojo | **Amenaza en tu servidor**, requiere acción / error | log de amenaza, todos los errores |

Ámbar = "esto es malo". Rojo = "esto está pasando en tu servidor, actúa". Es la misma
distinción que ya hacía el sitio entre `--color-malicious` y `--color-threat`.

### Vocabulario de títulos (cierra D3)

| Actual | Nuevo |
|---|---|
| `Hash Malicioso Detectado` | `Hash malicioso detectado` |
| `URL Maliciosa Detectada` | `URL maliciosa detectada` |
| `Archivo Malicioso Detectado` | `Archivo malicioso detectado` |
| `IP Maliciosa Detectada` | `IP maliciosa detectada` |
| `Hash Seguro` / `URL Segura` / `IP Segura` | `Hash seguro` / `URL segura` / `IP segura` |
| `Hash no encontrado` | `Hash no encontrado` *(ya correcto)* |
| `IP no encontrada` | `IP no encontrada` *(ya correcto)* |
| `Error en análisis`, `Error al analizar URL`, `Error al subir archivo`, `Error al descargar archivo`, `Error` ×5 | **`Error de análisis`**, **`Error de conexión`**, **`Límite de API alcanzado`** |
| `IP no encontrada` / `Hash no encontrado` (mensaje) | **`Sin resultados`** |
| `Sin cuota de API` | `Límite de API alcanzado` |
| `Uso incorrecto` | `Uso incorrecto` *(ya correcto)* |
| `Amenaza Detectada` | `Amenaza detectada` |
| `Contenido NSFW Detectado` | `Contenido NSFW detectado` |

**Los 3 errores canónicos** (todo error encaja en uno):
- `Error de análisis` — la API respondió algo que no se pudo interpretar, o el análisis se agotó.
- `Error de conexión` — timeout o excepción de red.
- `Límite de API alcanzado` — no hay cuota; **siempre con el campo `Detalle`** diciendo
  cuántos segundos faltan cuando se pueda calcular.

### API de `ui/embed.py`

```python
PIE_SIN_CONtexto = "Threat"

def pie(embed, contexto: str) -> discord.Embed
    # footer: "Threat · {contexto} · {UTC}" + thumbnail del avatar del bot

def resultado(tipo: str, datos: dict, mal: int) -> discord.Embed
    # tipo: "url" | "hash" | "ip" | "file"
    # datos: {"valor","vt_link","top_text"} según el tipo
    # color por severidad, campos del vocabulario cerrado, pie "Threat · {tipo} · {valor truncado}"

def nsfw(tipo: str, valor: str, detalles: str) -> discord.Embed
def error(titulo: str, descripcion: str, detalle: Optional[str] = None) -> discord.Embed
def aviso(titulo: str, descripcion: str, campos: Optional[list] = None) -> discord.Embed
def amenaza(...) -> discord.Embed        # log de guild, conserva LogActionView
def resumen_mensaje(...) -> discord.Embed  # envuelve la lógica actual de _construir_embed_unificado
```

`resultado()` es la única que se invoca desde la capa de caché, y por eso debe ser **pura**:
mismo `datos` → mismo embed, sin dependencias del bot ni de la red.

---

## Tareas

### F1 — `ui/embed.py` (nuevo)

Tokens en `core/config.py` y el módulo con los tokens reexportados, `pie()`, las 5 familias y
la tabla de equivalencia título viejo → título nuevo como constante `TITULOS` (para que los
tests puedan afirmar que ningún título viejo sobrevive).

### F2 — Caché: render-on-read

1. `core/database.py`:
   - Nueva columna `datos TEXT` + migración idempotente en `POOL.start()`:
     `PRAGMA table_info(analisis)` → si no existe `datos`, `ALTER TABLE analisis ADD COLUMN datos TEXT`.
     Necesario porque `CREATE TABLE IF NOT EXISTS` no añade columnas a una base existente.
   - `guardar_analisis_db(clave, tipo, resultado, embed=None, mal=0, datos=None)`: escribe
     `datos`; si `datos is not None` **no** escribe `embed_json` (el render es determinista).
   - `obtener_analisis_db(clave)`: si hay `datos` → `discord.Embed = resultado(tipo, datos, mal)`.
     Si no, cae al `embed_json` legacy tal cual.
   - `guardar_metadatos_hash`: `embed=None` (ya no hay datos que renderizar).
2. `core/cache.py`: la tupla RAM pasa a `(tipo, mal, datos_dict, timestamp)`;
   `set_cache_mem(clave, tipo, embed=None, mal=0, datos=None)` y `get_from_cache_mem` construye
   el embed al leer. Firma de retorno **sin cambios** → ningún llamador se rompe.
3. `api/sightengine.py:19-34`: la comprobación pasa de `embed_cache is not None` a
   `tipo is not None`; se elimina `dummy_embed` (línea 84).
4. `ui/message_handler.py:496` y `core/database.py:136`: eliminar los embeds dummy restantes.

### F3 — Write sites pasan `datos`

6 sitios en `api/virustotal.py` (`hash` malicioso/seguro, `ip` malicioso/seguro,
`_procesar_resultado_vt`, `_procesar_analisis_archivo`) y 1 en `api/sightengine.py` pasan
`datos={"valor":…, "vt_link":…, "top_text":…}` y construyen el embed con `ui.embed.resultado`.

`obtener_top_antivirus` se llama en el write site (como hoy) y su resultado se guarda ya
formateado en `top_text`, para que el render no dependa de `core/utils.py`.

### F4 — Migrar los 45 embeds

| Archivo | Embeds | Familia |
|---|---|---|
| `api/virustotal.py` | ~20 | `resultado` / `error` |
| `ui/message_handler.py` | 1 (`_construir_embed_unificado`) | `resumen_mensaje` |
| `cogs/analisis.py` | 5 | `error` |
| `cogs/eval.py` | 4 | `error` / `aviso` |
| `cogs/about.py` | 3 | `aviso` |
| `cogs/stats.py` | 1 | `aviso` |
| `cogs/configuracion.py` | 1 | `aviso` |
| `cogs/help.py` | 1 | `aviso` |
| `cogs/rep.py` | 1 | `aviso` |
| `cogs/whitelist.py` | 1 | `aviso` |
| `ui/views.py` | 1 (paginador) | `aviso` |
| `bot.py` | 1 (log de guild) | `aviso` |
| `core/utils.py` | 1 (prompt reseña) | `aviso` + `COLOR_TOPGG` |

En `api/virustotal.py` los ~15 embeds de error se colapsan a los 3 títulos canónicos
(eliminando de paso las 4 llamadas a `update_stats(guild_id, "error")` en las ramas que ya
devuelven `_sin_cuota()`, para no contar dos veces el mismo fallo).

### F5 — Tests

- `tests/test_embeds.py` (nuevo): para cada familia, comprobar pie presente y con el formato
  exacto, prefijo 🛡️, color correcto por severidad, y que `resultado()` es **puro**
  (mismo `datos` → embed idéntico). Test parametrizado que itera `TITULOS` y **falla si algún
  título viejo reaparece** en el código (grep sobre los ficheros de `cogs/`, `api/`, `ui/`).
- `tests/test_cache.py`: extender con round-trip `datos` → embed, y con el fallback legacy
  (fila sin `datos` devuelve su `embed_json` sin romperse).
- `tests/test_ssrf.py`, `test_api_quota.py`, `test_antispam.py`, `test_message_handler.py`:
  ajustar a las firmas nuevas. `test_message_handler.py` pasa a construir vía `ui.embed`.

### F6 — CI

`pytest -q` ya corre desde el trabajo anterior. Añadir un `ruff check .` como segundo gate
(la config ya está en `pyproject.toml`).

---

## Riesgos

| Riesgo | Mitigación |
|---|---|
| La migración `ALTER TABLE` falla si `analisis.db` está corrupta o en uso | Va dentro del `try` de `POOL.start()` con log explícito; si falla, el bot arranca sin `datos` y todo cae al comportamiento legacy. Degradación elegante |
| Cambiar `_construir_embed_unificado` rompe `test_message_handler.py` (6 tests assertan título y color exactos) | Los tests se actualizan **en la misma tarea** que la función, no después |
| La firma de `guardar_analisis_db` cambia de posición para `embed` | Se pasa a keyword-only (`*, embed=None, mal=0, datos=None`) para que ningún llamador positional se entierre en silencio |
| Entradas legacy mostrando el diseño viejo hasta 30 días | Es lo que se aceptó en D2/D8. Se documenta en el changelog del deploy |
| Los 6 que aparecen en `cogs/stats.py` leen `self.bot.*` para los límites | No se tocan; son ints ya resueltos en `core/config.py` |
| Re-render en cada lectura de caché | `resultado()` es una construcción de `Embed` pura y barata (sin I/O). Se memoiza por clave en RAM si el perfil muestra coste |

---

## Validación

**Automatizada**
1. `python -m compileall .` — limpio.
2. `python -m pytest tests -q` — verde. No ejecutable en este sandbox (sin `pip`).
3. `ruff check .` — gate añadido a CI.
4. **Harness con stubs de `discord`/`aiohttp`/`dotenv`**, que es la única forma de ejecutar
   la lógica aquí:
   - `verify_embeds.py` (nuevo, sistema de embeds): **713 aserciones, 0 fallos.**
   - `verify.py` (regresión F1–F10): **168 aserciones, 0 fallos.** Sus 2 aserciones de color
     se actualizaron al nuevo modelo (ámbar de marca en vez de `Color.orange()`).

**Cobertura del harness de embeds** (713 aserciones): pie de marca en las 12 familias ·
prefijo de escudo · color por severidad en los 4 tipos de elemento y los 3 errores ·
vocabulario de títulos y sentence case palabra por palabra · guardia que falla si reaparece
cualquier título viejo, si alguien llama a `discord.Embed()` fuera de `ui/embed.py`, si
vuelve un color literal de Discord o el truco `\u200b` · vocabulario y orden de campos ·
el `ID` de moderación conservado y el valor de usuario en code block · pureza de
`resultado()` (mismo `datos` → mismo `dict`) y round-trip `to_dict`/`from_dict` ·
render-on-read de RAM y de SQLite, incluyendo el fallback legacy · mapeo de prefijos de
clave (`filehash:` → `archivo`) · migración `ALTER TABLE` e idempotencia · que `embed`/`mal`/
`datos` sean keyword-only.

**Manual** (servidor de prueba)
| # | Escenario | Esperado |
|---|---|---|
| E1 | `/scan` con URL maliciosa, segura, hash, IP y archivo | Las 5 con pie `Threat · …`, escudo en el título, ámbar/verde/rojo, mismos nombres de campo |
| E2 | Repetir un `/scan` idéntico (cache hit) | Embed **idéntico** a la primera vez, prueba de que el render-on-read es determinista |
| E3 | Mensaje con 3 URLs + 2 adjuntos | Un solo embed, pie presente, sin desbordar 600 px |
| E4 | Forzar cada uno de los 3 errores canónicos | Título y `Detalle` correctos, rojo, escudo, pie |
| E5 | `/whitelist list`, `/settings`, `/help`, `/about`, `/uptime`, `/ping`, `/stats`, `/usercheck` | Todos grises, mismo pie, escudo en el título |
| E6 | Amenaza en servidor con canal de logs | Log rojo con pie, `Valor` en code block, `ID` del usuario presente, botones Ban/Kick/Ignorar operativos |
| E7 | Arrancar con un `analisis.db` viejo (sin columna `datos`) | Arranca sin error, los cache hits devuelven el embed legacy, los nuevos ya salen con el diseño nuevo |
| E8 | Top.gg rating prompt | Rosa `#FF3366`, escudo, pie presente |
| E9 | Whitelist > 20 dominios (paginador) | El indicador "Página X de Y · N dominios" sigue visible, ahora como campo |

---

## Fuera de alcance

- **No se cambia `core/analisis.db` de versión ni se borra la caché** (D2 explícito).
- **No se toca `landing/`**: la web ya tiene sus tokens; este plan solo los replica en Discord.
- **No se añaden imágenes/thumbnails a los embeds** más allá del avatar en el pie.
- **No se rediseñan los botones** de `LogActionView` ni del paginador.
- Los hallazgos F11–F17 del análisis inicial (imports muertos, `@vercel/blob` sin uso, dominio
  duplicado, anchors rotos, `vercel.json`, contradicción de la política de privacidad) siguen
  pendientes y sin relación con esto.
