# Plan de implementación — Corregir bugs F1–F10 de Threat

Objetivo: arreglar los 10 defectos verificados del análisis del repo
(`.kilo/plans/1790739696632-threat-repo-analysis.md`, sección 6), sin refactor estructural.

---

## Contexto (lo que hay que saber antes de tocar código)

**Repo**: bot de seguridad Discord en Python 3.10 (`discord.py` 2.7.1, `aiohttp`, `aiosqlite`),
~3.400 LOC en 28 `.py`, más `landing/` (Astro 6 + Tailwind 4, no tocado por este plan).

**Estructura relevante**

| Archivo | Rol |
|---|---|
| `bot.py` | Entry point, inyección de atributos en `commands.Bot`, eventos, cron horario |
| `core/config.py` | Constantes + env vars (sin estado) |
| `core/state.py` | `state.bot` + `ANALYSIS_SEMAPHORE = 20` |
| `core/cache.py` | Caché RAM LRU (100k, TTL 1 h) |
| `core/database.py` | Pool SQLite (4 conns, WAL) + `data.json` con debounce |
| `core/guild_config.py` | Config por guild, locks, stats, infracciones |
| `core/utils.py` | SSRF (`_resolve_url`), whitelist, acortadores, antispam |
| `api/virustotal.py` | Pool de keys, análisis URL/hash/IP/archivo, side-effects de amenaza |
| `api/sightengine.py` | NSFW multimodelo |
| `ui/message_handler.py` | Orquestador de `on_message`; embed unificado; logs |
| `cogs/*.py` | 10 cogs |

**Patrón de estado que hay que respetar**: los contadores mutables viven como atributos de
`state.bot` (`vt_key_usage`, `vt_key_daily_usage`, `vt_key_total_requests`, `user_scan_history`,
`antispam_scan`, `vt_user_requests`, `guilds_data`). Los locks por guild son módulo-globales en
`core/guild_config.py`.

**Restricción del entorno**: este sandbox no ejecuta `python` ni `pytest`. Todos los cambios se
validan por `compileall` + tests en el entorno del usuario/CI.

---

## Decisiones tomadas

| # | Decisión | Alternativa descartada | Motivo |
|---|---|---|---|
| D1 | `obtener_siguiente_key` **reserva** la cuota (ventana 60 s + diaria + total) dentro de `_vt_lock`; se borran `registrar_uso_vt`/`registrar_uso_se` y sus 11 call sites | Reservar solo la ventana de 60 s y dejar diario/total aparte | Selection+accounting atómico por construcción. De paso arregla F9: toda key seleccionada se cuenta, incluso si VT responde 404/403/500 |
| D2 | `elemento_id` canónico de una URL = `f"url:{url_expandida}"` (la misma string que VT ya cachea y que ya usa `:556` y `:478`) | Usar la URL original en ambos sitios | Es lo que ya produce el `INSERT` de caché; garantiza que log ↔ infracción ↔ botón "Ignorar" coincidan. La URL original se sigue mostrando en `valor` del embed y en el campo "Redirección" |
| D3 | `url_results` pasa de tupla de 4 a `NamedTuple UrlResult(url, tipo, mal, vt_link, elemento_id, ya_logueado)`, y se **elimina** la lista paralela `url_logged_internally` | Añadir solo un 5º campo | El emparejamiento por índice (`i < len(url_logged_internally)`) es exactamente lo que hoy hace frágil a F2. Con campos nombrados eluple imposible desalinearse |
| D4 | Antispam: función única `comprobar_antispam(bot, guild_id, user_id) -> (permitido, segundos)` en `core/utils.py`, que **cobra 1 unidad por mensaje** solo si va a haber consumo real de API (alguna URL o adjunto sin caché) | Cobrar por elemento analizado | Preserva la semántica actual ("30 análisis/hora") y la intención (limitar consumo de cuota, no castigar repeticiones de contenido ya cacheado) |
| D5 | `check_vt_user_limit` pasa a keyed `(guild_id, user_id)` y se purga en el cron | Dejarlo solo por `user_id` | Hoy un usuario que analiza en 4 servidores se bloquea a sí mismo. Además `vt_user_requests` nunca se limpia |
| D6 | F8: caché de huellas `message.id → (ts, sha256)` con TTL 1 h y cap 5.000 (mismo patrón que `_dns_cache`), registrada **al inicio** de `procesar_analisis` | Hacer `update_stats` idempotente por elemento | `update_stats` no tiene clave de dedupe posible (es global). El fingerprint también cierra la carrera `on_message`/`on_message_edit` simultáneos. Registrar al inicio evita doble procesamiento si la tarea anterior lanzó excepción |
| D7 | F3: `url_es_imagen` reutiliza `_resolve_url` y hace el `HEAD` **por IP con header `Host`** (igual que `expandir_url`/`descargar_url_segura`) | Solo validar antes del HEAD | Reutiliza el patrón ya probado; cierra DNS rebinding de verdad, no solo el chequeo previo |
| D8 | F3: `_resolve_url` también rechaza `is_reserved`, `is_multicast`, `is_unspecified` y el bloque CGNAT `100.64.0.0/10` | Solo lo ya implementado | `SECURITY.md:29` clasifica SSRF como vulnerabilidad; el filtro actual deja pasar `0.0.0.0/8`, multicast y CGNAT |
| D9 | F1: mover la mutación de whitelist a `core/guild_config.py` como `async def agregar_dominio(guild_id, dominio)` / `quitar_dominio(guild_id, dominio)`; el cog deja de importar el `_` privado | Solo añadir `await` | Un cog no debería importar un símbolo privado de `core`. Además hace la función testeable sin objetos de Discord |
| D10 | F6: constantes `VT_MAX_ANALYSES_PER_MINUTE`, `VT_MAX_ANALYSES_PER_DAY`, `SE_MAX_ANALYSES_PER_DAY`, `SE_OPS_PER_CALL` en `core/config.py`; se eliminan los literales `4`/`500` de `api/virustotal.py` y `cogs/stats.py` | — | Tres copias del mismo número hoy (`virustotal.py:39,48`, `stats.py:20,34,48`) |
| D11 | F5: `_limpiar_cron` (`bot.py:168`) llama además `guardar_datos(inmediato=True, include_runtime=True)` | Task nueva de intervalo | El cron ya corre cada hora; no añadir un segundo timer. `inmediato=True` cancela el debounce pendiente de forma segura (`database.py:192-200`) |
| D12 | Se añade `pytest -q` a `.github/workflows/test-bot.yml` y un `pyproject.toml` con config de pytest | Dejar CI como está | `pytest` ya está en `requirements.txt` pero nunca se ejecuta. Sin esto, los tests de este plan no protegen nada |

**Fuera de alcance** (anotado, no se toca): F11–F17 (imports muertos, `@vercel/blob`, README del
starter, dominio duplicado, anchors rotos, `vercel.json`, contradicción de la política de
privacidad), el refactor de `bot.analizar_x` a contenedor de servicios, y el
`on_message_edit` en sí (se mantiene; solo se deduplica).

---

## Tareas (en orden — cada una es commiteable y verificable)

### T0. Andamiaje de calidad  (D12)

1. Crear `pyproject.toml` raíz con `[tool.pytest.ini_options]` (`testpaths = ["tests"]`,
   `asyncio_mode = "strict"` — el modo actual, los tests usan `@pytest.mark.asyncio`) y
   `[tool.ruff]` con `line-length = 140` (el archivo más largo del repo tiene ~140 cols).
2. `.github/workflows/test-bot.yml`: añadir un step **antes** del arranque del bot:
   ```yaml
   - name: Tests unitarios
     run: python -m pytest tests -q
   ```
   Con `if: always()` no hace falta; si los tests fallan el job para y `merge-to-main.yml` no dispara.

### T1. F1 — `/whitelist add|remove` rotos  (D9)

- `core/guild_config.py`: añadir
  ```python
  async def agregar_dominio(guild_id: int, dominio: str) -> None:
      async with await _get_guild_lock(guild_id):
          config = await obtener_config_guild(guild_id)
          if dominio not in config["whitelist"]:
              config["whitelist"].append(dominio)
      await guardar_datos(inmediato=True)

  async def quitar_dominio(guild_id: int, dominio: str) -> None:  # simétrico
  ```
  (Ojo: `obtener_config_guild` **ya** toma el lock → usar `state.bot.guilds_data` directo dentro del
  lock, como hace `registrar_infraccion`, para no hacer doble lock).
- `cogs/whitelist.py`: borrar el import de `_get_guild_lock` (línea 8), reemplazar los bloques
  `async with _get_guild_lock(...)` de las líneas 75-77 y 109-111 por llamadas a las dos funciones
  nuevas. Eliminar `WhitelistCog.guardar_whitelist` (líneas 22-31), que queda sin uso.

### T2. F4 + F9 — Cuota de API atómica  (D1, D10)

- `core/config.py`: añadir `VT_MAX_ANALYSES_PER_DAY = 500`, `SE_MAX_ANALYSES_PER_DAY = 500`,
  `SE_OPS_PER_CALL = 4`. Renombrar/documentar `VT_MAX_ANALYSES_PER_MINUTE` como la fuente única.
- `api/virustotal.py`:
  - Reescribir `obtener_siguiente_key` (líneas 24-55): dentro de `_vt_lock`, podar la ventana de
    60 s, comprobar `>= VT_MAX_ANALYSES_PER_MINUTE`, comprobar el diario contra
    `VT_MAX_ANALYSES_PER_DAY`, y **si pasa, reservar**: `vt_key_usage[key].append(ahora)`,
    `vt_key_daily_usage[key]["count"] += 1`, `vt_key_total_requests[key] += 1`. Solo entonces
    `return key`.
  - Igual para `obtener_siguiente_se_key` (líneas 57-83), reservando `SE_OPS_PER_CALL` unidades.
  - **Borrar** `registrar_uso_se` (85-100) y `registrar_uso_vt` (102-117).
  - **Borrar** los 11 call sites: `analizar_url` (167, 189, 199, 212), `analizar_hash` (264),
    `analizar_ip` (321), `analizar_archivo` (399, 416, 430, 445).
- `api/sightengine.py:10,57`: quitar el import y la llamada a `registrar_uso_se`.
- `bot.py:76,81,82`: quitar `registrar_uso_se, registrar_uso_vt` del import y de los atributos.

### T3. F6 — Constantes de límite en `cogs/stats.py`  (D10)

- Reemplazar `self.bot.vt_key_count * 4` → `* config.VT_MAX_ANALYSES_PER_MINUTE` (línea 20),
  `* 500` → `* config.VT_MAX_ANALYSES_PER_DAY` (líneas 34 y 48).
- Importar `core.config` explícitamente (hoy `stats.py` usa solo `self.bot.*`).

### T4. F3 — Cerrar el SSRF  (D7, D8)

- `core/utils.py`: añadir `_IP_BLOQUEADAS_EXTRA` y ampliar `_resolve_url` (líneas 90-127) con un
  predicado `_ip_permitida(ip_obj) -> bool` que rechace, además de lo actual: `is_reserved`,
  `is_multicast`, `is_unspecified`, y que `ip_obj in ipaddress.ip_network("100.64.0.0/10")`.
  Aplicarlo en **ambos** sitios donde hoy se comprueba (`ipaddress.ip_address(hostname)` línea 97
  y cada resultado de `getaddrinfo` línea 113).
- `core/utils.py::url_es_imagen` (61-72): antes del `HEAD`, llamar a `_resolve_url`; si no es
  segura, devolver `False`. Rehacer el `HEAD` por IP con header `Host`, reutilizando el bloque de
  `expandir_url` (líneas 150-155). Añadir el import de `ipaddress` si falta (ya está, línea 5).

### T5. F10 — `Content-Type` dentro del context manager

- `ui/message_handler.py:199-211`: mover `content_type = resp.headers.get(...)` (206) y el bloque
  `if/elif` (208-211) **adentro** del `async with bot.session.get(...) as resp`, antes de que termine
  el bloque. Sacar solo `file_hash` (205) fuera.

### T6. F7 — Antispam unificado  (D4, D5)

- `core/utils.py`: añadir
  ```python
  async def comprobar_antispam(bot, guild_id: int, user_id: int) -> tuple[bool, int]:
      """(permitido, segundos_hasta_poder_reintentar). Registra el consumo si permite."""
  ```
  con key `(guild_id, user_id)` (o `user_id` suelto si `guild_id is None`, como hoy), ventana de
  3600 s, tope `ANTISPAM_ANALYSIS_PER_HOUR`, cooldown `ANTISPAM_COOLDOWN`. Devuelve los segundos
  exactos que `/scan` ya calcula (`oldest + 3600 - ahora`).
- `core/utils.py::check_vt_user_limit` (226-234): cambiar la firma a
  `(guild_id: int | None, user_id: int) -> bool` y usar key `(guild_id, user_id)`.
- `ui/message_handler.py`:
  - `procesar_analisis`: reemplazar el bloque de antispam de las líneas 332-358 por una llamada a
    `comprobar_antispam`, y **mantener** la condición `todas_en_cache` como criterio adicional:
    solo se cobra si `not todas_en_cache or message.attachments`.
  - Actualizar las dos llamadas a `check_vt_user_limit` (485, 542) para pasar `guild_id`.
- `cogs/analisis.py`: reemplazar los dos bloques duplicados de `user_scan_history`
  (79-93 y 219-233) por una llamada a `comprobar_antispam`, reutilizando el formateo de tiempo que
  ya existe en el primero.
- `bot.py::_limpiar_cron` (168-186): añadir la purga de `bot.vt_user_requests` (entradas con
  `time.time() - t > 60`), junto a las purgas existentes.

### T7. F2 — `elemento_id` coherente en el flujo multi-URL  (D2, D3)

- `ui/message_handler.py`:
  - Definir `class UrlResult(NamedTuple)` con `url`, `tipo`, `mal`, `vt_link`, `elemento_id`,
    `ya_logueado`.
  - Cambiar el tipo de `url_results` en la firma de `_construir_embed_unificado` (línea 26) y en
    `procesar_analisis` (línea 297).
  - **Borrar** la declaración de `url_logged_internally` (298) y sus 5 `append` (482, 487, 497, 560)
    más el `multi_logged_internally` (531, 536, 552) y el `zip` de la línea 554.
  - Los 4 `append` de `url_results` pasan a construir `UrlResult(...)` con `elemento_id` explícito:
    - Single cache-hit (481) → `elemento_id=f"url:{url}"`, `ya_logueado=False`
    - Single por límite VT (486) → `elemento_id=f"url:{url}"`, `ya_logueado=False`
    - Single tras `analizar_url` (496) → `elemento_id=f"url:{url}"` (la expandida),
      `ya_logueado=True`
    - Multi (559) → `elemento_id=f"url:{url_exp}"`, `ya_logueado` según venga de caché o de API
  - Reescribir `_construir_embed_unificado` para usar acceso por nombre
    (`any(r.tipo == "malicioso" for r in url_results)`, etc.) en las líneas 41-54 y 89-146.
  - Reescribir las líneas 575-584 igual.
  - El loop de logs (616-619) pasa a:
    ```python
    for r in url_results:
        if r.tipo == "malicioso" and not r.ya_logueado:
            await enviar_log_guild(guild_id, "URL", r.url, f"{r.mal} detecciones",
                                   message.author, url_vt=r.vt_link, elemento_id=r.elemento_id)
    ```
  - Verificar que `elemento_id` y `valor` de la línea 626 (`arch_results`) siguen siendo consistentes
    con lo que registra `api/virustotal.py:509` (`filehash:<sha>`): hoy el log de archivos de la
    rama multi **no** pasa `elemento_id`, así que el botón "Ignorar" no aparece. Añadir
    `elemento_id=f"filehash:{content_hash}"` (el `content_hash` que hoy se descarta con `_` en la
    línea 626) y usar el mismo valor que ya registra `registrar_infraccion` en `:221`.

### T8. F8 — No reprocesar un mensaje idéntico  (D6)

- `ui/message_handler.py`:
  - `_procesados: OrderedDict[int, tuple[float, str]]` a nivel de módulo, con
    `_HUELLA_TTL = 3600.0` y `_HUELLA_MAX = 5000`, replicando la estructura de `_dns_cache`.
  - `_huella_mensaje(message) -> str`: `sha256` de `message.content[:5000]` + los
    `sorted(a.id for a in message.attachments)`.
  - Al inicio de `procesar_analisis`, **antes** de la línea 277: si `_procesados.get(message.id)`
    tiene la misma huella y no expiró → `return`. Si no, `_procesados[message.id] = (now, huella)`
    y continuar.
  - Exportar `limpiar_cache_procesados() -> int` para purgar expirados.
- `bot.py::_limpiar_cron`: llamarla en cada pasada y loguear el conteo.

### T9. Tests

Todos sin red. `tests/conftest.py` ya añade la raíz al `sys.path`.

1. `tests/test_guild_config.py` (extender) — `agregar_dominio` / `quitar_dominio`:
   añade, no duplica, quita, no lanza si no existe; dos `agregar_dominio` concurrentes con el mismo
   dominio dejan **una** entrada (regresión directa de F1).
2. `tests/test_ssrf.py` (nuevo) — `_ip_permitida` con tabla parametrizada: `127.0.0.1`, `10.0.0.1`,
   `192.168.1.1`, `169.254.169.254`, `0.0.0.0`, `100.64.0.1`, `224.0.0.1`, `[::1]`, `[fe80::1]`,
   `[fc00::1]` → todos bloqueados; `8.8.8.8`, `1.1.1.1`, `[2606:4700::1111]` → permitidos.
3. `tests/test_api_quota.py` (nuevo) — con `VT_API_KEYS` monkeypatcheado a **una** clave y un
   `state.bot` falso: `asyncio.gather` de 10 llamadas concurrentes a `obtener_siguiente_key()`
   devuelve `None` en 6 de 10 y la key en 4 (regresión de F4). Segundo test: el total diario
   persiste entre llamadas. Tercero (F9): seleccionar key e ignorar el resultado igual incrementa
   `vt_key_total_requests`.
4. `tests/test_antispam.py` (nuevo) — `comprobar_antispam` con un objeto bot falso:
   29 llamadas seguidas → la 30.ª devuelve `(False, >0)`; tras `await asyncio.sleep` simulado con
   `patch("core.utils.time")` la ventana se poda y vuelve a permitir; cooldown de 10 s bloquea la
   segunda llamada inmediata; dos guilds distintos con el mismo `user_id` **no** se bloquean entre sí
   (regresión de F5/D5).
5. `tests/test_message_handler.py` (nuevo) — dos funciones puras extraídas en T7/T8:
   - `_construir_embed_unificado` con combinaciones: solo URLs seguras, URL maliciosa + NSFW +
     archivo malicioso, todo error, omitidos > 0. Verificar título, color y contadores
     (segmentos `█`/`░`).
   - Dedupe de huellas: mismo `message.id` + misma huella → la segunda llamada no procesa;
     huella distinta → sí procesa; huella expirada → sí procesa.
6. `tests/test_utils.py` (extender) — `normalizar_url` (puerto `:80`/`:443`, barra final, query),
   `_limpiar_url`, `dominio_en_whitelist` con `evil-youtube.com` y `youtube.com.evil.io`.

### T10. Documentación

- `README.md`: la tabla de "Protección activa" dice "30 análisis/hora por usuario, cooldown de 10s" —
  sigue siendo cierto tras T6; no cambia. Verificar que `/whitelist` sigue listada como funcional.
- `SECURITY.md`: sin cambios.

---

## Fuera de alcance

F11–F17 (import muerto `es_url_segura`, dependencia `@vercel/blob` sin uso, `landing/README.md` del
starter, dominio canónico duplicado, 3 anchors rotos en el footer, `landing/vercel.json`
redundante, contradicción entre `privacidad.astro:78` y Vercel Analytics), refactor de
`bot.analizar_x` a un contenedor de servicios, y `load_cogs` con ruta basada en `__file__`.

---

## Validación

**Automatizada**

1. `python -m compileall .` → sin errores (gate actual de CI).
2. `python -m pytest tests -q` → verde, incluyendo los ~30 casos nuevos. Este comando **no se pudo
   ejecutar** en el sandbox donde se escribió el plan.
3. `ruff check .` si se adopta ruff (`.ruff_cache/` ya está en `.gitignore`).

**Manual (requiere un servidor de Discord de prueba y keys reales)**

| # | Escenario | Resultado esperado |
|---|---|---|
| M1 | `/whitelist add example.com` → `list` → `remove example.com` | Los tres responden; `list` refleja el cambio. Antes: `AttributeError` |
| M2 | Mensaje con **2 URLs** maliciosas, la segunda tras un acortador | En el canal de logs, "Ignorar" sobre la del acortador responde "Infracción eliminada" y `/usercheck` baja en 1. Antes: "Esa infracción ya no existe" |
| M3 | Mensaje con un archivo malicioso **junto a** una URL | El log del archivo trae botón "Ignorar" funcional (hoy no aparece) |
| M4 | 10 mensajes seguidos con URLs nuevas del mismo usuario | Ningún `429` de VirusTotal en los logs; `/stats` muestra el consumo real |
| M5 | `/stats` → reiniciar el bot → `/stats` | Los contadores diarios **no** vuelven a 0 |
| M6 | `/whitelist` y `/stats` tras reiniciar | Los límites mostrados coinciden con `n_keys × 4/min` y `× 500/día` |
| M7 | Mensaje con `http://127.0.0.1:8000/`, `http://169.254.169.254/` y `http://[::1]/` | El bot responde "error"/"too_large" sin ninguna petición saliente a esas IPs |
| M8 | Editar un mensaje sin cambiar su contenido | No se envía un segundo embed ni cambian los contadores de `/stats` |
| M9 | Editar un mensaje **cambiando** el enlace por uno malicioso | Se analiza y se aplica la acción correspondiente |
| M10 | Adjuntar un `.png` que en realidad es un `.exe` | El campo "Verificación MIME"/aviso de extensión aparece en el embed |

**Nota de despliegue**: el deploy hace `git reset --hard origin/main` + `git clean -fd` en Pterodactyl.
`core/data.json` y `core/analisis.db` están gitignorados y `git clean` **sin** `-x` no los borra, así
que el formato de persistencia puede cambiar sin perder configuración. Aun así, tras T2 los contadores
viven en el mismo esquema (`__api_usage__`), así que no hace falta migración.

---

## Riesgos

| Riesgo | Mitigación |
|---|---|
| T2 cambia el punto de conteo: ahora **toda** key seleccionada cuenta, incluso si la llamada falla | Es intencional (F9). El coste es sobreestimar ligeramente el consumo en `/stats`, que es preferible a subestimarlo y agotar cuota |
| T2 borra dos funciones exportadas en `bot.py` | Verificado por grep: solo se usan dentro de `api/virustotal.py` y `api/sightengine.py`. Ningún cog las consume |
| T7 toca ~15 sitios de desempaquetado de `url_results` | Mitigado con `NamedTuple` de campos nombrados: un sitio mal actualizado falla al instante en los tests de `_construir_embed_unificado`, no en silencio |
| T8 puede saltarse el análisis si Discord entrega dos eventos con contenido idéntico para el mismo `message.id` | Es el objetivo. El TTL de 1 h limita la ventana del riesgo; un reinicio limpia el dict |
| T4 cambia el comportamiento de `url_es_imagen` para URLs válidas | La resolución por IP + header `Host` es el mismo patrón que ya usan `expandir_url` y `descargar_url_segura`, que funcionan en producción |
| Añadir `pytest` a CI hace fallar el pipeline mientras `tests/` se incrementally complete | Mitigado por el orden de T0: los tests se escriben en T9 y CI corre en T0. **Ejecutar `pytest -q` en verde antes de abrir el PR que activa el step de CI** |

---

## Pregunta abierta

Ninguna bloqueante. Decisión ya tomada por defecto si no hay objeción: **D3** (convertir
`url_results` a `NamedTuple` de 6 campos) es el cambio más grande del plan y el único que altera la
firma de `_construir_embed_unificado`. La alternativa de mínimo cambio es mantener la tupla de 4
campos y meter `elemento_id`/`ya_logueado` en un `dict` aparte, pero eso conserva el emparejamiento
por índice que causó F2.
