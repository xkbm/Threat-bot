# Plan de implementación — Corregir 6 defectos que limitan el bot (F0)

Objetivo: arreglar los 6 bugs verificados del análisis del repo, sin features nuevas.
Cada uno está confirmado leyendo el código; las referencias `archivo:línea` son del estado
de `main` en `61d90c3`.

**Por qué F0 y no features**: con 3 claves de VT el techo son **1.500 análisis/día**, y una URL
desconocida cuesta **5 unidades** (`api/virustotal.py:183-251`: GET → POST → 2 polls → GET final).
El defecto F1 hace que la caché de 7 días sea de solo-escritura en el autoescaneo, así que cada
reposteo de un dominio sin path vuelve a pagar las 5 unidades. Arreglar la cuota va antes que
cualquier feature que consuma más API.

---

## Contexto

**Repo**: bot de seguridad Discord, Python 3.10, `discord.py==2.7.1`, `aiohttp==3.14.3` (pin por
el parche de SNI, `requirements.txt:2-6`), `aiosqlite`. `landing/` es Astro 6, no se toca.

**Patrón de estado a respetar**: los contadores mutables viven como atributos de `state.bot`
(`vt_key_usage`, `user_scan_history`, `antispam_scan`, `vt_user_requests`, `guilds_data`).
Los locks por guild son módulo-globales en `core/guild_config.py`.

**Restricción de entorno**: en el sandbox donde se escribió este plan **no se pudo ejecutar
`python`, `pytest` ni `ruff`** (toolchain no instalada y `bash` restringido). La validación es
`compileall` + `pytest` + `ruff` en el entorno del usuario y en CI. No se ha dado por supuesto
nada que no se haya leído en el código.

**Restricción de despliegue**: `core/data.json` y `core/analisis.db` están gitignorados y el
deploy hace `git reset --hard` + `git clean -fd` (sin `-x`), así que no se borran. Ninguna
tarea de este plan cambia el esquema de persistencia → **no hace falta migración**.

---

## Decisiones tomadas

| # | Decisión | Alternativa descartada | Motivo |
|---|---|---|---|
| D1 | **Clave canónica de URL = `f"url:{normalizar_url(url)}"` en los dos lados.** `api/virustotal.py:510` pasa a normalizar antes de guardar, y `cogs/analisis.py:58` deja de usar la clave cruda | Alias de las dos claves / clave cruda en ambos lados | Con una sola forma de clave los aciertos están garantizados y las variantes (`http`/`https`, barra final, `:443`, mayúsculas) comparten entrada, que es justo lo que `normalizar_url` (`core/utils.py:228-237`) sabe colapsar. Escribir bajo dos claves duplicaría filas y complicaría el borrado |
| D2 | **`suspicious` es un veredicto de primer nivel (`"sospechoso"`), no se suma a `malicious`** | `mal = malicious + suspicious` | Es lo que VT quiere decir: `suspicious` es una categoría de primera clase del esquema, no "malicioso pero menos". Sumarla convertiría sitios legítimos con 1–2 engines ruidosos en "maliciosos" y, con el modo estricto por defecto (`core/guild_config.py:25`), **borraría el mensaje**. El coste de `sospechoso` es que hay que propagar un cuarto veredicto por el render-on-read, y eso lo hace explícito |
| D3 | **Modo estricto borra por amenaza, doble extensión real O MIMEMismatch** | Solo doble extensión / ninguna | Ambas señales son "el archivo miente sobre lo que es", que es el patrón del scam. El defecto era que la tupla llevaba el MIMEMismatch en el slot que el llamante leía como doble extensión, así que la señal verdadera se perdía |
| D4 | **Single-flight por clave de caché con un `dict` de `asyncio.Lock`**, no un `Event` | Cachear el `Task` en sí | Un `Lock` no necesita cleanup en el cron ni puede quedar filtrado si una tarea se cancela: se guarda bajo la clave, se usa y se borra en `finally`. El dict se autolimpia, no hay estado que purgar |
| D5 | **`/scan` pasa `mensaje_original=None` pero registra la infracción vía un camino explícito**, no "false" en el argumento | Pasar un `Message` falso / no registrar | `registrar_infraccion` y `update_stats` son idempotentes por `elemento_id`, así que el camino correcto es un parámetro nuevo `registrar: bool` en `_on_threat_found`, no duplicar la cadena de side-effects |
| D6 | **`/usercheck` exige `moderator`** (`default_permissions` + comprobación en runtime) | Dejarlo abierto | Es un expediente de seguridad de una persona y `SECURITY.md:26` ya lista "bypass del sistema de permisos" como vulnerabilidad. Se usa la bandera compuesta `discord.Permissions.moderator()` (manage_messages + kick + ban + timeout) porque cubre a quien modera sin ser administrador, que es el caso real en servidores medianos |
| D7 | **`sospechoso` se cachea con su propio string de veredicto**, no se re-deriva de `mal` | Guardar siempre `mal` y derivar | `core.cache._render` y `core.database.renderizar_embed` reconstruyen el embed desde `datos` + `mal`. Para que un "sospechoso" cacheado se re-renderice bien **meses después** (el payload `datos` es lo que se persiste), el veredicto tiene que viajar dentro de `datos` |

**Fuera de alcance** (anotado, no se toca en este plan): enriquecimiento de respuestas de VT
(familia de malware, antigüedad del dominio, reputación), `GET /domains/{domain}`, heurísticas
propias sin API, timeout de Discord, views persistentes, stats por servidor, `url=` en
SightEngine, y los F11–F17 del plan anterior (imports muertos, `@vercel/blob` sin uso, dominio
duplicado, anchors rotos). Todo eso es candidato a un plan propio **después** de este.

---

## Los 6 defectos

| # | Defecto | Ubicación | Efecto |
|---|---|---|---|
| F1 | La caché de URLs nunca acierta en el autoescaneo | `ui/message_handler.py:562,441` escribe-key en `api/virustotal.py:510` | Repostear una URL sin path gasta 5 unidades de VT otra vez. Con 1.500/día de techo, es el bug que limita el bot |
| F2 | `has_doble_ext` lee el MIMEMismatch, no la doble extensión | `ui/message_handler.py:691` vs `:288` | Modo estricto **nunca** borra por doble extensión, que es su motivo documentado |
| F3 | El veredicto ignora `suspicious` | `api/virustotal.py:509` | El bot responde "seguro, sin detecciones" sobre enlaces que VT marca como sospechosos. Es el veredicto incorrecto más frecuente |
| F4 | `/usercheck` peta en DM y no tiene gate de permisos | `cogs/rep.py:18` y `:15` | `AttributeError` sin manejar tras el `defer`; cualquier miembro lee el expediente de cualquier otro |
| F5 | `/scan` no registra infracción ni log de amenaza | `api/virustotal.py:572` (guarda de `mensaje_original`) | Autoescaneo y comando discrepan del mismo veredicto; `/stats` solo cuenta lo del autoescaneo |
| F6 | Sin single-flight | `ui/message_handler.py:563-604, 625-662` | 20 usuarios pegando la misma URL nueva = 20 llamadas a VT, 100 unidades, 20 filas en stats |

---

## Tareas (en orden — cada una commiteable y verificable)

### T1. F1 — Clave de caché canónica  (D1)

- `core/utils.py`: **no tocar** `normalizar_url`. Ya es correcta.
- `api/virustotal.py:507-510`: en `_procesar_resultado_vt`, calcular la clave según el tipo:
  ```python
  clave_valor = normalizar_url(valor) if tipo == "url" else valor
  clave = f"{tipo}:{clave_valor}"
  ```
  Importar `normalizar_url` desde `core.utils` (comprobar que no crea ciclo: `core/utils.py`
  importa `discord`, `aiohttp`, `core.config` — no importa `api/`; `api/virustotal.py` ya importa
  de `core.utils`, confirmado en `:16`).
- `api/virustotal.py:534-537` (`_procesar_analisis_archivo`): la clave ya es `filehash:{sha}`,
  que es canónica de por sí. Sin cambio.
- `cogs/analisis.py:58`: cambiar `clave = f"url:{valor}"` por
  `clave = f"url:{normalizar_url(valor)}"`. Importar `normalizar_url` (el import de la línea 8
  ya trae el resto de `core.utils`).
- **`elemento_id` NO se toca**: sigue siendo `f"url:{valor}"` con la URL **expandida** y sin
  normalizar (`ui/message_handler.py:576,589,602,642,656,662` y `api/virustotal.py:573`). Es
  deliberado y está documentado en el commit `61d90c3`: la infracción se ancla a la URL
  expandida que el usuario leyó, no a la clave de caché. Cambiarlo aquí rompería el botón
  "Ignorar" de los logs ya enviados.
- **Borrar** las claves `url:` antiguas de `core/analisis.db` no es necesario: se quedan
  huérfanas y expiran solas (7 días, `core/config.py:54`). Reanalizar las que sigan vivas cuesta
  cuota una sola vez.

**Regresión que cubre**: escribir una URL por `analizar_url` y releerla por el camino del
autoescaneo con la misma cadena normalizada → **acierta**.

### T2. F3 — Veredicto `sospechoso`  (D2, D7)

Este es el cambio más grande: un cuarto veredicto atraviesa el render-on-read, la caché, SQLite,
el embed unificado, las reacciones, el log de amenazas y `/stats`.

- `core/config.py`:
  - `COLOR_SOSPECHOSO: int = 0xE8C547` (reutiliza el token `--color-alert` de
    `landing/src/styles/global.css:15`, que existe en la paleta de la web y está libre en el bot).
  - `SEVERIDAD_COLOR["sospechoso"] = COLOR_SOSPECHOSO`.
  - `EMOJI_SOSPECHOSO`: **no crear un emoji nuevo**. Reutilizar `EMOJI_WARNING`, que ya es el
    icono de "algo va mal" y está en el bot. Un emoji nuevo exigiría subirlo al servidor de
    Threat y cambiar su ID; no está justificado para un cuarto nivel de severidad.
- `api/virustotal.py`:
  - `_procesar_resultado_vt:508-525`: leer `stats.get("suspicious", 0)`; calcular
    `tipo_str = "malicioso" if mal > 0 else "sospechoso" if susp > 0 else "seguro"`;
    meter `susp` en `datos` (D7) y **no** llamar a `_on_threat_found` cuando sea
    `"sospechoso"` — un sospechoso se muestra y se loguea, pero no genera infracción ni borra
    (D2). Añadir `"susp": susp` a `datos` para que el render-on-read reconstruya el título bien.
  - `analizar_hash:309` y `analizar_ip:355`: mismo cálculo de `susp` sobre sus `stats`.
  - `_procesar_analisis_archivo:534-551`: idem, leyendo `susp` de `stats`.
  - `_on_threat_found:571-575`: **no tocar la guarda**. Sigue siendo "solo con
    `mensaje_original`", que es lo que F5 va a resolver explícitamente en T5.
- `ui/embed.py`:
  - `TITULOS`: añadir `url_sospechosa: "URL sospechosa"`, `hash_sospechoso: "Hash sospechoso"`,
    `ip_sospechosa: "IP sospechosa"`, `archivo_sospechoso: "Archivo sospechoso"`. Los 4 pasan el
    test de sentence case (`test_sentence_case_en_titulos`, `tests/test_embeds.py:172`) y el de
    unicidad (`:187`) porque son todos distintos.
  - `_TITULO_RESULTADO:135-144`: añadir las 4-tuplas `("url","sospechoso")` etc.
  - `resultado:147-173`: `veredicto` pasa a leerse de `datos.get("veredicto")` con fallback a
    la regla actual `mal > 0` (D7) — así las filas antiguas de SQLite y las entradas legacy sin
    `veredicto` en `datos` siguen renderizando igual que antes. La `description` pasa a ser
    `"**{mal}** detecciones"` / `"**{susp}** engines lo marcan como sospechoso"` /
    `"Sin detecciones"`.
  - `pie(embed, f"{etiqueta} · {veredicto}")` ya sale bien sin cambios.
- `core/guild_config.py:81-96` (`update_stats`): añadir la rama `elif tipo == "sospechoso"` que
  incrementa `global_stats["sospechoso"]`. `obtener_stats_globales:76-79` y los dos dicts
  iniciales (`:78`, `:84`) necesitan la clave nueva, y `core/database.py` (los defaults de
  `__global__` al cargar) también — **buscar los dos sitios**: `guild_config.py:78` y `:84` más
  el `cargar_datos` de `database.py`.
- `cogs/stats.py:69-84`: añadir el campo `Sospechosos` con el icono `EMOJI_WARNING`. No tocar
  `porcentaje_maliciosos`: hoy divide `maliciosos` entre `total_analisis`, que ya mezcla
  categorías. Arreglar eso es cosmético y queda fuera.
- `ui/message_handler.py`:
  - `_icono_de_estado:176-183`: rama `"sospechoso"` → `EMOJI_WARNING`.
  - `_construir_embed_unificado:120-149`: `has_suspicious`, su contador, su línea en la
    `desc`, su color cuando no hay amenaza confirmada y su título ("Elementos sospechosos
    detectados"). Cuando hay `sospechoso` **y** `malicioso`, manda el título/color de
    `malicioso` y `sospechoso` solo añade contador y línea.
  - `seguros` en `:137` se recalcula para que `sospechoso` no cuente como seguro.
  - El log de amenazas en `:721-740` **no** incluye `sospechoso` (D2: no hay infracción que
    ignorar, y `elemento_id` sin infracción haría que "Ignorar" responda "esa infracción ya no
    existe").
- `api/sightengine.py`: **no tocar**. `susp` es un concepto de VT, no de SightEngine.

### T3. F2 — `has_doble_ext` real  (D3)

- `ui/message_handler.py`:
  - `_procesar_archivo:281-324`: la tupla de retorno pasa de 5 a 6 campos,
    `(filename, tipo, mal, file_hash, wm, doble_ext)`. Actualizar los 3 `return` (`:293, 298,
    301, 312, 321, 324` — son 5, todos con `"error"` o con el resultado). El `doble_ext` ya se
    calcula en `:288`; hoy solo se usa para la reacción de `:291` y se pierde.
  - **Todos** los desempaquetados de 5 campos pasan a 6: `:122, 131, 137, 147, 152, 684, 687,
    690, 691, 734`. Los que usan `_` se adaptan; los que nombran variables, también.
  - `:691` pasa a `has_doble_ext = any(d for _, _, _, _, _, d in arch_results if d)`.
  - `:712` (`if (has_threat or has_doble_ext) and strict_mode`) pasa a
    `if (has_threat or has_doble_ext or has_mime_mismatch) and strict_mode`, con
    `has_mime_mismatch = any(w for _, _, _, _, w, _ in arch_results if w)` (D3).
  - `_construir_embed_unificado`: el docstring de la firma (`:107`) pasa a documentar los 6
    campos.
- `cogs/analisis.py`: **no tocar**. `/scan` ya muestra ambos avisos como campos del embed
  (`:138-141, 170-173`) y no borra nada; no tiene mensaje que borrar.

### T4. F6 — Single-flight por clave  (D4)

- `ui/message_handler.py`, a nivel de módulo (junto a `_procesados`, `:32-34`):
  ```python
  _vuelos: dict[str, asyncio.Lock] = {}
  _vuelos_lock = asyncio.Lock()

  @asynccontextmanager
  async def _vuelo(clave: str):
      """Serializa los análisis de una misma clave: el primero llama a la API y los
      demás esperan su resultado en lugar de gastar una unidad de cuota cada uno."""
      async with _vuelos_lock:
          lock = _vuelos.get(clave)
          if lock is None:
              lock = _vuelos[clave] = asyncio.Lock()
      async with lock:
          yield
      async with _vuelos_lock:
          if not lock.locked() and _vuelos.get(clave) is lock:
              del _vuelos[clave]
  ```
  Requiere `from contextlib import asynccontextmanager`.
  El `finally` implícito del `async with lock` libera a los esperadores **antes** de borrar la
  entrada, así que un tercer mensaje que llegue entre medias no se queda con un lock ya
  huérfano.
- Aplicar en los 3 caminos de caché-miss: `:585-604` (URL única), `:650-662` (`_api_url` de
  multi-URL) y `cogs/analisis.py:208-238`. El de archivo (`_procesar_archivo:313-324`) se cubre
  solo si se envuelve también; **sí incluirlo**, usa la misma clave `filehash:`.
- Con el wrapped, los esperadores reciben `(None, None, 0)` del `get_from_cache_mem` de su
  siguiente iteración solo si vuelven a mirar — **no**: hay que re-leer la caché **después** de
  adquirir el vuelo, no antes. Reordenar: adquirir el vuelo → mirar caché → si sigue miss,
  llamar a la API. Si no se reordena, el single-flight no sirve de nada porque todos decidieron
  llamar a la API antes de esperar.
- Purga: el dict se autolimpia (D4), pero **añadir el log de depuración** `log.debug(f"VUELO → key={clave} espera={lock.locked()}")`
  para poder verificarlo en producción.

### T5. F5 — `/scan` registra la infracción  (D5)

- `api/virustotal.py:571-575` (`_on_threat_found`): cambiar la guarda
  `if guild_id and mensaje_original:` por `if guild_id and (mensaje_original or registrar):`,
  con `registrar: bool = False` como parámetro nuevo. Cuando `mensaje_original` es `None`, la
  cadena de side-effects corre **sin** el paso de `mensaje_original.delete()` (`:564` ya está
  dentro de `if mensaje_original` implícito por el `config["strict_mode"]` — hay que envolver esa
  parte, no dejarla ejecutarse con `None`).
- `api/virustotal.py:553-560` (`_post_threat_side_effects`): recibir `mensaje_original:
  Optional[discord.Message]` y hacer el `delete()` solo si no es `None`.
- `cogs/analisis.py`: las 3 llamadas de la rama `url` / `ip` / `hash` (`:221, 232, 237`) pasan
  `registrar=True`. La llamada de archivo (`:148-150`) también, pero su `elemento_id` debe ser
  `f"filehash:{file_hash}"` explícito — hoy `analizar_archivo` ya lo calcula solo
  (`api/virustotal.py:541`), no hay que cambiar nada.
- `cogs/analisis.py:196-206` (cache-hit): **registrar también**. Hoy una URL maliciosa cacheada
  escaneada por `/scan` no deja rastro. Añadir, tras el `if embed is not None:`, un
  `if tipo.value == "url" and tipo_res == "malicioso": await registrar_infraccion(...)` con el
  mismo `elemento_id = f"url:{valor}"` que usa el log. Requiere exponer
  `registrar_infraccion` en `bot.py` (no está en la lista de exportaciones, líneas 76-104).
- `cogs/analisis.py`: **no** aplicar el log de amenazas a `/scan`. El comando es explícito: quien
  lo ejecuta ya está mirando el resultado. Mandarlo al canal de logs duplicaría el ruido de un
  evento que el moderador está provokeando a mano.

### T6. F4 — `/usercheck`  (D6)

- `cogs/rep.py`:
  - Añadir `@app_commands.default_permissions(manage_messages=True)` al comando. Se declara
    `manage_messages` (y no `moderator`) porque `default_permissions` solo acepta un permiso
    simple, no una bandera compuesta.
  - Comprobación en runtime antes del `defer`:
    ```python
    if not interaction.permissions.moderator:
        await interaction.response.send_message("Necesitas ser moderador para usar este comando.", ephemeral=True)
        return
    ```
    `discord.Permissions.moderator` es la bandera compuesta que discord.py ya expone: cubre
    también a quien modera sin ser administrador, que es el caso real en servidores medianos.
  - Guardar DM: `if interaction.guild is None:` → responder efímero y `return`, **antes** de
    `await interaction.response.defer(ephemeral=True)` (que hoy ya se ejecutó cuando revienta
    `interaction.guild.id` en `:18`).
  - El `log.debug` de `:41` ya registra `admin={interaction.user.id}`; renombrar a
    `moderador=` para que el log diga lo que significa.
- **No** añadir un comando nuevo para esto. El bug es una guarda que falta, no una feature.

### T7. Tests

Todos sin red, en `tests/`. `conftest.py` ya añade la raíz al `sys.path`.

1. `tests/test_cache_keys.py` (**nuevo**) — regresión directa de F1:
   - `normalizar_url` colapsa `https://x.com` y `https://x.com/` al mismo `clave`.
   - Con un `state.bot` falso y la caché SQLite real en `:memory:`, llamar a
     `_procesar_resultado_vt` con `https://x.com` y luego leer con
     `f"url:{normalizar_url('https://x.com/')}"` → **acierto**.
   - `/scan` y el autoescaneo producen la **misma** clave para el mismo input (el test compara las
     dos expresiones, no necesita el cog entero).
2. `tests/test_veredictos.py` (**nuevo**) — F3:
   - `stats` con `malicious: 0, suspicious: 3` → veredicto `"sospechoso"`, título
     `url_sospechosa`, color `COLOR_SOSPECHOSO`, y **no** se llama a `_on_threat_found`.
   - `malicious: 1, suspicious: 5` → `"malicioso"` (precedence).
   - `malicious: 0, suspicious: 0` → `"seguro"`.
   - Render-on-read: un `datos` con `{"veredicto": "sospechoso", "susp": 3}` cacheado, leído
     después, devuelve el embed con el título sospechoso (D7).
   - Fila legacy sin `veredicto` en `datos` → sigue renderizando por la regla `mal > 0`.
3. `tests/test_message_handler.py` (extender) — F2:
   - `_construir_embed_unificado` con `arch_results` de 6 campos, uno con `doble_ext=True` y
     `wm=""`, otro con `doble_ext=False` y `wm="Extensión .png pero tipo real text/html"`.
   - Un test dedicado del gate de borrado: extraer la condición de `:712` a una función pura
     `debe_borrar(has_threat, has_doble_ext, has_mime_mismatch, strict_mode) -> bool` y
     parametrizarla con las 8 combinaciones. Es la única forma de testearla sin un `Message`
     real de Discord.
4. `tests/test_singleflight.py` (**nuevo**) — F6:
   - 20 corrutinas concurrentes sobre la misma clave con un factory que cuenta invocaciones y
     `await asyncio.sleep(0)` → el factory se llama **1 vez**.
   - 20 corrutinas sobre 20 claves distintas → 20 invocaciones (el vuelo no serializa de más).
   - Tras salir del `with`, `_vuelos` queda vacío.
   - Una excepción dentro del vuelo no deja la clave bloqueada para la siguiente llamada.
5. `tests/test_ssrf.py` / `test_utils.py` (extender) — sin cambios de comportamiento, pero
   `normalizar_url` merece casos para los puertos y la barra final ya que ahora es la clave de
   caché (`tests/test_utils.py` ya los tiene; **verificar que siguen en verde**).

### T8. Documentación

- `README.md:36` — la tabla de "Protección activa" no menciona `sospechoso`. Añadir una línea
  al apartado de "Análisis automático" indicando que los enlaces que VT marca como
  *suspicious* se reportan como sospechosos y no disparan borrado. Es el único cambio de
  comportamiento visible para el usuario final.
- `README.md:42-54` — la lista de comandos no incluye `/uptime`, `/ping`, `/disablelogchannel`,
  `/reboot`, `/eval`. **Fuera de alcance** de este plan (es F11–F17 del plan anterior), pero
  anotarlo para el plan siguiente.
- `SECURITY.md` — sin cambios. La decisión D2 (un sospechoso no genera infracción) es
  conservadora desde el punto de vista de privacidad, no hace falta documentarla ahí.

---

## Orden demerge

F1 y F6 son la misma línea de pensamiento (cuota) y se refuerzan: T1 sin T4 deja el bug
parcialmente arreglado. **T1 y T4 van en el mismo PR o en commits consecutivos.**

F3 es independiente y es el que más superficie toca. Si hubiera que revertir algo, F3 es el
candidato — pero es también el de mayor valor de detección, así que no es un buen candidato a
revertir.

F2, F4 y F5 son independientes entre sí y de bajo riesgo.

---

## Validación

**Automatizada** (en el entorno del usuario y en CI — no se pudo ejecutar en el sandbox):

1. `python -m compileall .` → sin errores.
2. `python -m pytest tests -q` → verde, incluyendo los ~25 casos nuevos. Los tests existentes de
   `test_embeds.py` son los que más riesgo tienen: `test_titulo_correcto` (`:143`) está
   parametrizado con 8 combinaciones y hay que **añadir las 4 de `sospechoso`**, y
   `test_severidad_abierta` (`:137`) recorre `SEVERIDAD_COLOR` para comprobar que todo valor de
   la paleta es un color de Discord.
3. `ruff check .` con la config de `pyproject.toml` (solo `E9` + `F`).

**Manual** (requiere un servidor de prueba y keys reales):

| # | Escenario | Resultado esperado |
|---|---|---|
| M1 | Publicar `https://ejemplo-sin-path.com` dos veces, separadas por minutos | La 2.ª vez **no** aparece `SQLITE MISS` en el log de depuración; `/stats` no suma análisis. Antes: 5 unidades de VT por repetición |
| M2 | Publicar `https://ejemplo.com` y luego `https://ejemplo.com/` | Una sola entrada de caché. Antes: dos claves distintas |
| M3 | Enviar `foto.png.exe` en modo estricto | El mensaje se borra. Antes: no se borraba |
| M4 | Enviar un `.png` que Discord sirve como `text/html`, en modo estricto | El mensaje se borra (esto ya funcionaba; el test es para confirmar que no se rompió) |
| M5 | Enviar `foto.png` bien formada, en modo estricto | El mensaje **no** se borra |
| M6 | 20 usuarios pegan la misma URL nueva a la vez | Los logs muestran **un** `VT URL INICIO` y 19 esperas; `/stats` suma 1 análisis |
| M7 | `/scan` de una URL maliciosa sin cachear, y luego la misma en caché | Ambas muestran log de amenaza y la infracción suma 1 (idempotente por `elemento_id`) |
| M8 | `/scan` de una URL maliciosa **sin** canal de logs configurado | No lanza; el embed de respuesta se ve igual |
| M9 | `/usercheck` en DM | Responde "solo en servidores", sin traceback |
| M10 | `/usercheck` como miembro sin permisos de moderación | Responde "necesitas ser moderador", ephemeral, sin defer |
| M11 | `/scan` de un enlace que VT marca `suspicious: 3, malicious: 0` | Título "URL sospechosa", ámbar, **no** se borra con el modo estricto, **no** genera log de amenaza ni infracción |
| M12 | El mismo enlace con `malicious: 2, suspicious: 5` | Título "URL maliciosa", ámbar de malicioso, se borra y genera log |

**Nota de despliegue**: sin migración. Los formatos de `data.json` y `analisis.db` no cambian;
`__global__` gana la clave `sospechosos` con `setdefault`-equivalente en `cargar_datos`, igual
que ya se hizo con `nsfw` (`core/database.py`, rama `global_stats.get("nsfw", 0)`). Las filas
`url:` viejas en SQLite se quedan huérfanas y expiran solas a los 7 días.

---

## Riesgos

| Riesgo | Mitigación |
|---|---|
| **T2 toca ~25 sitios.** Un `tipo == "malicioso"` que se quede sin su rama `sospechoso` convierte un sospechoso en "seguro" en silencio, que es exactamente el bug que se arregla | El veredicto viaja dentro de `datos` (D7) y `resultado()` tiene fallback a la regla antigua, así que un sitio olvidado **degrada al comportamiento anterior**, no a "seguro" — el `_TITULO_RESULTADO.get()` ya devuelve un texto genérico. Los tests parametrizados de `test_veredictos.py` cubren las 3 precedencias |
| **T1 deja huérfanas las claves `url:` existentes** | Expiran solas en 7 días. Lo único que cuesta es reanalizar las que sigan vivas, una vez. No se borra nada a mano: `git clean -fd` no toca ficheros gitignorados |
| **T4 puede serializar análisis distintos** si la clave no es canónica | Es exactamente por eso que T1 va antes. Con la clave canónica, dos textos que VT no distingue **sí** son el mismo análisis, que es la definición correcta de un vuelo |
| **T4 con un `Lock` reentrante mal colocado** deja mensajes colgados | El `async with lock` se libera siempre (incluso con excepción) y el `finally` del context manager borra la entrada. El test de "excepción no bloquea la siguiente llamada" cubre exactamente esto |
| **T5 hace que `/scan` registre infracciones**, lo que cambia el comportamiento observable del comando | Es el objetivo (D5), pero es el cambio con más riesgo de sorpresa para el usuario. `registrar_infraccion` es idempotente por `elemento_id`, así que `/scan` dos veces la misma URL **no** sube el contador |
| **T2 añade un color que no está en la paleta del bot** | Se reutiliza `--color-alert: #E8C547` de `landing/src/styles/global.css:15`, que ya es parte del sistema visual de la marca. No se inventa un hex nuevo |

---

## Pregunta abierta

Ninguna bloqueante. Un punto que el implementador debe decidir al escribir T4: **dónde** va el
`async with _vuelo(clave)` exactamente. La regla es "adquirir el vuelo **antes** de mirar la
caché, y llamar a la API dentro". Si el `async with` se coloca solo alrededor de la llamada
(`analizar_url(...)`) sin reordenar la comprobación de caché que la precede, el single-flight no
ahorra nada: los 20.messages deciden llamar a la API antes de esperar al primero. Dejar el motivo
escrito como el que ya hay en `ui/message_handler.py:302-303` para el MIMEMismatch.
