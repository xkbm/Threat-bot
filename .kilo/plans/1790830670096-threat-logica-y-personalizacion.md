# Threat — coherencia de escaneo + personalización

## Contexto

Bot de seguridad para Discord (Python 3.10+, discord.py 2.7.1). Analiza URLs, archivos,
imágenes, hashes e IPs con VirusTotal y SightEngine, y avisa/borrar en modo estricto.

La auditoría del repo encontró que **la lógica de clasificación de contenido no tiene
sentido**: la regla es binaria y excluyente, y por eso hay rutas donde un archivo nunca
se escanea. Además hay defectos de persistencia que contradicen comentarios del propio
código. Este plan arregla los defectos, hace que toda regla tenga justificación explícita,
convierte el panel de configuración en algo personalizable de verdad, y añade features.

## Decisiones tomadas

1. **Clasificación por contenido real, no por extensión.** Magic bytes mandan; la
   extensión y el `Content-Type` son solo pistas. De ahí se deriva qué análisis aplica.
2. **Veredictos SightEngine separados**: `nsfw` (pornografía/gore) ≠ `restringido`
   (alcohol/armas). Umbrales configurables por servidor. `nudity` lee `raw` **y**
   `partial`. Se ignoran `firearm_toy` y `firearm_gesture`. Se añade `gore-2.0`.
3. **`/settings` pasa a ser un panel interactivo** y la config por guild se modela como
   un esquema extensible, no como 5 booleanos sueltos.
4. **Features nuevas**: menú contextual "Analizar con Threat", `/history`, anti-phishing.
5. **Nunca "seguro" por omisión.** Si un elemento no se pudo comprobar, su veredicto es
   `error`. Nunca verde.
6. **Config, infracciones y cuota pasan a SQLite.** `data.json` queda como respaldo de
   migración.
7. **Aviso en tres interruptores.** `silent_mode` sigue siendo el master retrocompatible
   ("solo avisa si hay algo que mirar") y debajo van `avisar_limpios`,
   `avisar_sospechosos` y `avisar_errores`. Los defaults reproducen exactamente el
   comportamiento actual, así que ningún servidor existente cambia al actualizar.
8. **Una sola reacción por mensaje.** Un `ReactionController` por mensaje garantiza una
   única reacción de Threat en cualquier instante; la whitelist sale de la escalera de
   reacciones y pasa a ser una línea del embed. Los interruptores de aviso gobiernan
   **solo el embed**: la reacción es feedback visual instantáneo y no hace ruido en el
   canal.

## Defectos confirmados (con referencia)

| # | Defecto | Ubicación | Por qué importa |
|---|---------|-----------|-----------------|
| D1 | Adjuntos se parten en dos listas **exclusivas**: imagen→solo SightEngine, no-imagen→solo VT | `ui/message_handler.py:369-370` | Un `.png` con malware embebido no se escanea jamás |
| D2 | `es_imagen()` decide por extensión o `content_type`, nunca por contenido | `core/utils.py:99-104` | `malware.png` → `image/png` → clasificado imagen → sin VT. Y al revés: `foto.exe.png` es imagen → sin verificación MIME ni doble extensión, porque esas comprobaciones solo viven en `_procesar_archivo` (`ui/message_handler.py:336-340`) |
| D3 | URL que resuelve a imagen se salta VT por completo | `ui/message_handler.py:514` | Un phishing que devuelve un `.png` nunca se reporta como malicioso |
| D4 | `/scan tipo=file` nunca mira NSFW | `cogs/analisis.py:147-153` | Subir un PNG por comando no detecta nada de contenido |
| D5 | `nudity` lee solo `raw` (X-rated) con umbral 0.5; descarta `partial` (bikini, lencería, escote) | `api/sightengine.py:60-61` | Es exactamente el contenido que aparece en un servidor. El detector es casi inerte. Además `nudity` v1.0 está deprecated → `nudity-2.1` |
| D6 | `weapon` mete `firearm_toy` (juguetes, nerf, airsoft) en el `max()` | `api/sightengine.py:63-65` | Una foto de un juguete marca NSFW |
| D7 | `alcohol` comparte veredicto y borrado con `nudity` | `api/sightengine.py:72-77`, `ui/message_handler.py:789-792` | Una foto de una cerveza (prob 0.75) → "Contenido NSFW detectado" + infracción + borrado en modo estricto |
| D8 | Sin SightEngine devuelve `False, {}, False` y `models.get("error")` es falsy | `api/sightengine.py:35-45`, `ui/message_handler.py:295-299`, `:567-586` | Una imagen **no analizada se reporta y se cuenta como "segura"**. Es el peor fallo del sistema |
| D9 | `_flush_datos(include_runtime=False)` borra `__api_usage__` y `__antispam__`. Es el default de `update_stats`, `registrar_infraccion`, `agregar_dominio`, los 5 comandos de `configuracion.py` y `api/sightengine.py:84` | `core/database.py:238-254` | Contradice el arreglo F5 documentado en `bot.py:199-202`: cada análisis borra los contadores de cuota y el historial de antispam que el cron horario acaba de escribir |
| D10 | `infracciones_registradas` es una lista por usuario que nunca se purga | `core/guild_config.py:114-118` | Crece sin límite y `data.json` se reescribe entero en cada infracción |
| D11 | `update_stats` se llama también en cache-hit de NSFW, pero no en cache-hit de URL | `ui/message_handler.py:296` vs `api/virustotal.py:550-553` | Las estadísticas se inflan con imágenes repetidas; inconsistente |
| D12 | `ANALYSIS_SEMAPHORE` (20) envuelve la llamada completa a `analizar_url`, que hace `sleep(55)` entre sondeos | `ui/message_handler.py:729-731` | ~20 URLs nuevas simultáneas agotan el pool y bloquean todo ~2 min |
| D13 | `on_message` no filtra otros bots ni webhooks | `bot.py:212-223` | Los bots de otrosutantemporales disparan análisis y consumen cuota |
| D14 | `intents.members = True` (intent privilegiado) sin ningún uso | `bot.py:48` | Obliga a habilitarlo en el developer portal sin ningún beneficio |
| D15 | `ConfirmBanView.on_timeout` edita `self.message`, que nunca se asigna | `ui/views.py:163-172` | El timeout de 30 s no desactiva nada: el banner de ban sigue vivo para siempre |
| D16 | Las reacciones se añaden en 5 sitios y **solo se retira `EMOJI_LOADING`**. `EMOJI_WHITELIST` (`:472`) se pone *antes* de conocer el resultado y nunca se quita | `ui/message_handler.py:321, 472, 506, 789-800` | Un link en whitelist + un `.pdf.exe` + una imagen NSFW deja **3 reacciones** simultáneas. Y un mensaje con whitelist + link malicioso sale marcado con ambos emojis, que se lee contradictorio |
| D17 | `silent_mode` mezcla dos decisiones distintas: no avisar de lo limpio y no avisar de lo que falló. Además `omitidos` fuerza el embed pase lo que pase (`:783`) sin existir forma de desactivarlo | `ui/message_handler.py:783`, `core/guild_config.py:26` | Un servidor que solo quiere_castigo de amenazas tampoco puede silenciar los errores de quota, y uno que silencia los errores se ve obligado a ver cada imagen limpia |

## Tareas

### Fase 0 — Cimientos

1. **`core/filetypes.py` (nuevo).** Detección por magic bytes. `imghdr` no sirve: está
   deprecado desde 3.11 y se eliminó en 3.13 (PEP 594). Implementar a mano, sin
   dependencia nueva: las firmas son pocas y ya existe el precedente de
   `_EXT_EJECUTABLE` en `core/utils.py`.
   - Firmas: JPEG `FFD8FF`, PNG `89504E470D0A1A0A`, GIF `GIF87a/GIF89a`,
     WEBP `RIFF....WEBP`, BMP `BM`, ICO `00000100`, HEIC/AVIF `ftyp{heic,heix,mif1,avif}`,
     TIFF `II*\0/MM\0*`, SVG (texto `<svg`), PDF `%PDF`, ZIP/PK, RAR, 7z,
     OLE/DOC/XLS `D0CF11E0A1B11AE1`, ELF, Mach-O, PE `MZ`, Python/zip app.
   - `detectar(contenido: bytes) -> TipoContenido` con `TipoContenido` = `IMAGEN`,
     `EJECUTABLE`, `DOCUMENTO`, `ARCHIVO`, `DESCONOCIDO`. Cada tipo lleva su MIME
     esperado, para poder detectar el mismatch.
   - Leer solo los primeros 4 KB: no hace falta el archivo entero para clasificar.

2. **Motor de veredictos (`core/veredictos.py`, nuevo).** Fuente única de verdad.
   Hoy `"malicioso" / "sospechoso" / "seguro" / "nsfw" / "error"` está repetido en 5
   ficheros con literales sueltos. Definir el conjunto cerrado, su color, su icono y su
   acción por defecto; quitar los literales de `api/`, `ui/` y `cogs/`.

3. **Eliminar `ANALYSIS_SEMAPHORE` de `api/virustotal.py` y `cogs/analisis.py`.**
   Mantenerlo solo alrededor de las peticiones HTTP reales, nunca de un `sleep(55)`.
   Unificar con `bot._analysis_sem` (100) — hoy hay tres semáforos para lo mismo
   (`bot.py:13`, `bot.py:60`, `core/state.py:6`).

4. **Quitar `intents.members`** de `bot.py:48`.

### Fase 0b — Aviso y reacciones (arregla D16 y D17)

Esta fase va **antes** que la del panel, porque el panel solo tiene sentido si estas dos
funciones ya son puras y testeables. Ambas reciben un objeto `Señales` y devuelven una
decisión; ninguna toca Discord.

5. **`core/senales.py` (nuevo).** Un único contenedor de todo lo que se ha detectado en
   un mensaje. Reemplaza las 14 variables locales sueltas que hoy recorre
   `procesar_analisis` y `_construir_embed_unificado`. Campos: lista de resultados con su
   veredicto y su tipo, más banderas agregadas (`malicious`, `nsfw`, `restringido`,
   `phishing`, `suspicious`, `error`, `cooldown`, `doble_ext`, `mime_mismatch`,
   `whitelist_omitidos`, `omitidos`) y los detalles que hoy se pierden entre funciones
   (`datos_nsfw` con los scores crudos, que la nueva feature `/explicar` reutilizará).

6. **`core/aviso.py` (nuevo): `debe_enviar_embed(senales, config) -> bool`.** Reglas, en
   este orden:
   ```python
   if not config["silent_mode"]:                 # master apagado → siempre
       return True
   if señales.hay_amenaza():                    # malicioso/nsfw/restringido/phishing
       return True                               # (hoy las amenazas siempre avisan)
   if config["avisar_sospechosos"] and señales.suspicious:
       return True
   if config["avisar_errores"] and (señales.error or señales.cooldown or señales.omitidos):
       return True
   return config["avisar_limpios"]
   ```
   `omitidos` y `cooldown` cuentan como errores porque son literalmente "no se pudo
   comprobar todo". Antes `omitidos` se colaba en la condición (`:783`) sin existir forma
   de desactivarlo.

7. **`core/reacciones.py` (nuevo).**
   - `resolver_reaccion(senales) -> str`: función **pura**, una única tabla de prioridad
     (de peor a mejor):
     `malicioso` → `nsfw` → `restringido` → `phishing` → `cooldown` → `error` →
     `suspicious` → `doble_ext`/`mime_mismatch` → `seguro`.
     **La whitelist no está en la tabla**: se reporta en el embed.
   - `class ReactionController`: dueño del mensaje. Un `set(emoji)` quita antes el emoji
     de Threat que hubiera puesto (si es distinto) y pone el nuevo. Lleva además una
     ranura `transient` separada para `EMOJI_LOADING`, que es un indicador de progreso y
     no un veredicto: si entra un veredicto mientras el loading está puesto, lo retira;
     si el análisis continúa, se vuelve a poner. Garantía: **como mucho una reacción de
     veredicto y una de loading, y nunca dos de veredicto**.

8. **Sanear `procesar_analisis` (`ui/message_handler.py`).** Dejar de añadir reacciones
   durante el análisis y acumular señales:
   - `:321` — `_procesar_archivo` deja de poner `EMOJI_WARNING`; la doble extensión ya
     viaja en la tupla que devuelve.
   - `:472` — se deja de poner `EMOJI_WHITELIST`; se cuenta en `señales.whitelist_omitidos`.
     Esto además arregla el caso contradictorio de D16.
   - `:506` — se deja de poner `EMOJI_COOLDOWN`; se marca `señales.cooldown`.
   - `:556`, `:640`, `:674` — pasan por el `ReactionController` en su ranura transient.
   - `:783` — se sustituye la condición por `debe_enviar_embed(señales, config)`.
   - `:789-800` — la cadena de `if/elif` se sustituye por
     `await reacciones.set(resolver_reaccion(senales))`, respetando `config["reacciones"]`.

9. **Añadir la línea de whitelist al embed**, junto a la de omitidos que ya existe
   (`:171-172`): `N enlace(s) en whitelist`. Es el sitio natural: el embed es el detalle
   y la reacción es el resumen de una sola cosa.

10. **Defaults y migración retrocompatible.** Las guilds existentes no deben cambiar de
    comportamiento al arrancar la versión nueva. Al cargar una guild sin las claves
    nuevas, derivarlas de su `silent_mode` actual:
    `silent_mode=True` → `avisar_limpios=False`; `silent_mode=False` → `avisar_limpios=True`;
    `avisar_sospechosos=avisar_errores=reacciones=True`. A partir de ahí se guardan
    explícitas y la derivación ya no se repite. Documentar la equivalencia en el panel
    para que nadie la lea como un cambio de política.

### Fase 1 — Clasificación y política de escaneo

11. **Reescribir `_analizar_adjuntos` (`ui/message_handler.py:361-392`).** Orden:
   descargar una vez → `detectar()` → aplicar la política → construir la tupla.
   Eliminar la partición `imagenes`/`otros`.

   | Tipo real | Análisis | Señales extra |
   |-----------|----------|---------------|
   | `IMAGEN` | SightEngine (NSFW) + lookup de hash en VT (1 req, sin upload si el hash ya existe) | MIME declarado vs real; doble extensión |
   | `EJECUTABLE` / `DESCONOCIDO` | VT (lookup + upload) | MIME declarado vs real; doble extensión |
   | `DOCUMENTO` | VT (lookup + upload) | MIME declarado vs real; doble extensión |
   | `ARCHIVO` | VT (lookup + upload) | doble extensión |

   `es_imagen()` se conserva **solo como pista previa** para no descargar de más, pero
   nunca decide el veredicto. Si la extensión dice `.png` y los bytes dicen PE, gana PE.

12. **Extraer `_verificar_nombre` a una función pura** reutilizable por imagen y archivo:
   devuelve `(doble_extension: bool, aviso_mime: Optional[str])`. Hoy vive dentro de
   `_procesar_archivo` (`ui/message_handler.py:317-340`) y por eso las imágenes nunca la
   obtienen. Ampliar la comprobación MIME a todas las extensiones conocidas, no solo
   `.jpg`/`.png`.

13. **`_procesar_imagen` (`ui/message_handler.py:275-301`)**: pasar a devolver también el
   veredicto de VT del hash. El elemento pasa a tener **dos** dimensiones: contenido
   (NSFW/restringido) y reputación (malicioso/sospechoso/seguro). Actualizar
   `_construir_embed_unificado` para que muestre ambas.

14. **`url_es_imagen` (`core/utils.py:144-167`)**: una URL que resuelve a imagen se
   analiza con SightEngine **y** con el reporte de URL de VT. Eliminar el `return`
   temprano que hoy hace que se salte VT.

15. **`/scan` (`cogs/analisis.py`)**: añadir la opción `imagen` y hacer que `file` acepte
   cualquier adjunto, incluida una imagen, aplicando la misma política que el autoescaneo.
   Extraer la política a una función compartida para que `/scan` y el autoescaneo no
   puedan divergir.

16. **Filtro de emisores (`bot.py:212-223`)**: ignorar mensajes de otros bots y
    webhooks. Comprobar `message.webhook_id`.

17. **`update_stats` solo en cache-miss.** Mover la llamada en
    `ui/message_handler.py:296` y `:569` dentro del `if not from_cache`.

### Fase 2 — SightEngine

18. **Parseo corregido (`api/sightengine.py`).** Contra las respuestas reales
    documentadas:
    - `nudity-2.1` → usar `raw` **y** `partial` (no solo `raw`). Subir de `nudity` v1.0
      a `nudity-2.1` (v1.0 está deprecated).
    - `gore-2.0` → `prob`.
    - `weapon` → `classes`, **descartando `firearm_toy` y `firearm_gesture`**.
    - `alcohol` → `prob`.
    - `offensive` → usar `prob`, no `max(values())` (actualmente mete `prob` y las clases
      en la misma comparación).

19. **Umbrales configurables.** `NSFW_CONFIDENCE_THRESHOLD = 0.5` deja de ser una
    constante global y pasa a ser un valor por guild, con default sensato y validado.
    Los umbrales de `alcohol`/`offensive` (`0.7` hardcodeado) salen del código.

20. **Separar `nsfw` de `restringido`** (decisión 2):
    - `nsfw`: `nudity.raw`, `nudity.partial`, `gore.prob`, `offensive` sexual.
    - `restringido`: `alcohol.prob`, `weapon` (armas/cuchillos reales).
    - `restringido` **no borra por defecto**: avisa, registra y va al log. La acción es
      configurable por guild.
    - Colores: `nsfw` = `COLOR_NSFW` (rojo), `restringido` = `COLOR_SOSPECHOSO` (ámbar).

21. **Nunca "seguro" por omisión.** Reescribir `analizar_imagen_multimodelo` para que
    devuelva un resultado tipado: `Ok(is_nsfw, max_confidence, models)` o
    `Fallo(motivo)`. Ninguna ruta de fallo devuelve `is_nsfw=False`. Sin claves, sin
    cuota, HTTP != 200, excepción o tamaño excedido → `Fallo`, que el handler traduce a
    veredicto `error`, reacción de error y contador `errores`.

22. **Duplicidad de SightEngine.** `SE_OPS_PER_CALL` pasa a derivarse de la lista real de
    modelos activos por guild, no de la constante `4`. Si `gore-2.0` está activo, son 5.

### Fase 3 — Anti-phishing (feature, va antes del panel porque añade veredicto)

23. **`core/phishing.py` (nuevo).** Detección local, **sin coste de cuota**:
    - Lista de marcas de alto valor: Steam, Discord, Epic Games, Riot, Twitch, Mojang,
      Meta, Instagram, WhatsApp, Telegram, PayPal, Binance, Coinbase, Microsoft, Apple,
      Amazon, Netflix, Roblox, Epic.
    - Homoglifos: `0→o`, `1→l/i`, `3→e`, `5→s`, `7→t`, `rn→m`, `vv→w`, `cl→d`,
      normalización a NFKC y a ASCII.
    - Comparar el dominio (y cada subdominio) contra la marca por similitud de
      Levenshtein, además de los sufijos sospechosos (`-support`, `-verify`,
      `-login`, `-secure`, `.tk/.ml/.ga/.cf/.gq`, IP como host, punycode `xn--`).
    - Salida: veredicto `phishing` (ámbar). **Informativo: no borra y no infracciona por
      defecto.** Se comprueba **antes** de llamar a VT, así que además ahorra cuota.

### Fase 4 — Persistencia en SQLite

24. **Eliminar el parámetro `include_runtime`** de `guardar_datos`/`_flush_datos`
    (D9). `_flush_datos` escribe **siempre** todas las secciones. Es la causa raíz y no
    debe quedar como opción.

25. **Esquema nuevo** (`core/database.py`, reutilizando `DatabasePool` y siguiendo el
    patrón de `_asegurar_columna_datos`, que ya sabe migrar):
    ```sql
    guild_config (guild_id INTEGER PRIMARY KEY, data TEXT, updated_at REAL)
    infracciones  (guild_id INTEGER, user_id TEXT, elemento_id TEXT, created_at REAL,
                   PRIMARY KEY (guild_id, user_id, elemento_id))
    runtime       (key TEXT PRIMARY KEY, value TEXT)     -- cuota + antispam
    eventos       (guild_id INTEGER, channel_id INTEGER, message_id INTEGER,
                   user_id INTEGER, tipo TEXT, veredicto TEXT, created_at REAL)
    ```
    Índices en `infracciones(created_at)` (para purgar) y en
    `eventos(guild_id, channel_id, created_at)` (para `/history`).

26. **`core/guild_config.py` pasa a leer/escribir SQLite.** Desaparece
    `state.bot.guilds_data`. `obtener_config_guild` devuelve una copia y existe un
    `actualizar_config(guild_id, **campos)` que hace el `UPDATE` y el `guardar_datos`.
    `guild_config` deja de importar `state`.

27. **Migración de una pasada**: si existe `data.json` y la tabla `guild_config` está
    vacía, se importa y se deja `data.json.bak`. Si la migración falla, el bot arranca
    igual leyendo `data.json` (fallback explícito, con log).

28. **Purgar infracciones.** `infracciones_registradas` se resuelve en el `DELETE` de la
    tabla (D10). Añadir a `_limpiar_cron` un `DELETE FROM infracciones WHERE created_at < ?`
    (90 días por defecto, configurable).

29. **`ui/views.py:141-147`** pasa a consultar SQLite por `elemento_id`. El "Ignorar" del
    log pasa a ser un `DELETE` real, no una resta en una lista.

### Fase 5 — Panel /settings

30. **Esquema de config extensible** (`core/config_schema.py`, nuevo): diccionario
    declarativo de claves con tipo, default, validador, sección y etiqueta. Todos los
    valores se leen de ahí, así que añadir una opción es añadir una entrada, no tocar
    cinco sitios. Validar y **clampar** en la escritura, nunca lanzar.

    Secciones: `general` · `escaneo` · `aviso` · `contenido` · `moderacion` ·
    `exclusiones` · `cuota`.

    Claves de **aviso** (decisión 7): `silent_mode` (master), `avisar_limpios`,
    `avisar_sospechosos`, `avisar_errores`, `reacciones`.

    Resto de claves nuevas: `umbral_nudity`, `umbral_partial`, `umbral_gore`,
    `umbral_alcohol`, `umbral_weapon`, `umbral_offensive`, `modelos_se` (lista),
    `canales_exentos`, `roles_exentos`, `canales_sin_embed`, `canal_logs_peligro`,
    `canal_logs_uso`, `prefijo_log`, `antispam_por_hora`, `antispam_cooldown`,
    `accion_nsfw`, `accion_restringido`, `accion_phishing`, `accion_malicious`
    (`ignorar` | `borrar` | `timeout`), `max_adjuntos`, `max_urls`.

31. **Emojis de los veredictos nuevos — IDs ya decididos por el autor.** Los dos
    veredictos nuevos llevan emoji propio, aporteado por el autor:
    ```python
    EMOJI_RESTRINGIDO: str = "<:Flag:1555092175547801670>"
    EMOJI_PHISHING: str = "<:Phishing:1555091633865760808>"
    ```
    Se añaden a `core/config.py` junto al resto (`core/config.py:60-90`) y se exportan
    en `bot.py` con el mismo patrón que los demás, para que los cogs y `ui/` los
    alcancen como `self.bot.EMOJI_RESTRINGIDO`.

    Razonamiento de la elección:
    - `restringido` → **`<:Flag:1555092175547801670>`** (bandera con el signo rojo).
      "Prohibido" es el vocabulario que usa Discord para el contenido restringido por
      edad, que es exactamente lo que cubre este veredicto (alcohol, armas).
    - `phishing` → **`<:Phishing:1555091633865760808>`** (anzuelo). Lectura directa.

    Los IDs van fijos en el código, no por `.env`: ya son el valor real y no tiene
    sentido obligar a quien despliega a conocerlos. **Prohibido inventar IDs de emoji
    que no existan**; si alguno se elimina del servidor, el emoji se muestra como texto
    y no rompe el arranque.

32. **`ui/views.py`: `ConfigPanelView`** con `custom_id=f"threat:cfg:{guild_id}"` y
    `timeout=None`. Registrar con `bot.add_dynamic_item` al arrancar para que los
    botones sobrevivan a un reinicio (D15 sigue vigente para `ConfirmBanView`: hay que
    guardarle `view.message = msg` o quitarle el timeout).
    - Selects para umbrales y acciones; switches para booleanos; autocomplete para
      canales y roles.
    - La sección `aviso` muestra los 4 interruptores con su equivalencia respecto a
      `silent_mode`, para que nadie piense que ha cambiado la política del servidor.
    - Cada cambio persiste al instante y responde con `interaction.edit_original_response`
      para que solo quien abrió el panel lo vea (efímero, no spam en el canal).

33. **`/settings` pasa a abrir el panel.** Sus modos (`aviso`/`general`/`escaneo`/…)
    eligen la sección inicial. Los 7 comandos existentes (`/silentmode`, `/strictmode`,
    `/autoscan`, `/setlogchannel`, `/disablelogchannel`, `/whitelist`) **se conservan como
    atajos de un paso** y pasan a usar `actualizar_config`; no se rompen para nadie.
    `/silentmode` queda marcado como atajo del master y muestra los tres interruptores
    derivados en su confirmación, para que nadie los active a ciegas.

34. **`/settings` de solo lectura se sustituye** por la vista de resumen del panel.
    Actualizar `cogs/help.py` con los comandos nuevos y la sección de "Reacciones" que
    ahora incluye `phishing` y `restringido`.

### Fase 6 — Features

35. **Menú contextual.** `@app_commands.context_menu(name="Analizar con Threat")` en un
    `cogs/contextual.py`. Extrae URL del mensaje (o toma el adjunto), aplica la misma
    política, responde efímero. **Consume su propio antispam** (una clave distinta en
    `user_scan_history`), no el de `/scan`, para que un moderador no se bloquee a sí
    mismo alternando entre ambas vías.

36. **`/history`** (`cogs/historial.py`). Últimos N análisis de un canal, con filtro
    opcional por usuario, desde la tabla `eventos`. Moderadores (`manage_messages`),
    efímero, paginado. Es también el registro que hoy no existe de "qué se escaneó".

37. **Registrar eventos.** `procesar_analisis` inserta una fila en `eventos` por mensaje
    analizado (batch, no una por elemento).

38. **Actualizar `README.md`** y `cogs/about.py`: la tabla de capacidades ya no es
    cierta (menciona "IPs" y "Hashes" como análisis automático y no lo son) y hay que
    documentar los nuevos veredictos, el panel y las features.

### Fase 7 — Tests y CI

39. **`tests/test_clasificacion.py`**: magic bytes de cada formato; `malware.png` con
    cabecera PE → `EJECUTABLE`; `foto.exe.png` → señal de doble extensión **y** mismatch
    de MIME en la ruta de imagen; PDF → `DOCUMENTO`.

40. **`tests/test_sightengine.py`**: fixtures con respuestas reales documentadas de
    `nudity-2.1`, `gore-2.0`, `weapon`, `alcohol`, `offensive`. Casos: `partial` alto →
    `nsfw`; `firearm_toy` alto → **no** restringido; alcohol 0.75 → `restringido` y no
    `nsfw`; sin claves → `Fallo`; HTTP 500 → `Fallo`; respuesta sin el modelo pedido →
    `Fallo`.

41. **`tests/test_sin_cuota.py`**: sin SightEngine un elemento sale `error`, nunca
    `seguro`; no se incrementa `seguros`; con `avisar_errores` apagado no se manda
    embed; en modo estricto el mensaje **no** se borra.

42. **`tests/test_reacciones.py`**: matriz de combinaciones de señales → **exactamente
    una** reacción. Incluir los casos que hoy fallan: whitelist + doble extensión + NSFW,
    whitelist + malicioso (solo malicioso), y que `EMOJI_LOADING` no deja dos veredictos
    puestos. Comprobar además que la whitelist aparece en la descripción del embed.

43. **`tests/test_politica_aviso.py`**: matriz `silent_mode` × `avisar_limpios` ×
    `avisar_sospechosos` × `avisar_errores` × tipo de señal. Y una prueba de
    retrocompatibilidad: una config antigua con `silent_mode=True` y sin las claves
    nuevas produce el mismo resultado que antes.

44. **`tests/test_persistencia.py`**: `include_runtime` ya no existe (guarda estática que
    falla si vuelve a aparecer en el código); migración `data.json` → SQLite; roundtrip
    de config; purga de infracciones; el "Ignorar" del log borra la fila.

45. **`tests/test_phishing.py`**: positivos (`rnicrosoft.com`, `discorcl-giveaway.io`,
    `steamcommunnity.ru`, `paypa1-secure.tk`, IP como host) y negativos
    (`github.com`, `discord.com`, `notmicrosoft.com`, dominios con la marca como
    subdominio legítimo).

46. **`tests/test_veredictos.py` (extender)**: `restringido` y `phishing` no borran en
    modo estricto por defecto; `nsfw` sí; el título y el color de cada veredicto.

47. **`tests/test_config_schema.py`**: toda clave del esquema valida y clampa; un valor
    fuera de rango se corrige en vez de lanzar; una clave desconocida se ignora; los dos
    emojis nuevos tienen el formato `<:name:id>` válido y están exportados en `bot`.

48. **CI**: el workflow ya corre `compileall`, `ruff` y `pytest`. Añadir `pytest` con
    cobertura mínima en los ficheros nuevos y subir Python a 3.12 (para no arrastrar
    `imghdr`, aunque ya no se use) comprobando que el bot sigue arrancando en 3.10.

## Riesgos

- **Coste de cuota.** Una imagen pasa de 4 ops SE a **5 ops SE + 1 req VT**. Con el plan
  gratuito (500/día de cada uno) el techo baja de ~125 a **~100 imágenes/día**. Mitigación
  incorporada: el error explícito hace visible el corte en vez de mentir, el anti-phishing
  filtra gratis antes de gastar VT, y `modelos_se` por guild permite bajar el bundle a
  3 modelos (nudity, gore, offensive) si hace falta. `SE_OPS_PER_CALL` se recalcula.
- **Caché con formato viejo.** `nsfw:<hash>` guarda `models` con la forma anterior. La
  entrada antigua no se puede reparsear: usar clave nueva `nsfw2:<hash>` y leer la vieja
  solo como acierto por defecto. La caducidad de 30 días hace que se purguen solas.
- **Falsos positivos de anti-phishing.** Un dominio legítimo parecido se marca en ámbar.
  Mitigación: verificable desde el propio embed, nunca borra ni infracciona.
- **Falsos positivos de doble extensión.** Era la regla ya existente; ahora se aplica
  también a imágenes, así que el riesgo crece. Mantener `accion_malicious` por defecto en
  `ignorar` para señales de nombre/MIME y reservar `borrar` para VT confirmado.
- **Migración a SQLite.** Si algo falla, el bot debe arrancar. Requisito: que la ruta de
  lectura tenga fallback a `data.json` y que la migración sea idempotente.
- **Coste de la semaphore en el sondeo VT.** `analizar_url` puede gastar hasta 5 unidades
  y dormir 55 s. Con la tasa por usuario (`check_vt_user_limit`) y el vuelo, el pico está
  acotado; sacar el semáforo del sleep es lo que evita el bloqueo global.
- **Regresión de aviso al actualizar.** Si la derivación de `avisar_limpios` desde
  `silent_mode` se implementa mal, los servidores existentes empiezan a recibir (o a
  dejar de recibir) embeds. Por eso los interruptores se persisten explícitamente en la
  primera carga y hay una prueba de retrocompatibilidad (tarea 43).
- **Perder la señal de whitelist.** Al sacarla de las reacciones, un mensaje con enlaces
  en whitelist y nada más pasa a llevar el check verde. El dato no se pierde: va al
  embed (tarea 9). Hay que comprobar que el embed se manda en ese caso o la información
  desaparece del todo — de ahí que `whitelist_omitidos` se cuente como motivo de aviso
  cuando no hay nada más que informar.
- **Emojis.** Los dos IDs vienen dados por el autor y están subidos a su servidor
  (tarea 31). Si alguno se borrara del servidor, Discord lo muestra como texto plano y
  el bot sigue funcionando: no hay fallback que mantener ni que sincronizar.
- **`ReactionController` y concurrencia.** `on_message` y `on_message_edit` pueden
  procesar el mismo mensaje a la vez. El controlador debe vivir en el estado del mensaje
  (o keyed por `message.id`), no como variable local, o los dos textos compiten por
  quitar y poner emojis.

## Validación

```bash
python -m pytest tests -q          # suite completa, incluidas las nuevas
ruff check .                       # lint
python -m compileall .             # CI existente
DISCORD_TOKEN=x VT_API_KEY=x SIGHTENGINE_API_USER=x SIGHTENGINE_API_KEY=x \
  timeout 15s python bot.py        # arranque (patrón del workflow actual)
```

Manuales, con un guild de pruebas:
1. Subir `malware.png` (PE con extensión .png) → debe salir **malicioso**, no NSFW.
2. Subir una foto normal → `seguro` en contenido, `seguro` en reputación.
3. Sin claves de SightEngine → ningún elemento sale verde.
4. `/settings` → cambiar un umbral → recargar el panel → el valor persiste.
5. Reiniciar el bot → `/stats` conserva la cuota consumida (D9) y `/usercheck` conserva
   las infracciones (D10).
6. Click derecho en un mensaje → "Analizar con Threat" → responde efímero.
7. `/history` → lista los últimos análisis del canal.
8. **Reacciones**: mensaje con un link en whitelist + un `.pdf.exe` + una imagen NSFW →
   **una sola reacción** y el embed dice cuántos enlaces hubo en whitelist (D16).
9. **Aviso**: con `silent_mode` activo y `avisar_errores` apagado, un mensaje con un
   elemento no verificable no manda embed; con `avisar_errores` activado sí. Con
   `avisar_limpios` apagado tampoco manda embed, pero **la reacción verde sigue**
   (D17).
10. **Retrocompatibilidad**: arrancar con un `data.json` viejo → el comportamiento de
    aviso es idéntico al de antes de actualizar.

## Fuera de alcance

- Migrar la landing (Astro): solo se actualizan los textos del README y `/about`.
- Análisis de audio/vídeo de SightEngine: el bot solo sigue aceptando imágenes.
- Persistir el estado de las moderaciones masivas (no forman parte de este plan).
- Reimplementar `/eval`: sigue siendo un `exec` restringido a `OWNER_ID`.