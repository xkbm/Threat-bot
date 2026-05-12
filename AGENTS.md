# Threat-bot — AGENTS.md

## Stack
Python 3.10+ · discord.py ≥2.3.0 · aiohttp · aiosqlite · python-dotenv · psutil

## Arranque
```bash
pip install -r requirements.txt
python bot.py
```
El entrypoint es `bot.py`. Arranque requiere `.env` con `DISCORD_TOKEN`, `OWNER_ID`, `VT_API_KEY`, `SIGHTENGINE_API_USER`, `SIGHTENGINE_API_KEY`.

## Estructura
```
bot.py                  → entrypoint, eventos Discord (on_ready, on_message, on_message_edit)
api/
  virustotal.py         → analizar_url/hash/ip/archivo, key rotation, logs
  sightengine.py        → NSFW detection (nudity, weapon, alcohol, offensive)
cogs/
  analisis.py          → /scan (url, ip, hash, file) — manual
  configuracion.py     → /silentmode, /strictmode, /setlogchannel, /settings, /disablelogchannel
  whitelist.py         → /whitelist add/remove/list
  rep.py               → /usercheck
  stats.py             → /stats (uso API, proporción amenazas)
  about.py             → /about
  help.py              → /help
  eval.py              → /eval (prefix + slash, owner only)
  reboot.py            → /reboot (owner only, confirm buttons)
core/
  config.py            → emojis, constantes, keys
  database.py          → SQLite (analisis.db) + JSON (data.json)
  cache.py             → LRU OrderedDict, 1h TTL, max 1000
  guild_config.py      → config por servidor (silent, strict, whitelist, stats, infracciones)
  utils.py             → expandir_url, descargar_url_segura, es_hash_valido, tiene_doble_extension
  state.py             → singleton `bot = None` para acceso cross-module
ui/
  message_handler.py   → auto-scan pipeline para on_message / on_message_edit
  views.py             → LogActionView (ban/kick/ignore desde logs) + ConfirmBanView
```

## ⚠️ Trampas comunes para agentes

### Funciones asignadas como atributos NO son bound methods
En `bot.py` se asignan funciones como atributos de instancia (`bot.analizar_url = analizar_url`). Python NO las bindea automáticamente. Llamar `self.bot.func(arg)` pasa `arg` como primer parámetro de la función, NO como segundo.

```python
# expandir_url(bot, url) → necesita 2 args
expanded = await self.bot.expandir_url(valor)          # ❌ TypeError
expanded = await expandir_url(self.bot, valor)          # ✅ import directo con 2 args

# analizar_url(url, ...) → solo 1 positional arg necesario
tipo_res, embed, mal = await self.bot.analizar_url(...) # ✅ funciona (1 arg → url)
```

**Solución**: Importar la función directamente desde su módulo y pasar `self.bot` explícitamente cuando la función lo requiera. Ej: `from core.utils import expandir_url`.

### Logger DEBUG no activo por defecto
Solo estos loggers tienen `setLevel(logging.DEBUG)` en `bot.py`:
- `cache`, `db`, `handler`, `virustotal`, `sightengine`

Los loggers de `cogs/` (`analisis`, `configuracion`, `eval`, `help`, `reboot`, `rep`, `stats`, `whitelist`, `about`) y `guild_config` usan level herado del root (INFO). Para ver sus DEBUGs hay que agregarlos en `bot.py`.

### `defer()` obligatorio + NotFound
- Todo comando slash DEBE llamar `await interaction.response.defer()` (o `defer(ephemeral=True)`) al inicio.
- Comandos admin efímeros: `defer(ephemeral=True)` + `followup.send(...)`.
- Comandos públicos: `defer()` + `edit_original_response(...)`.
- Envolver `edit_original_response` / `followup.send` en `try/except discord.errors.NotFound: pass`.

### Claves de caché
- **URLs**: Se guardan con la URL expandida: `f"url:{expanded_url}"`. La búsqueda en caché también debe usar la expandida.
- **Archivos**: Se guardan con SHA-256: `f"filehash:{sha256}"`.

### CI/CD
```
push dev → test-bot.yml (compileall + 15s boot test with dummy .env)
         → si OK → merge-to-main.yml (git merge dev→main + Pterodactyl deploy + restart)
```

### Permission integer del bot
`277025745990`

## Convenciones del proyecto
- Comandos admin: decorator `@app_commands.default_permissions(administrator=True)`
- `Guardar_datos(inmediato=True)` para cambios en config que deben persistir ya.
- Owner check: `str(interaction.user.id) != OWNER_ID` (OWNER_ID es string de .env).
- Logging: `log = logging.getLogger("nombre")`; formateo `f"PREFIX → ... t={time.time()-_t0:.1f}s"`.
- Cooldown `/scan`: `@app_commands.checks.cooldown(1, 30.0, key=lambda i: (i.guild_id, i.user.id))`.
