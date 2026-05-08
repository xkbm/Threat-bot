# Threat-bot — Memory

## Proyecto
Bot de Discord para análisis de seguridad (URLs, IPs, hashes, archivos, imágenes NSFW).
Usa VirusTotal v3 y Sightengine.

## Stack
- Python 3.8+ (compatible hasta 3.13)
- discord.py >= 2.3.0
- aiohttp, aiosqlite, python-dotenv, psutil

## Estructura
```
bot.py                  → Entry point, intents, eventos on_message/on_message_edit
api/
  virustotal.py         → VT API (URL, hash, IP, file analysis)
  sightengine.py        → NSFW image detection
cogs/
  about.py              → /about
  analisis.py           → /scan (URL, IP, hash, file)
  configuracion.py      → /silentmode, /strictmode, /setlogchannel, /settings
  eval.py               → /eval (owner only)
  help.py               → /help
  reboot.py             → /reboot (owner only)
  rep.py                → /usercheck
  stats.py              → /stats
  whitelist.py          → /whitelist add/remove/list
core/
  config.py             → Constantes, emojis, API keys desde .env
  database.py           → SQLite + JSON persistence, debounced writes
  cache.py              → LRU cache in-memory (OrderedDict, 1000 entries)
  guild_config.py       → Per-guild config, stats, infracciones
  state.py              → Singleton bot reference
  utils.py              → URL resolution, SSRF check, dominio_en_whitelist, helpers
ui/
  message_handler.py    → Auto-scan pipeline on every message
  views.py              → Discord UI views (ban/kick/ignore buttons)
```

## Intents (privilegiados, activar en Discord Developer Portal)
- message_content
- members

## Permisos del bot
- Ver canales, Enviar mensajes, Enviar en hilos, Leer historial
- Insertar enlaces, Añadir reacciones, Usar emojis externos
- Gestionar mensajes, Expulsar miembros, Bloquear miembros
- Permission integer: 277025745990

## Config (`.env`)
```
DISCORD_TOKEN=
OWNER_ID=
VT_API_KEY=          (VT_API_KEY_2, VT_API_KEY_3 opcionales)
SIGHTENGINE_API_USER=  (SIGHTENGINE_API_USER_2/3, SIGHTENGINE_API_KEY_2/3 opcionales)
SIGHTENGINE_API_KEY=
```

## Cambios recientes (whitelist)
- Reemplazado `str.removeprefix()` por slicing (compatible Python 3.8+)
- Agregada validación de formato de dominio al añadir (`PATRON_DOMINIO` regex)
- Re-check de whitelist tras expandir URLs (ahorra llamadas VT)
- Unificado `DOMINIOS_PROTEGIDOS` en `core/config.py`
- Eliminados `__pycache__` y `.opencode/`

## Comandos
- `/whitelist add <dominio>` — requiere admin
- `/whitelist remove <dominio>` — no permite borrar protegidos
- `/whitelist list` — muestra whitelist del servidor
- Comandos admin adicionales: `/silentmode`, `/strictmode`, `/setlogchannel`, `/settings`
- Owner only: `/eval`, `/reboot`
