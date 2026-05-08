# Threat-bot — AGENTS.md

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
  sightengine.py       → NSFW image detection
cogs/
  about.py            → /about
  analisis.py        → /scan
  configuracion.py   → /silentmode, /strictmode, /setlogchannel, /settings
  eval.py             → /eval (owner only)
  help.py             → /help
  reboot.py           → /reboot (owner only)
  rep.py              → /usercheck
  stats.py            → /stats
  whitelist.py        → /whitelist add/remove/list
core/
  config.py           → Constantes, emojis, API keys desde .env
  database.py        → SQLite + JSON persistence
  cache.py           → LRU cache in-memory
  guild_config.py    → Per-guild config, stats, infracciones
  utils.py           → URL resolution, SSRF check, helpers
ui/
  message_handler.py  → Auto-scan pipeline
  views.py          → Discord UI views
```

## ERROR 10062: Unknown interaction
**CRÍTICO**: Error común cuando comandos slash responden a interacciones expiradas o ya respondidas.

**Patrón de corrección** (usar en todos los cogs):
```python
try:
    await interaction.response.send_message(embed=embed)
except discord.errors.NotFound:
    try:
        await interaction.followup.send(embed=embed)
    except Exception as e:
        print(f"Error al responder: {e}")
```

**Alternativa correcta**: Usar `defer()` + `followup.send()` (ya implementado en configuracion.py, stats.py, eval.py).

## Intents requeridos
- message_content
- members

## Config (.env)
```
DISCORD_TOKEN=
OWNER_ID=
VT_API_KEY=          (VT_API_KEY_2, VT_API_KEY_3 opcionales)
SIGHTENGINE_API_USER=
SIGHTENGINE_API_KEY=
```

## Permisos bot
Permission integer: 277025745990

## Comandos admin
- /silentmode, /strictmode, /setlogchannel, /settings, /whitelist, /usercheck

## Owner only
- /eval, /reboot