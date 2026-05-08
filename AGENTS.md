# Threat-bot — AGENTS.md

## Proyecto
Bot de Discord para análisis de seguridad (URLs, IPs, hashes, archivos, imágenes NSFW).
Usa VirusTotal v3 y Sightengine.

## Stack
- Python 3.8+ (compatible hasta 3.14)
- discord.py >= 2.3.0
- aiohttp, aiosqlite, python-dotenv, psutil

## Estructura
```
bot.py                  → Entry point, on_ready, change_presence
api/
  virustotal.py         → VT API (URL, hash, IP, file)
  sightengine.py       → NSFW detection
cogs/
  about.py            → /about
  analisis.py        → /scan
  configuracion.py   → /silentmode, /strictmode, /setlogchannel, /settings
  eval.py             → /eval (owner only)
  help.py             → /help
  reboot.py           → /reboot (owner only)
  rep.py              → /usercheck
  stats.py            → /stats
  whitelist.py        → /whitelist
core/
  config.py           → Constantes, emojis, API keys
  database.py        → SQLite + JSON
  cache.py           → LRU cache
  guild_config.py    → Per-guild config
  utils.py           → URL resolution, SSRF check
ui/
  message_handler.py  → Auto-scan pipeline
  views.py          → UI buttons
```

## Comandos slash con defer()
**CRÍTICO**: Todo comando slash DEBE usar defer() al inicio para evitar timeout.

```python
@app_commands.command(name="help", description="...")
async def help_command(self, interaction: discord.Interaction):
    await interaction.response.defer()  # ← Importante!

    # ... procesamiento ...

    try:
        await interaction.edit_original_response(embed=embed)
    except discord.errors.NotFound:
        pass  # Ignorar si expiró
```

Errores comunes:
- **10062** (Unknown interaction): Interacción expiró → ignore con `pass`
- **10015** (Unknown webhook): Usa `defer()` + `edit_original_response()` desde el inicio

## Actividad del bot
```
Tipo: Watching
Mensaje: "Viendo enlaces - /help"
```

## Intents requeridos
En Discord Developer Portal:
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

## CI/CD (GitHub Actions)
Flujo automático:
```
push dev → test-bot.yml (sintaxis) → merge-to-main.yml (merge + restart Pterodactyl)
```

## Comandos
- **Admin**: /silentmode, /strictmode, /setlogchannel, /settings, /whitelist, /usercheck
- **Owner only**: /eval, /reboot

## Permisos bot
Permission integer: 277025745990