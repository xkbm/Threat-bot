# Threat-bot — AGENTS.md

## Stack
Python 3.10+ · discord.py ≥2.3.0 · aiohttp · aiosqlite · python-dotenv · psutil

## Start
```bash
pip install -r requirements.txt
python bot.py
```
Entrypoint `bot.py`. Requires `.env` with `DISCORD_TOKEN`, `OWNER_ID`, `VT_API_KEY`, `SIGHTENGINE_API_USER`, `SIGHTENGINE_API_KEY`.

## CI/CD
```
push dev → compileall + timeout 15s python bot.py (dummy .env)
         → if OK → git merge dev→main → Pterodactyl git pull + restart
```

## Architecture
- **Entrypoint**: `bot.py` — setup_hook loads all `cogs/*.py` as extensions, on_ready inits DB + syncs slash commands
- **State**: `core/state.py` holds `bot = None` singleton; `state.bot = bot` is set after `commands.Bot()` instantiation (bot.py:29). Import `from core import state` then `state.bot` anywhere.
- **Shutdown**: `bot.close` is monkey-patched (bot.py:188-192) to close `bot.session` + `bot.db` before closing.
- **Persistence**: SQLite (`analisis.db`) + JSON (`data.json`)
- **Cogs**: `/scan`, `/silentmode`, `/strictmode`, `/setlogchannel`, `/settings`, `/disablelogchannel`, `/whitelist`, `/usercheck`, `/stats`, `/about`, `/help`, `/eval` (owner), `/reboot` (owner)

## ⚠️ Gotchas

### Bound-method illusion
`bot.py:52-83` assigns module-level functions as attributes (`bot.analizar_url = analizar_url`). Python does NOT bind them. Calling `self.bot.func(arg)` passes `arg` as the function's first positional arg, NOT second.

```python
# expandir_url(bot, url) → needs 2 args
expanded = await self.bot.expandir_url(valor)          # ❌ TypeError (valor → bot param)
expanded = await expandir_url(self.bot, valor)          # ✅ import directly

# analizar_url(url, ...) → only needs url
tipo_res, embed, mal = await self.bot.analizar_url(...) # ✅ works (url is positional)
```
**Fix**: Import the function directly and pass `self.bot` explicitly when needed. E.g. `from core.utils import expandir_url`.

### Logger DEBUG
Only these loggers get `setLevel(logging.DEBUG)` in `bot.py:16-20`: `cache`, `db`, `handler`, `virustotal`, `sightengine`. Cog loggers (`analisis`, `configuracion`, etc.) inherit INFO from root — add them to `bot.py` if you need DEBUG.

### Timeouts
- **VirusTotal requests**: `VT_TIMEOUT = aiohttp.ClientTimeout(total=75)` in `api/virustotal.py:19` — always pass `timeout=VT_TIMEOUT` on new VT API calls
- **bot.session** (used for everything else): created in `on_ready` with `aiohttp.ClientTimeout(total=10)` — bot.py:122

### VT return type
All `analizar_url`, `analizar_hash`, `analizar_ip`, `analizar_archivo` return `(tipo: str, embed: discord.Embed, mal: int)` where `tipo` is `"malicioso"`, `"seguro"`, or `"error"`.

### Cache keys
- URLs: `f"url:{expanded_url}"` — always expand before cache lookup
- File hashes: `f"filehash:{sha256}"`

### VT GUI link
```python
url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
vt_link = f"https://www.virustotal.com/gui/url/{url_id}"
```

### API key rotation
Up to 3 VT keys and 3 SE key-pairs. Rotation is automatic via `obtener_siguiente_key()` / `obtener_siguiente_se_key()` with per-key usage tracking. Defined in `core/config.py:8-20`.

### Slash commands
All slash commands must `await interaction.response.defer()` (defer ephemeral=True for admin commands). Wrap followups in `try/except discord.errors.NotFound: pass`.
