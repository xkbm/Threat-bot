# Threat-bot

## Commit header
`bot.py` line 1 must be `# Commit: <hash>` — actualizarlo al commit actual antes de modificar el archivo.

## MCP first
Usar herramientas MCP (GitHub, Jina) antes que bash, websearch o webfetch.

## Stack
Python 3.10+ · discord.py ≥2.3.0 · aiohttp · aiosqlite · python-dotenv

## Start
```
pip install -r requirements.txt
python bot.py
```
Requires `.env` with `DISCORD_TOKEN`, `OWNER_ID`, `VT_API_KEY`, `SIGHTENGINE_API_USER`, `SIGHTENGINE_API_KEY`.
Optional multi-key: `VT_API_KEY_2/3`, `SIGHTENGINE_API_USER_2/3` + `SIGHTENGINE_API_KEY_2/3`.

## MCP servers (`opencode.jsonc`, gitignored)
- **GitHub** (`@modelcontextprotocol/server-github` via npx) — PRs/commits/issues. Token from env `GITHUB_PAT`.
- **Jina AI** (`https://mcp.jina.ai/v1`) — `search_web`, `read_url`, `capture_screenshot_url`, `extract_pdf`, `search_images`. Free tier, 7k weekly calls.

## Git
- Use MCP GitHub tools for commits, merges, PRs, branches.
- Bash git only for `push`, `fetch`, `pull`, `status`, `diff`, `log`, `add`.

## CI/CD
`push dev` → GitHub Actions (`test-bot.yml`): `python -m compileall .` + `timeout 15s python bot.py` (dummy env) → if OK → `merge-to-main.yml`: merge dev→main → Pterodactyl git pull + restart.

## Verificación local (no instalar nada)
El bot corre en un servidor Pterodactyl. Para verificar cambios localmente solo ejecutar `python -m compileall .` — si compila sin errores, está correcto. No instalar requirements ni ejecutar `bot.py` en local.

## Architecture
- **Entrypoint** `bot.py:116` `setup_hook` loads `cogs/*.py`; `on_ready` inits DB + syncs slash commands. `bot._ready_done` guard prevents double init.
- **Concurrency guard**: `core/state.py:ANALYSIS_SEMAPHORE = asyncio.Semaphore(20)` limits concurrent analyses.
- **State** `core/state.py` — `state.bot = bot` set at `bot.py:29`. Import `from core import state` then `state.bot` anywhere.
- **Shutdown** `bot.py:207-211` monkey-patches `bot.close` → calls `shutdown()` (cancel tasks, flush data, stop DB pool, close session) then original close.
- **Guild cleanup** `bot.py:187-193` — `on_guild_remove` handler removes guild from `bot.guilds_data` and flushes to disk immediately.
- **Background tasks**: `_rotar_estado()` rotates bot presence every 30s; `_limpiar_cron()` clears expired SQLite cache every hour.
- **Persistence**: `core/analisis.db` (SQLite, cached scans) + `core/data.json` (JSON, guild configs). Both resolved as absolute paths from `core/config.py`. `guardar_datos()` debounces 3s; pass `inmediato=True` for instant writes. DB uses `DatabasePool` (4 connections, WAL mode, async read-round-robin + write-lock) via `core/database.py:POOL`.
- **`load_dotenv()`** called in both `bot.py:23` and `core/config.py:5` — harmless (no override) but relevant for env load order.
- **Error results (not cached)**: `_finalizar_error` (`api/virustotal.py:460`) solo llama `update_stats` — errors nunca se cachean para no bloquear reanálisis.
- **Timeouts**: bot session `total=60` (`bot.py:125`), VT `total=180` (`api/virustotal.py:20`), SE `total=30` (`api/sightengine.py:12`).
- **Size limits**: `MAX_FILE_SIZE = 32MB` for VT file uploads, `MAX_IMAGE_SIZE = 2MB` for SightEngine image scans (`core/config.py:26-27`).
- **Cogs**: `/scan` (30s cooldown per user+guild, `cogs/analisis.py:18`), `/silentmode`, `/strictmode`, `/setlogchannel`, `/settings`, `/disablelogchannel`, `/whitelist`, `/usercheck` (`cogs/rep.py`), `/stats`, `/about`, `/uptime`, `/ping`, `/help`, `/eval` (owner), `/reboot` (owner).

## Auto-analysis pipeline
`on_message` / `on_message_edit` → `ui/message_handler.py:232` `procesar_analisis(bot, message)`.
- **URLs** (non-image, not whitelisted): expand shorteners first → RAM cache → SQLite cache → VT API.
- **Image URLs** (single, non-whitelisted, detected by `url_es_imagen` path extension check): SSRF-safe download via `descargar_url_segura()` (`core/utils.py:150`) — DNS resolve → private-IP check → download → SightEngine NSFW.
- **Attachments**: images → SightEngine (`es_imagen()` checks extension + content-type), other files → VirusTotal. Batch cap: 5 per message. Attachment processing (`_procesar_adjuntos`) runs alongside URL analysis (called from all URL return points).
- **Double extension**: `tiene_doble_extension()` (`core/utils.py:180`) warns on e.g. `file.jpg.vbs`.
- **MIME mismatch**: warns when `.jpg` has non-`image/jpeg` content-type or `.png` non-`image/png`.

## Caching
- **RAM**: `OrderedDict` max 100000 entries, 1h TTL. Returns `(tipo, embed, mal)` or `(None, None, 0)`.
- **SQLite**: `analisis.db` table `analisis(clave, tipo, resultado, embed_json, timestamp, expira)`. Expiry: URL/IP 7d, hash/file/NSFW 30d.
- **DNS cache**: `core/utils.py:14` — `_dns_cache` dict, 300s TTL. Avoids redundant lookups during SSRF checks.
- Cache keys: `f"url:{expanded_url}"`, `f"ip:{ip}"`, `f"hash:{hash}"`, `f"filehash:{sha256}"`, `f"nsfw:{sha256}"`.
- Always expand URLs before cache lookup (`expandir_url` in `core/utils.py:126`).

## VT integration (`api/virustotal.py`)
- `analizar_*` return `(tipo: str, embed: discord.Embed, mal: int)`. `tipo`: `"malicioso"`, `"seguro"`, `"error"`.
- Up to 3 keys, rotated via `obtener_siguiente_key()` (async, with lock). Skips keys with ≥4 req in last 60s; returns `None` if all exhausted.
- 500 req/day per key. `obtener_siguiente_key()` also tracks daily usage.
- VT GUI link: `base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")` → `https://www.virustotal.com/gui/url/{url_id}`.

## SightEngine NSFW (`api/sightengine.py`)
- `analizar_imagen_multimodelo(hash, bytes)` → `(is_nsfw, max_confidence, models, from_cache)`.
- Models: `nudity`, `weapon`, `alcohol`, `offensive`. Thresholds: nudity/weapon ≥0.5, alcohol/offensive ≥0.7.
- Up to 3 key-pairs, rotated via `obtener_siguiente_se_key()` (async). Skips keys with ≥4 req in last 60s; returns `None` if all exhausted. Rate tracking increments +4 per call (stats quirk).
- Empty `image_bytes` returns `(False, 0.0, {}, False)` early without calling API.

## Anti-spam
- 30 URLs/hour per user, 10s cooldown between scans. Tracks in `bot.user_scan_history` and `bot.antispam_scan`. Applied to all scan paths including image URLs.

## Whitelist
- `dominio_en_whitelist(dominio, whitelist)` checks exact match or subdomain (`core/utils.py:43`).
- Protected domains (`core/config.py:68-73`: youtube.com, github.com, etc.) cannot be removed via `/whitelist remove`. New guilds inherit these as default whitelist.
- `/whitelist list` uses `WhitelistPaginatorView` (`ui/views.py:114`) with Anterior/Siguiente buttons when >20 domains.

## Guild config
`bot.guilds_data[guild_id]` = `{silent_mode, strict_mode, log_channel_id, whitelist, stats, infracciones, infracciones_registradas}`.
Global stats stored at `bot.guilds_data["__global__"]`. API usage and antispam state persisted under `__api_usage__` / `__antispam__` keys.

## Log embeds
`enviar_log_guild()` sends threat alerts with `LogActionView` (Ban/Kick/Ignore buttons) to the configured log channel. Buttons check user permissions before acting.

## ⚠️ Gotchas
- **Bound-method illusion** (`bot.py:52-82`): assigning module funcs as bot attrs does NOT bind `self`. `await self.bot.expandir_url(valor)` passes `valor` as bot param. Fix: import directly and pass `self.bot` explicitly.
- **Admin slash commands** use `_safe_followup()` wrapper (`cogs/configuracion.py:13-17`) that catches `discord.errors.NotFound` on expired interactions.
- **`strict_mode`** uses bare `try/except Exception: pass` for message deletion — will silently fail on missing permissions.
- **SSRF protection**: `descargar_url_segura()` resolves DNS → checks for private/loopback IPs → downloads via IP with `Host` header.
- **Logger DEBUG** only on: `cache`, `db`, `handler`, `virustotal`, `sightengine`. Cog loggers inherit INFO from root.
- **`/scan` file downloads** from attachment URL inside cog (not via `descargar_url_segura`).
- **`psutil` in requirements.txt** is unused (never imported) — dependency solely from a template or prior version.
