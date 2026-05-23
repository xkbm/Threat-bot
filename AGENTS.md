# Threat-bot

## Commit header
`bot.py` line 1 must be `# Commit: <hash>` — actualizarlo al commit actual antes de modificar el archivo.

## MCP first
Usar herramientas MCP (GitHub, Jina) antes que bash, websearch o webfetch.

## Stack
Python 3.10+ · discord.py ≥2.3.0 · aiohttp · aiosqlite · python-dotenv · psutil

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

## Architecture
- **Entrypoint** `bot.py:116` `setup_hook` loads `cogs/*.py`; `on_ready` inits DB + syncs slash commands.
- **State** `core/state.py` — `state.bot = bot` set at `bot.py:29`. Import `from core import state` then `state.bot` anywhere.
- **Shutdown** `bot.py:188-192` monkey-patches `bot.close` to close `bot.session` + `bot.db`.
- **Persistence**: SQLite `analisis.db` (cached scans) + JSON `data.json` (guild configs).
- **Bot session timeout** `aiohttp.ClientTimeout(total=60)` at `bot.py:122`. SightEngine uses its own `SE_TIMEOUT = 30` (`api/sightengine.py:12`), VT uses `VT_TIMEOUT = 180` (`api/virustotal.py:19`).
- **Size limits**: `MAX_FILE_SIZE = 32MB` for VT file uploads, `MAX_IMAGE_SIZE = 2MB` for SightEngine image scans (`core/config.py:22-23`).
- **Cogs**: `/scan` (30s cooldown per user+guild, `analisis.py:17`), `/silentmode`, `/strictmode`, `/setlogchannel`, `/settings`, `/disablelogchannel`, `/whitelist`, `/usercheck`, `/stats`, `/about`, `/help`, `/eval` (owner), `/reboot` (owner).

## Auto-analysis pipeline
`on_message` → `ui/message_handler.py:procesar_analisis(bot, message)`. Same flow for `on_message_edit`.
- **URLs** (non-image, not whitelisted): expand shorteners first → RAM cache → SQLite cache → VT API.
- **Image URLs** (single, non-whitelisted): SSRF-safe download via `descargar_url_segura()` (`core/utils.py:133`) — DNS resolve → private-IP check → download → SightEngine NSFW.
- **Attachments**: images → SightEngine, other files → VirusTotal. Batch cap: 5 per message.
- **Messages with both URLs + attachments**: URL branch does `return` early, skipping file analysis (`ui/message_handler.py:195,287`).

## Caching
- **RAM**: `OrderedDict` max 1000 entries, 1h TTL. `get_from_cache_mem(key)` → `(tipo, embed, mal)` or `(None, None, 0)`.
- **SQLite**: `analisis.db` table `analisis(clave, tipo, resultado, embed_json, timestamp, expira)`. Expiry: URL/IP 7d, hash/file/NSFW 30d.
- Cache keys: `f"url:{expanded_url}"`, `f"ip:{ip}"`, `f"hash:{hash}"`, `f"filehash:{sha256}"`, `f"nsfw:{sha256}"`.
- Always expand URLs before cache lookup (`expandir_url` in `core/utils.py:110`).

## VT integration (`api/virustotal.py`)
- `analizar_*` return `(tipo: str, embed: discord.Embed, mal: int)`. `tipo`: `"malicioso"`, `"seguro"`, `"error"`.
- 3 keys max, rotated via `obtener_siguiente_key()` (async, with lock). Rate: 4 req/min per key, 500/day. No rate-limit enforcement (only timestamp tracking).
- VT GUI link: `base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")` → `https://www.virustotal.com/gui/url/{url_id}`.

## SightEngine NSFW (`api/sightengine.py`)
- `analizar_imagen_multimodelo(hash, bytes)` → `(is_nsfw, max_confidence, models, from_cache)`.
- Models: `nudity`, `weapon`, `alcohol`, `offensive`. Thresholds: nudity/weapon ≥0.5, offensive ≥0.7.
- ~~**Bug**: `alcohol` is fetched and displayed but NOT included in `is_nsfw` (`api/sightengine.py:59-63`). A 95% alcohol image won't trigger any action.~~ ✅ FIXED
- Up to 3 key-pairs, rotated via `obtener_siguiente_se_key()` (async). Rate tracking increments +4 per call (stats quirk).
- Timeout: `SE_TIMEOUT = aiohttp.ClientTimeout(total=30)` at `api/sightengine.py:12` — passed explicitly on each request.

## Anti-spam
- 30 URLs/hour per user, 10s cooldown between scans. Tracks in `bot.user_scan_history` and `bot.antispam_scan`.
- ~~**Bug**: Image URL scans skip anti-spam (`ui/message_handler.py:57-109` — anti-spam at lines 161-173 is inside the non-image URL branch).~~ ✅ FIXED

## Whitelist
- `dominio_en_whitelist(dominio, whitelist)` checks exact match or subdomain (`core/utils.py:38`).
- Protected domains (`core/config.py:64-69`: youtube.com, github.com, etc.) cannot be removed via `/whitelist remove`.

## Guild config
Each guild: `bot.guilds_data[guild_id]` = `{silent_mode, strict_mode, log_channel_id, whitelist, stats, infracciones, infracciones_registradas}`.

## DB write debounce
`guardar_datos()` debounces 3s before flushing to `data.json`. Pass `inmediato=True` for instant writes (config changes). `cargar_datos()` (`core/database.py:154`) is async — uses `asyncio.to_thread()` for file I/O.

## Log embeds
`enviar_log_guild()` sends threat alerts with `LogActionView` (Ban/Kick/Ignore buttons) to the configured log channel. Buttons check user permissions before acting.

## ⚠️ Gotchas
- **Bound-method illusion** (`bot.py:52-83`): assigning module funcs as bot attrs does NOT bind `self`. `await self.bot.expandir_url(valor)` passes `valor` as bot param. Fix: import directly and pass `self.bot` explicitly.
- **Admin slash commands** use `_safe_followup()` wrapper (`cogs/configuracion.py:12-16`) that catches `discord.errors.NotFound` on expired interactions.
- **`strict_mode`** uses bare `try/except Exception: pass` for message deletion — will silently fail on missing permissions.
- **SSRF protection**: `descargar_url_segura()` (`core/utils.py:133`) resolves DNS → checks for private/loopback IPs → downloads via IP (with `Host` header) — blocks SSRF against internal networks.
- **MIME mismatch**: file analysis warns when `.jpg` has non-`image/jpeg` content-type or `.png` has non-`image/png` (`ui/message_handler.py:378-381`).
- **Logger DEBUG** only on: `cache`, `db`, `handler`, `virustotal`, `sightengine`. Cog loggers inherit INFO from root.
