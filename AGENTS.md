# Threat-bot

## MCP first
Siempre que exista una herramienta MCP disponible para una tarea (GitHub, Jina, etc.), debe usarse en lugar de bash, websearch, webfetch o cualquier otra alternativa.

## Stack
Python 3.10+ · discord.py ≥2.3.0 · aiohttp · aiosqlite · python-dotenv · psutil

## Start
```
pip install -r requirements.txt
python bot.py
```
Requires `.env` with `DISCORD_TOKEN`, `OWNER_ID`, `VT_API_KEY`, `SIGHTENGINE_API_USER`, `SIGHTENGINE_API_KEY`.
Optional multi-key: `VT_API_KEY_2/3`, `SIGHTENGINE_API_USER_2/3` + `SIGHTENGINE_API_KEY_2/3`.

## MCP servers (`opencode.jsonc`)
- **GitHub** (`@modelcontextprotocol/server-github` via npx) — local, for PRs/commits/issues. Token from env `GITHUB_PAT`.
- **Jina AI** (`https://mcp.jina.ai/v1`) — remote, no install needed. Provides `search_web`, `read_url`, `capture_screenshot_url`, `extract_pdf`, `search_images`. Free tier, 7k weekly calls. Use instead of basic webfetch for better web content retrieval.

## Git
- All git operations (commits, merges, PRs, branch management) must use the **MCP GitHub tool** (`github_*` functions), not bash.
- Bash git is only allowed for `push`, `fetch`, `pull`, `status`, `diff`, `log`, and `add` when preparing or syncing changes locally.

## CI/CD
`push dev` → compileall + `timeout 15s python bot.py` (dummy .env) → if OK → git merge dev→main → Pterodactyl git pull + restart

## Architecture
- **Entrypoint** `bot.py`: `setup_hook` loads `cogs/*.py`, `on_ready` inits DB + syncs slash commands
- **State** `core/state.py`: `state.bot = bot` singleton set at `bot.py:29`. Import `from core import state` then `state.bot` anywhere.
- **Shutdown** `bot.py:188-192`: `bot.close` monkey-patched to close `bot.session` + `bot.db` before exit
- **Persistence** SQLite (`analisis.db`) for cached scans + JSON (`data.json`) for guild configs
- **Cogs** `/scan`, `/silentmode`, `/strictmode`, `/setlogchannel`, `/settings`, `/disablelogchannel`, `/whitelist`, `/usercheck`, `/stats`, `/about`, `/help`, `/eval` (owner), `/reboot` (owner)
- **Skills** `.agents/skills/` holds project skills (discord-py, sqlite-ops, async-python-patterns, python-cybersecurity-tool-development, find-skills)
- **MCP config** `opencode.jsonc` is gitignored (contains GITHUB_PAT)

## Auto-analysis pipeline
`on_message` → `ui/message_handler.py:procesar_analisis(bot, message)`. Scans all URLs (expand acortadores first), images (SightEngine NSFW), and file attachments (VirusTotal). Checks RAM cache → SQLite cache → API. Same flow for `on_message_edit`.

## Caching
- **RAM**: `OrderedDict` max 1000 entries, 1h TTL. `get_from_cache_mem(key)` → `(tipo, embed, mal)` or `(None, None, 0)`.
- **SQLite**: `analisis.db` table `analisis(clave, tipo, resultado, embed_json, timestamp, expira)`. Expiry per scan type: URL/IP 7d, hash/file/NSFW 30d.
- Cache keys: `f"url:{expanded_url}"`, `f"ip:{ip}"`, `f"hash:{hash}"`, `f"filehash:{sha256}"`, `f"nsfw:{sha256}"`.
- Always expand URLs before cache lookup (`expandir_url` in `core/utils.py:107`).

## VT integration (`api/virustotal.py`)
- All `analizar_*` return `(tipo: str, embed: discord.Embed, mal: int)`. `tipo` is `"malicioso"`, `"seguro"`, or `"error"`.
- `VT_TIMEOUT = aiohttp.ClientTimeout(total=75)` — always pass on new VT calls.
- 3 keys max, rotated via `obtener_siguiente_key()` (async, with lock). Rate: 4 req/min per key, 500/day.
- VT GUI link: `base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")`, then `https://www.virustotal.com/gui/url/{url_id}`.

## SightEngine NSFW (`api/sightengine.py`)
- `analizar_imagen_multimodelo(hash, bytes)` → `(is_nsfw, max_confidence, models, from_cache)`.
- Models: `nudity`, `weapon`, `alcohol`, `offensive`. Thresholds: nudity/weapon ≥0.5, offensive/alcohol ≥0.7.
- Up to 3 key-pairs, rotated via `obtener_siguiente_se_key()` (async, with lock). Rate: 4 ops/min per key, 500/day.

## Anti-spam
- 30 URLs/hour per user, 10s cooldown between scans. Tracked in `bot.user_scan_history` and `bot.antispam_scan`.

## Whitelist
- `dominio_en_whitelist(dominio, whitelist)` checks exact match or subdomain. Protected domains (`core/config.py:64-69`: youtube.com, github.com, etc.) cannot be removed via `/whitelist remove`.

## Guild config
Each guild: `bot.guilds_data[guild_id] = {silent_mode, strict_mode, log_channel_id, whitelist, stats, infracciones, infracciones_registradas}`. No `on_guild_remove` handler — guild data persists in memory forever.

## DB write debounce
`guardar_datos()` debounces 3s before flushing to `data.json`. Pass `inmediato=True` for instant writes (used in config changes).

## Log embeds
`enviar_log_guild()` sends threat alerts with `LogActionView` (Ban/Kick/Ignore buttons) to the configured log channel. Buttons check user permissions before acting.

## ⚠️ Gotchas
- **Bound-method illusion** (`bot.py:52-83`): assigning module funcs as bot attrs does NOT bind them. `await self.bot.expandir_url(valor)` passes `valor` as bot param. Fix: import directly (`from core.utils import expandir_url`) and pass `self.bot` explicitly.
- **Logger DEBUG** only on these loggers: `cache`, `db`, `handler`, `virustotal`, `sightengine`. Cog loggers inherit INFO from root.
- **Slash commands**: always `await interaction.response.defer()` (ephemeral for admin). Wrap followups in `try/except discord.errors.NotFound: pass`.
