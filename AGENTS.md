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
- **GitHub** (local binary `.mcp/github/github-mcp-server.exe`) — PRs/commits/issues. Token via env var `GITHUB_PERSONAL_ACCESS_TOKEN`.
  *Nota: `@modelcontextprotocol/server-github` (NPM, archivado) bug #727 — no accede a repos privados. Remote Copilot MCP endpoint requiere fine-grained PAT + suscripción Copilot.*
- **Jina AI** (`https://mcp.jina.ai/v1`) — `search_web`, `read_url`, `capture_screenshot_url`, `extract_pdf`, `search_images`. Free tier, 7k weekly calls.

## Git
- Use MCP GitHub tools for commits, merges, PRs, branches.
- Bash git only for `push`, `fetch`, `pull`, `status`, `diff`, `log`, `add`.

## CI/CD
`push dev` → GitHub Actions (`test-bot.yml`): `python -m compileall .` + `timeout 15s python bot.py` (dummy env) → if OK → `merge-to-main.yml`: merge dev→main → Pterodactyl git pull + restart.

## Verificación local (no instalar nada)
El bot corre en un servidor Pterodactyl. Para verificar cambios localmente solo ejecutar `python -m compileall .` — si compila sin errores, está correcto. No instalar requirements ni ejecutar `bot.py` en local.

## Architecture
- **Entrypoint** `bot.py:119` `setup_hook` → loads `cogs/*.py`; `on_ready` inits DB + slash sync. `bot._ready_done` guard.
- **Concurrency**: `core/state.py:ANALYSIS_SEMAPHORE = Semaphore(20)` (API calls), `bot._analysis_sem = Semaphore(100)` (in-flight tasks), `bot._download_sem = Semaphore(5)` (attachment downloads).
- **State shortcut**: `core/state.py` — `state.bot = bot` at `bot.py:31`. Import `from core import state` then `state.bot` anywhere.
- **Lifecycle**: `bot.close` monkey-patched (`bot.py:217-221`) → cancel tasks → flush data → stop DB pool → close session → original close. `on_guild_remove` (`bot.py:197-203`) removes guild from `guilds_data` + instant flush. Background: `_rotar_estado()` every 30s, `_limpiar_cron()` hourly SQLite cleanup.
- **Persistence**: SQLite (`analisis.db`, 4-conn WAL pool via `DatabasePool`) for cached scans; JSON (`data.json`) for guild configs. `guardar_datos()` debounces 3s; pass `inmediato=True` for instant writes.
- **Config details**: `load_dotenv()` in both `bot.py:25` + `core/config.py:5` (innocuo). Timeouts: bot=60s, VT=180s, SE=30s. Size limits: 32MB (VT upload), 2MB (SE image). Errors never cached (`_finalizar_error` solo `update_stats`).

## Auto-analysis pipeline
`on_message` / `on_message_edit` → `ui/message_handler.py:232` `procesar_analisis(bot, message)`.
- **URLs** (non-image, not whitelisted): expand → RAM cache → SQLite cache → VT API.
- **Image URLs** (single, non-whitelisted): SSRF-safe download (`descargar_url_segura`) → SightEngine NSFW.
- **Attachments**: images → SightEngine, others → VT. Batch cap: 5. Runs alongside URL analysis.
- **File heuristics**: `tiene_doble_extension` warns on `file.jpg.vbs`; MIME mismatch warns on `.jpg` with non-`image/jpeg` content-type.

## Caching
- **RAM**: `OrderedDict` max 100000 entries, 1h TTL. Returns `(tipo, embed, mal)` or `(None, None, 0)`.
- **SQLite**: `analisis.db` table `analisis(clave, tipo, resultado, embed_json, timestamp, expira)`. Expiry: URL/IP 7d, hash/file/NSFW 30d.
- **DNS cache**: `core/utils.py:14` — `OrderedDict`, 300s TTL, max 5000 entries with LRU eviction. Avoids redundant lookups during SSRF checks.
- Cache keys: `f"url:{expanded_url}"`, `f"ip:{ip}"`, `f"hash:{hash}"`, `f"filehash:{sha256}"`, `f"nsfw:{sha256}"`.
- Always expand URLs before cache lookup (`expandir_url` in `core/utils.py:126`).

## VT integration (`api/virustotal.py`)
- `analizar_*` return `(tipo: str, embed: discord.Embed, mal: int)`. `tipo`: `"malicioso"`, `"seguro"`, `"error"`.
- Up to 3 keys, rotated via `obtener_siguiente_key()` (async, with lock). Skips keys with ≥4 req in last 60s; returns `None` if all exhausted.
- 500 req/day per key. `obtener_siguiente_key()` also tracks daily usage.

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

## Landing page (`landing/`)
Astro v6.3.8 + Tailwind v4 (`@tailwindcss/vite`). Deployed on Vercel.
- **Commands**: `cd landing && pnpm run dev` / `pnpm run build`
- **Manager**: pnpm only
- **URL**: `https://threat-bot-discord.vercel.app/`
- **Pages**: `index.astro` (single-page), `privacidad.astro`, `terminos.astro`
- **Discord invite**: `https://discord.com/oauth2/authorize?client_id=1038186932456390726&permissions=277025745990&scope=bot+applications.commands&redirect_uri=https%3A%2F%2Fthreat-bot-discord.vercel.app%2Fthanks&response_type=code`
- **Bot integration**: `/about` and `/help` have a "Sitio web" button (`discord.ui.Button` with `EMOJI_LINK`) pointing to Vercel URL
- **Git**: landing changes on `web` branch; fast-forward merge to `main`
- **Build output**: `landing/dist/` (gitignored). `pnpm run build` also generates `sitemap-index.xml`
- **Design Context**: ver `PRODUCT.md` (raíz). Register: **brand**. Personalidad: moderno/serio/preciso. Principios: claridad sobre decoración, restricción profesional, enseñar mostrando, credibilidad técnica. Dark-forced, WCAG AA, `prefers-reduced-motion`.

## ⚠️ Gotchas
- **Bound-method illusion** (`bot.py:52-82`): assigning module funcs as bot attrs does NOT bind `self`. `await self.bot.expandir_url(valor)` passes `valor` as bot param. Fix: import directly and pass `self.bot` explicitly.
- **Admin slash commands** use `_safe_followup()` wrapper (`cogs/configuracion.py:13-17`) that catches `discord.errors.NotFound` on expired interactions.
- **`strict_mode`** uses bare `try/except Exception: pass` for message deletion — will silently fail on missing permissions.
- **SSRF protection**: `descargar_url_segura()` resolves DNS → checks for private/loopback IPs → downloads via IP with `Host` header.
- **Logger DEBUG** only on: `cache`, `db`, `handler`, `virustotal`, `sightengine`. Cog loggers inherit INFO from root.
- **`/scan` file downloads** from attachment URL inside cog (not via `descargar_url_segura`).
- **`psutil` in requirements.txt** is unused (never imported) — dependency solely from a template or prior version.
