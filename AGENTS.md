# Threat-bot

## Commit header
`bot.py` line 1 must be `# Commit: <hash>` — actualizarlo al commit actual antes de modificar el archivo.

## Emojis (core/config.py)
- `EMOJI_CORRECTO` — análisis seguro
- `EMOJI_INCORRECTO` — uso incorrecto de comandos
- `EMOJI_ERROR` — errores de análisis (no confundir con WARNING)
- `EMOJI_WARNING` — alertas de amenaza/malicioso
- `EMOJI_NSFW` — detección NSFW
- `EMOJI_LOADING` — análisis en progreso
- `EMOJI_COOLDOWN` — rate limit / cooldown
- `EMOJI_LINK`, `EMOJI_LUPA`, `EMOJI_FILE`, `EMOJI_SHIELD`, etc. — iconos de UI

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

## License
AGPL-3.0 — visible, but forks must stay open source. GitHub detects it natively.

## CI/CD
`push dev` → GitHub Actions (`test-bot.yml`): `python -m compileall .` + `timeout 15s python bot.py` (dummy env) → if OK → `merge-to-main.yml`: merge dev→main → Pterodactyl git pull + restart.

## Two-project structure
- **Bot** (root): Python, deployed to Pterodactyl. Branches: `dev` → `main`.
- **Landing** (`landing/`): Astro/TypeScript, deployed to Vercel. Branch: `web` (fast-forward merge to `main`).
- These are independent — bot CI does not test landing, and vice versa.

## Verificación local (no instalar nada)
El bot corre en un servidor Pterodactyl. Para verificar cambios localmente solo ejecutar `python -m compileall .` — si compila sin errores, está correcto. No instalar requirements ni ejecutar `bot.py` en local.

## Testing
```
pip install -r requirements.txt
python -m pytest tests/ -v
```
Tests cover: `core/utils.py` (whitelist, hash validation, double extension, percentage bar, antivirus extraction), `core/cache.py` (hit/miss/expiry), `core/guild_config.py` (lock creation/removal/concurrency).

## Architecture
- **Entrypoint** `bot.py:119` `setup_hook` → loads `cogs/*.py`; `on_ready` inits DB + slash sync. `bot._ready_done` guard.
- **Concurrency**: `core/state.py:ANALYSIS_SEMAPHORE = Semaphore(20)` (API calls), `bot._analysis_sem = Semaphore(100)` (in-flight tasks), `bot._download_sem = Semaphore(5)` (attachment downloads).
- **State shortcut**: `core/state.py` — `state.bot = bot` at `bot.py:31`. Import `from core import state` then `state.bot` anywhere.
- **Lifecycle**: `bot.close` monkey-patched (`bot.py:217-221`) → cancel tasks → flush data → stop DB pool → close session → original close. `on_guild_remove` (`bot.py:197-203`) removes guild from `guilds_data` + instant flush + removes guild lock. Background: `_rotar_estado()` every 30s, `_limpiar_cron()` hourly SQLite cleanup + `user_scan_history`/`antispam_scan` stale entry cleanup.
- **Persistence**: SQLite (`analisis.db`, 4-conn WAL pool via `DatabasePool`) for cached scans; JSON (`data.json`) for guild configs. `guardar_datos()` debounces 3s; pass `inmediato=True` for instant writes.
- **Config details**: `load_dotenv()` in both `bot.py:25` + `core/config.py:5` (innocuo). Timeouts: bot=60s, VT=180s, SE=30s. Size limits: 32MB (VT upload), 2MB (SE image). Errors never cached (`_finalizar_error` solo `update_stats`).

## Auto-analysis pipeline
`on_message` / `on_message_edit` → `ui/message_handler.py:234` `procesar_analisis(bot, message)`.
- **URLs** (non-image, not whitelisted): expand → RAM cache → SQLite cache → VT API.
- **Image URLs** (single, non-whitelisted): SSRF-safe download (`descargar_url_segura`) → SightEngine NSFW.
- **Attachments**: images → SightEngine, others → VT. Batch cap: 5. Runs alongside URL analysis.
- **File heuristics**: `tiene_doble_extension` warns on `file.jpg.vbs`; MIME mismatch warns on `.jpg` with non-`image/jpeg` content-type.

## Caching
- **RAM**: `OrderedDict` max 100000 entries, 1h TTL. Returns `(tipo, embed, mal)` or `(None, None, 0)`.
- **SQLite**: `analisis.db` table `analisis(clave, tipo, resultado, embed_json, timestamp, expira)`. Expiry: URL/IP 7d, hash/file/NSFW 30d.
- **DNS cache**: `core/utils.py:15` — `OrderedDict`, 300s TTL, max 5000 entries with LRU eviction. Avoids redundant lookups during SSRF checks.
- Cache keys: `f"url:{normalizar_url(url)}"`, `f"ip:{ip}"`, `f"hash:{hash}"`, `f"filehash:{sha256}"`, `f"nsfw:{sha256}"`.
- URLs are normalized before cache key generation (`normalizar_url` in `core/utils.py:133`): lowercase scheme/host, strip trailing slashes, remove default ports. Prevents duplicate VT calls for equivalent URLs.
- Always expand URLs before cache lookup (`expandir_url` in `core/utils.py:145`).

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
- 30 analyses/hour per user (`ANTISPAM_ANALYSIS_PER_HOUR`), 10s cooldown between scans (`ANTISPAM_COOLDOWN`). Tracks in `bot.user_scan_history` and `bot.antispam_scan`. **Always applies** — even on cache hits. In `/scan` applies to all types; in auto-analysis only gates URL processing — attachments bypass it.
- **Cache behavior**: 30/h + 10s cooldown always enforced. Timestamp append (`bot.antispam_scan[spam_key]`) only happens on cache miss (when `todas_en_cache` is False). This means cache hits don't consume cooldown but still reject if user is rate-limited.
- Per-user VT hard limit: `VT_MAX_ANALYSES_PER_MINUTE = 4` (`core/config.py:80`). Checked via `check_vt_user_limit()` in `core/utils.py:226`. Sliding 60s window. Only applies on cache miss (real VT calls). Cache hits bypass this limit by design.

## Whitelist
- `dominio_en_whitelist(dominio, whitelist)` checks exact match or subdomain (`core/utils.py:45`).
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
- **Pages**: `index.astro` (single-page), `privacidad.astro`, `terminos.astro`, `thanks.astro`, `404.astro`
- **Discord invite**: `https://discord.com/oauth2/authorize?client_id=1038186932456390726&permissions=277025745990&scope=bot+applications.commands&redirect_uri=https%3A%2F%2Fthreat-bot-discord.vercel.app%2Fthanks&response_type=code`
- **Bot integration**: `/about` and `/help` have a "Sitio web" button (`discord.ui.Button` with `EMOJI_LINK`) pointing to Vercel URL
- **Git**: landing changes on `web` branch; fast-forward merge to `main`
- **Build output**: `landing/dist/` (gitignored). `pnpm run build` also generates `sitemap-index.xml`
- **Design Context**: ver `PRODUCT.md` (raíz). Register: **brand**. Personalidad: moderno/serio/preciso. Principios: claridad sobre decoración, restricción profesional, enseñar mostrando, credibilidad técnica. Dark-forced, WCAG AA, `prefers-reduced-motion`.
- **Nav**: Full-width always-visible bar (`bg-surface-900/80 backdrop-blur-sm border-b border-white/5`). Logo + 3 links (desktop) + CTA "Añadir a Discord" con icono `+`. Mobile: logo + CTA solamente (sin hamburger). `Icon` importado de `components/Icon.astro`.
- **Chat mockup**: 3 escenarios con pesos (50% malicioso, 30% seguro, 20% whitelist). Cada conversación tiene `urlFrom: 'u1'|'u2'` que dice quién envía la URL. Usuarios únicos vía `do/while`. Emojis reales en `landing/public/emoji-*.png` (warn, check, whitelist). Whitelist responde con texto plano (no embed). Malicioso usa borde naranja (`rgb(230,126,34)`), no rojo.
- **CSS**: Scroll reveal variants: `up` (blur+translate), `scale` (scale+blur), `subtle` (translate sin blur), `fade` (solo opacity), `none`. `.is-visible` DEBE venir después de las variantes en el CSS para que `filter: none` gane. Card hover: `translateY(-2px)`. CTA shadow: `box-shadow: 0 4px 14px rgba(88,101,242,0.25)`. Warm neutrals: hue 40 en superficies de texto.
- **Emoji files**: `landing/public/emoji-warn.png`, `emoji-check.png`, `emoji-whitelist.png`. `emoji-wrong.png` existe pero NO se usa. Root files (`check.png`, `warn.png`, `wrong.png`, `whitelist.png`) son las fuentes — ya copiados a public.
- **Footer**: Copyright + GitHub icon (`https://github.com/xkbm`, inline SVG) + "Añadir a Discord" link.

## ⚠️ Gotchas
- **Bound-method illusion** (`bot.py:52-82`): assigning module funcs as bot attrs does NOT bind `self`. `await self.bot.expandir_url(valor)` passes `valor` as bot param. Fix: import directly and pass `self.bot` explicitly.
- **Admin slash commands** use `_safe_followup()` wrapper (`cogs/configuracion.py:13-17`) that catches `discord.errors.NotFound` on expired interactions.
- **`strict_mode`** uses `except (discord.errors.Forbidden, discord.errors.NotFound)` for message deletion — silently ignores permission/missing errors.
- **SSRF protection**: `descargar_url_segura()` resolves DNS → checks for private/loopback IPs → downloads via IP with `Host` header.
- **SSL handshake limitation**: `expandir_url` connects via IP with `Host` header — TLS SNI uses the IP, not the hostname. Fails with CDNs (Cloudflare) that require correct SNI. Fallback works: URL is returned as-is for VT analysis.
- **Logger DEBUG** only on: `cache`, `db`, `handler`, `virustotal`, `sightengine`. Cog loggers inherit INFO from root.
- **`/scan` file downloads** from attachment URL inside cog (not via `descargar_url_segura`).
- **SVG `className`** (`landing/`): SVG elements have `className` as `SVGAnimatedString`, not a plain string. Setting `element.className = 'foo'` may throw or silently fail. Use `setAttribute('class', ...)` or avoid manipulating SVG class from JS.
- **CSS specificity for scroll reveals** (`landing/`): `.scroll-reveal.is-visible` must come AFTER variant rules (`[data-reveal="up"]`, `[data-reveal="scale"]`, etc.) in the CSS. If it comes before, the variant's `filter: blur(Npx)` overrides `filter: none` and content stays blurred forever.

## Logging
- Default format: `[YYYY-MM-DD HH:MM:SS] [LEVEL] logger: message` with timestamps.
- Set `LOG_FORMAT=json` in `.env` for structured JSON logging (machine-parseable).
- DEBUG loggers: `cache`, `db`, `handler`, `virustotal`, `sightengine`. All others inherit INFO from root.

## Data validation
- `cargar_datos()` merges defaults into loaded guild configs — missing fields get safe defaults instead of crashing.

## 🔴 Known bot issues (not yet fixed)
- (none currently)
