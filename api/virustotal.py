import time
import asyncio
import hashlib
import json
import base64
from typing import Optional, Any
import logging
import aiohttp
import discord
from core import state
from core.config import VT_API_KEYS, SE_API_KEYS_PAIRS, MAX_FILE_SIZE, EMOJI_WARNING, EMOJI_CORRECTO, EMOJI_INCORRECTO, EMOJI_LINK, EMOJI_FILE, EMOJI_FINGERPRINT, EMOJI_GUARDIAN, EMOJI_SHIELD, EMOJI_NSFW
from core.cache import get_from_cache_mem, set_cache_mem
from core.database import guardar_analisis_db, guardar_metadatos_hash
from core.utils import obtener_top_antivirus, es_hash_valido
from ui.views import LogActionView
from core.guild_config import obtener_config_guild, update_stats, registrar_infraccion

log = logging.getLogger("virustotal")

VT_TIMEOUT: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=180)
_vt_lock = asyncio.Lock()
_se_lock = asyncio.Lock()

async def obtener_siguiente_key() -> Optional[str]:
    async with _vt_lock:
        if not VT_API_KEYS:
            return None
        ahora = time.time()
        intentos = len(VT_API_KEYS)
        for _ in range(intentos):
            key = VT_API_KEYS[state.bot.vt_key_index]
            state.bot.vt_key_index = (state.bot.vt_key_index + 1) % len(VT_API_KEYS)

            if key not in state.bot.vt_key_usage:
                state.bot.vt_key_usage[key] = []

            state.bot.vt_key_usage[key] = [t for t in state.bot.vt_key_usage[key] if ahora - t <= 60]

            if len(state.bot.vt_key_usage[key]) >= 4:
                log.debug(f"VT key rate-limited: {key[:8]}... ({len(state.bot.vt_key_usage[key])} req in 60s)")
                continue

            hoy = time.strftime("%Y-%m-%d", time.gmtime())
            if key not in state.bot.vt_key_total_requests:
                state.bot.vt_key_total_requests[key] = 0
            if key not in state.bot.vt_key_daily_usage:
                state.bot.vt_key_daily_usage[key] = {"count": 0, "date": hoy}
            if state.bot.vt_key_daily_usage[key]["count"] >= 500 and state.bot.vt_key_daily_usage[key]["date"] == hoy:
                log.debug(f"VT key daily limit: {key[:8]}... (500 req/day)")
                continue

            return key

        log.warning("Todas las keys de VT están rate-limited")
        return None

async def obtener_siguiente_se_key() -> Optional[tuple[str, str]]:
    async with _se_lock:
        if not SE_API_KEYS_PAIRS:
            return None
        ahora = time.time()
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        intentos = len(SE_API_KEYS_PAIRS)
        for _ in range(intentos):
            pair = SE_API_KEYS_PAIRS[state.bot.se_key_index]
            state.bot.se_key_index = (state.bot.se_key_index + 1) % len(SE_API_KEYS_PAIRS)
            api_key = pair[0]

            state.bot.se_key_usage.setdefault(api_key, [])
            state.bot.se_key_usage[api_key] = [t for t in state.bot.se_key_usage[api_key] if ahora - t <= 60]
            if len(state.bot.se_key_usage[api_key]) >= 4:
                log.debug(f"SE key rate-limited: {api_key[:8]}... ({len(state.bot.se_key_usage[api_key])} req in 60s)")
                continue

            return pair

        log.warning("Todas las keys de SightEngine están rate-limited")
        return None

async def registrar_uso_se(api_key: str) -> None:
    ahora = time.time()
    hoy = time.strftime("%Y-%m-%d", time.gmtime())
    if api_key not in state.bot.se_key_usage:
        state.bot.se_key_usage[api_key] = []
    if api_key not in state.bot.se_key_total_requests:
        state.bot.se_key_total_requests[api_key] = 0
    if api_key not in state.bot.se_key_daily_usage:
        state.bot.se_key_daily_usage[api_key] = {"count": 0, "date": hoy}
    state.bot.se_key_usage[api_key] = [t for t in state.bot.se_key_usage[api_key] if ahora - t <= 60]
    state.bot.se_key_usage[api_key].append(ahora)
    if state.bot.se_key_daily_usage[api_key]["date"] != hoy:
        state.bot.se_key_daily_usage[api_key] = {"count": 4, "date": hoy}
    else:
        state.bot.se_key_daily_usage[api_key]["count"] += 4
    state.bot.se_key_total_requests[api_key] += 4

async def registrar_uso_vt(key: str) -> None:
    ahora = time.time()
    hoy = time.strftime("%Y-%m-%d", time.gmtime())
    if key not in state.bot.vt_key_usage:
        state.bot.vt_key_usage[key] = []
    if key not in state.bot.vt_key_total_requests:
        state.bot.vt_key_total_requests[key] = 0
    if key not in state.bot.vt_key_daily_usage:
        state.bot.vt_key_daily_usage[key] = {"count": 0, "date": hoy}
    state.bot.vt_key_usage[key] = [t for t in state.bot.vt_key_usage[key] if ahora - t <= 60]
    state.bot.vt_key_usage[key].append(ahora)
    if state.bot.vt_key_daily_usage[key]["date"] != hoy:
        state.bot.vt_key_daily_usage[key] = {"count": 1, "date": hoy}
    else:
        state.bot.vt_key_daily_usage[key]["count"] += 1
    state.bot.vt_key_total_requests[key] += 1

async def enviar_log_guild(guild_id: int, tipo: str, valor: str, detalles: str, usuario: discord.User, url_vt: Optional[str] = None, elemento_id: Optional[str] = None, es_nsfw: bool = False) -> Optional[discord.Message]:
    config = await obtener_config_guild(guild_id)
    log_channel_id = config["log_channel_id"]
    if log_channel_id is None:
        return None
    channel = state.bot.get_channel(log_channel_id)
    if channel is None:
        return None
    if es_nsfw:
        embed = discord.Embed(
            title=f"{EMOJI_NSFW} Contenido NSFW Detectado",
            description=f"**{tipo}** contenido NSFW detectado",
            color=discord.Color.orange()
        )
    else:
        embed = discord.Embed(
            title=f"{EMOJI_WARNING} Amenaza Detectada",
            description=f"**{tipo.upper()}** analizado resultó **malicioso**",
            color=discord.Color.red()
        )
    embed.add_field(name=f"{EMOJI_FINGERPRINT} Valor", value=f"`{valor}`", inline=False)
    embed.add_field(name=f"{EMOJI_GUARDIAN} Usuario", value=usuario.mention, inline=True)
    embed.add_field(name=f"{EMOJI_SHIELD} Detalles", value=detalles, inline=True)
    if url_vt:
        embed.add_field(name=f"{EMOJI_LINK} VirusTotal", value=f"[Ver informe]({url_vt})", inline=False)
    embed.set_footer(text=f"ID: {usuario.id} • {time.strftime('%Y-%m-%d %H:%M:%S')}")
    view = LogActionView(guild_id, usuario.id, elemento_id=elemento_id)
    try:
        msg = await channel.send(embed=embed, view=view)
        view.message = msg
        return msg
    except discord.errors.Forbidden:
        log.error(f"enviar_log_guild: sin permisos send_messages/embed_links en #{channel} (guild {guild_id})")
    except Exception as e:
        log.error(f"enviar_log_guild: error enviando a canal {channel_id}: {e}")
    return None

async def analizar_url(url: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT URL INICIO → {url}")
    key = await obtener_siguiente_key()
    if not key:
        log.debug(f"VT URL ERROR → no hay keys disponibles t={time.time()-_t0:.1f}s")
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    _t = time.time()
    async with state.bot.session.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers, timeout=VT_TIMEOUT
    ) as resp:
        log.debug(f"VT URL GET → status={resp.status} t={time.time()-_t:.1f}s")
        if resp.status == 200:
            data = await resp.json()
            attrs = data["data"]["attributes"]
            if attrs.get("last_analysis_stats"):
                await registrar_uso_vt(key)
                normalized = {
                    "data": {
                        "attributes": {
                            "stats": attrs["last_analysis_stats"],
                            "results": attrs.get("last_analysis_results", {}),
                        }
                    }
                }
                return await _procesar_resultado_vt(normalized, "url", url, guild_id, mensaje_original, guardar_cache)

    try:
        _t = time.time()
        async with state.bot.session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT URL POST → status={resp.status} t={time.time()-_t:.1f}s")
            if resp.status == 200:
                data = await resp.json()
                scan_id = data["data"]["id"]
                log.debug(f"VT URL SCAN ID → {scan_id} t={time.time()-_t0:.1f}s")
                for intento in range(3):
                    if intento > 0:
                        await asyncio.sleep(20)
                    await registrar_uso_vt(key)
                    _t2 = time.time()
                    async with state.bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers, timeout=VT_TIMEOUT) as resp2:
                        log.debug(f"VT URL POLL → intento={intento+1}/3 status={resp2.status} t={time.time()-_t2:.1f}s acum={time.time()-_t0:.1f}s")
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            status = analysis["data"]["attributes"]["status"]
                            if status == "completed":
                                log.debug(f"VT URL COMPLETED → url={url} t={time.time()-_t0:.1f}s")
                                return await _procesar_resultado_vt(analysis, "url", url, guild_id, mensaje_original, guardar_cache)
                            else:
                                log.debug(f"VT URL STATUS → {status} intento={intento+1}/3")
                log.debug(f"VT URL TIMEOUT → {url} t={time.time()-_t0:.1f}s")
                await _finalizar_error(guild_id, "url", url)
                return "error", discord.Embed(title="Error en análisis", description=f"El análisis no pudo completarse tras varios intentos. Intenta de nuevo.", color=discord.Color.red()), 0
            else:
                log.debug(f"VT URL ERROR → status={resp.status} url={url} t={time.time()-_t0:.1f}s")
                await _finalizar_error(guild_id, "url", url)
                return "error", discord.Embed(title="Error al analizar URL", description=f"VirusTotal respondió con código {resp.status}.", color=discord.Color.red()), 0
    except asyncio.TimeoutError:
        log.error(f"VT URL TIMEOUT HTTP → {url} t={time.time()-_t0:.1f}s")
        await _finalizar_error(guild_id, "url", url)
        return "error", discord.Embed(title="Error de conexión", description=f"La conexión con VirusTotal expiró ({VT_TIMEOUT.total or 180:.0f}s).", color=discord.Color.red()), 0
    except Exception as e:
        log.error(f"VT URL EXCEPTION → {url}: {e} t={time.time()-_t0:.1f}s")
        await _finalizar_error(guild_id, "url", url)
        return "error", discord.Embed(title="Error de conexión", description=f"No se pudo contactar con VirusTotal: {type(e).__name__}", color=discord.Color.red()), 0


async def analizar_hash(hash_valor: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT HASH INICIO → {hash_valor}")
    if not es_hash_valido(hash_valor):
        log.debug(f"VT HASH INVALIDO → {hash_valor} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", discord.Embed(title=f"{EMOJI_INCORRECTO} Hash inválido", description=f"`{hash_valor}` no es un hash MD5, SHA-1 o SHA-256 válido.", color=discord.Color.red()), 0
    key = await obtener_siguiente_key()
    if not key:
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}
    try:
        _t = time.time()
        async with state.bot.session.get(f"https://www.virustotal.com/api/v3/files/{hash_valor}", headers=headers, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT HASH GET → status={resp.status} t={time.time()-_t:.1f}s")
            if resp.status == 200:
                await registrar_uso_vt(key)
                data = await resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                results = data["data"]["attributes"]["last_analysis_results"]
                vt_link = f"https://www.virustotal.com/gui/file/{hash_valor}"
                mal = stats["malicious"]
                if mal > 0:
                    await _on_threat_found("hash", hash_valor, mal, guild_id, mensaje_original, vt_link, results, guardar_cache)
                    top = obtener_top_antivirus(results)
                    top_text = ", ".join(top) if top else "Varios antivirus"
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Hash Malicioso Detectado", description=f"**{mal}** antivirus lo identificaron", color=discord.Color.orange())
                    embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                    embed.add_field(name="Detectado por", value=f"`{top_text}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        await guardar_analisis_db(f"hash:{hash_valor}", "hash", "malicioso", embed, mal)
                        await set_cache_mem(f"hash:{hash_valor}", "malicioso", embed, mal)
                    log.debug(f"VT HASH MALICIOSO → {hash_valor} mal={mal} t={time.time()-_t0:.1f}s")
                    return "malicioso", embed, mal
                else:
                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} Hash Seguro", description="No se encontraron amenazas", color=discord.Color.green())
                    embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        await guardar_analisis_db(f"hash:{hash_valor}", "hash", "seguro", embed, 0)
                        await set_cache_mem(f"hash:{hash_valor}", "seguro", embed, 0)
                    await update_stats(guild_id, "seguro")
                    log.debug(f"VT HASH SEGURO → {hash_valor} t={time.time()-_t0:.1f}s")
                    return "seguro", embed, 0
            else:
                await update_stats(guild_id, "error")
                embed = discord.Embed(title="Hash no encontrado", description="No existe en VirusTotal", color=discord.Color.red())
                log.debug(f"VT HASH NO ENCONTRADO → {hash_valor} status={resp.status} t={time.time()-_t0:.1f}s")
                return "error", embed, 0
    except asyncio.TimeoutError:
        log.error(f"VT HASH TIMEOUT → {hash_valor} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        embed = discord.Embed(title="Error", description="La solicitud a VirusTotal expiró.", color=discord.Color.red())
        return "error", embed, 0
    except Exception as e:
        log.error(f"VT HASH EXCEPTION → {hash_valor}: {e} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        embed = discord.Embed(title="Error", description="No se pudo consultar el hash", color=discord.Color.red())
        return "error", embed, 0

async def analizar_ip(ip: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT IP INICIO → {ip}")
    key = await obtener_siguiente_key()
    if not key:
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}
    try:
        _t = time.time()
        async with state.bot.session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT IP GET → status={resp.status} t={time.time()-_t:.1f}s")
            if resp.status == 200:
                await registrar_uso_vt(key)
                data = await resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                mal = stats["malicious"]
                vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
                if mal > 0:
                    await _on_threat_found("ip", ip, mal, guild_id, mensaje_original, vt_link)
                    embed = discord.Embed(title=f"{EMOJI_WARNING} IP Maliciosa Detectada", description=f"**{mal}** fuentes reportan actividad sospechosa", color=discord.Color.orange())
                    embed.add_field(name="IP", value=f"`{ip}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        await guardar_analisis_db(f"ip:{ip}", "ip", "malicioso", embed, mal)
                        await set_cache_mem(f"ip:{ip}", "malicioso", embed, mal)
                    log.debug(f"VT IP MALICIOSA → {ip} mal={mal} t={time.time()-_t0:.1f}s")
                    return "malicioso", embed, mal
                else:
                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} IP Segura", description="No se encontraron reportes", color=discord.Color.green())
                    embed.add_field(name="IP", value=f"`{ip}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        await guardar_analisis_db(f"ip:{ip}", "ip", "seguro", embed, 0)
                        await set_cache_mem(f"ip:{ip}", "seguro", embed, 0)
                    await update_stats(guild_id, "seguro")
                    log.debug(f"VT IP SEGURA → {ip} t={time.time()-_t0:.1f}s")
                    return "seguro", embed, 0
            else:
                await update_stats(guild_id, "error")
                log.debug(f"VT IP NO ENCONTRADA → {ip} status={resp.status} t={time.time()-_t0:.1f}s")
                embed = discord.Embed(title="IP no encontrada", description="No se pudo analizar la IP", color=discord.Color.red())
                return "error", embed, 0
    except asyncio.TimeoutError:
        log.error(f"VT IP TIMEOUT → {ip} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        embed = discord.Embed(title="Error", description="La solicitud a VirusTotal expiró.", color=discord.Color.red())
        return "error", embed, 0
    except Exception as e:
        log.error(f"VT IP EXCEPTION → {ip}: {e} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        embed = discord.Embed(title="Error", description="No se pudo contactar con VirusTotal", color=discord.Color.red())
        return "error", embed, 0

async def analizar_archivo(archivo: discord.Attachment, file_bytes: Optional[bytes] = None, file_hash: Optional[str] = None, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT FILE INICIO → {archivo.filename} hash={file_hash} size={archivo.size}")

    if file_bytes is None:
        try:
            _t = time.time()
            async with state.bot.session.get(archivo.url) as resp:
                log.debug(f"VT FILE DESCARGANDO → status={resp.status} t={time.time()-_t:.1f}s")
                if resp.status != 200:
                    await update_stats(guild_id, "error")
                    return "error", discord.Embed(title="Error al descargar archivo", description=f"El servidor respondió con código {resp.status}", color=discord.Color.red()), 0
                file_bytes = await resp.read(limit=MAX_FILE_SIZE + 1024)
                if len(file_bytes) > MAX_FILE_SIZE:
                    log.debug(f"VT FILE DEMASIADO GRANDE → {archivo.filename} bytes={len(file_bytes)} t={time.time()-_t0:.1f}s")
                    await update_stats(guild_id, "error")
                    return "error", discord.Embed(title="Archivo demasiado grande", description=f"{EMOJI_FILE} `{archivo.filename}` excede 32 MB", color=discord.Color.red()), 0
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                log.debug(f"VT FILE DESCARGADO → hash={file_hash} bytes={len(file_bytes)} t={time.time()-_t0:.1f}s")
        except Exception as e:
            log.error(f"VT FILE DESCARGAR ERROR → {archivo.filename}: {e} t={time.time()-_t0:.1f}s")
            await update_stats(guild_id, "error")
            return "error", discord.Embed(title="Error", description="Error al descargar el archivo", color=discord.Color.red()), 0

    if archivo.size > MAX_FILE_SIZE:
        log.debug(f"VT FILE DEMASIADO GRANDE → {archivo.filename} size={archivo.size} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        embed = discord.Embed(title="Archivo demasiado grande", description=f"{EMOJI_FILE} `{archivo.filename}` excede 32 MB", color=discord.Color.red())
        return "error", embed, 0

    key = await obtener_siguiente_key()
    if not key:
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}

    try:
        _t = time.time()
        check_resp = await state.bot.session.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers,
            timeout=VT_TIMEOUT
        )
        log.debug(f"VT FILE CHECK HASH → status={check_resp.status} t={time.time()-_t:.1f}s acum={time.time()-_t0:.1f}s")
        if check_resp.status == 200:
            existing = await check_resp.json()
            if existing["data"]["attributes"].get("last_analysis_stats"):
                log.debug(f"VT FILE CACHED VT → {archivo.filename} hash={file_hash} t={time.time()-_t0:.1f}s")
                attrs = existing["data"]["attributes"]
                analysis_attrs = dict(attrs)
                analysis_attrs["stats"] = attrs["last_analysis_stats"]
                analysis = {"data": {"attributes": analysis_attrs}}
                return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache)

        log.debug(f"VT FILE SUBIENDO → {archivo.filename} size={len(file_bytes) if file_bytes else '?'} t={time.time()-_t0:.1f}s")
        data = aiohttp.FormData()
        data.add_field('file', file_bytes, filename=archivo.filename)
        _t2 = time.time()
        async with state.bot.session.post("https://www.virustotal.com/api/v3/files", headers=headers, data=data, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT FILE SUBIDO → status={resp.status} t={time.time()-_t2:.1f}s acum={time.time()-_t0:.1f}s")
            if resp.status == 200:
                result_json = await resp.json()
                scan_id = result_json["data"]["id"]
                log.debug(f"VT FILE SCAN ID → {scan_id} t={time.time()-_t0:.1f}s")
                for i in range(3):
                    if i > 0:
                        await asyncio.sleep(20)
                    await registrar_uso_vt(key)
                    _t3 = time.time()
                    async with state.bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers, timeout=VT_TIMEOUT) as resp2:
                        log.debug(f"VT FILE POLL → intento={i+1}/3 status={resp2.status} t={time.time()-_t3:.1f}s acum={time.time()-_t0:.1f}s")
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            status = analysis["data"]["attributes"]["status"]
                            stats = analysis["data"]["attributes"].get("stats", {})
                            log.debug(f"VT FILE STATUS → {status} stats={stats} intento={i+1}/3")
                            if status == "completed":
                                log.debug(f"VT FILE COMPLETED → {archivo.filename} t={time.time()-_t0:.1f}s")
                                return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache)
                            elif status == "queued":
                                log.debug(f"VT FILE QUEUED → intento={i+1}/3")
                log.error(f"VT FILE TIMEOUT → {archivo.filename} t={time.time()-_t0:.1f}s")
                await update_stats(guild_id, "error")
                return "error", discord.Embed(title="Error en análisis", description="El análisis tardó más de lo esperado. Intenta de nuevo.", color=discord.Color.red()), 0
            else:
                log.error(f"VT FILE SUBIR ERROR → status={resp.status} t={time.time()-_t0:.1f}s")
                await update_stats(guild_id, "error")
                return "error", discord.Embed(title="Error al subir archivo", description="VirusTotal rechazó el archivo", color=discord.Color.red()), 0
    except asyncio.TimeoutError:
        log.error(f"VT FILE TIMEOUT HTTP → {archivo.filename} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", discord.Embed(title="Error", description="La solicitud a VirusTotal expiró.", color=discord.Color.red()), 0
    except Exception as e:
        log.error(f"VT FILE EXCEPTION → {archivo.filename}: {e} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", discord.Embed(title="Error", description="No se pudo analizar el archivo", color=discord.Color.red()), 0

async def _procesar_resultado_vt(analysis: dict, tipo: str, valor: str, guild_id: Optional[int], mensaje_original: Optional[discord.Message], guardar_cache: bool) -> tuple[str, discord.Embed, int]:
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    clave = f"{tipo}:{valor}"
    log.debug(f"VT RESULT → {tipo}={valor} mal={mal} harmless={stats.get('harmless',0)} undetected={stats.get('undetected',0)}")
    url_id = base64.urlsafe_b64encode(valor.encode()).decode().rstrip("=")
    vt_link = f"https://www.virustotal.com/gui/url/{url_id}"

    if mal > 0:
        await _on_threat_found(tipo, valor, mal, guild_id, mensaje_original, vt_link)
        embed = discord.Embed(title=f"{EMOJI_WARNING} URL Maliciosa Detectada", description=f"Se encontraron **{mal}** detecciones", color=discord.Color.orange())
        embed.add_field(name="URL", value=f"`{valor}`", inline=False)
        embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
        tipo_str = "malicioso"
    else:
        embed = discord.Embed(title=f"{EMOJI_CORRECTO} URL Segura", description="No se detectaron amenazas", color=discord.Color.green())
        embed.add_field(name="URL", value=f"`{valor}`", inline=False)
        embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
        tipo_str = "seguro"
        if guild_id:
            await update_stats(guild_id, "seguro")

    if guardar_cache:
        await guardar_analisis_db(clave, tipo, tipo_str, embed, mal)
        await set_cache_mem(clave, tipo_str, embed, mal)
    return tipo_str, embed, mal

async def _procesar_analisis_archivo(analysis: dict, archivo: discord.Attachment, file_hash: str, guild_id: Optional[int], mensaje_original: Optional[discord.Message], guardar_cache: bool) -> tuple[str, discord.Embed, int]:
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    clave = f"filehash:{file_hash}"
    log.debug(f"VT FILE RESULT → {archivo.filename} hash={file_hash} mal={mal}")

    if mal > 0:
        await _on_threat_found("Archivo", archivo.filename, mal, guild_id, mensaje_original, None, elemento_id=f"filehash:{file_hash}")
        embed = discord.Embed(title=f"{EMOJI_WARNING} Archivo Malicioso Detectado", description=f"**{mal}** antivirus detectaron {EMOJI_FILE} `{archivo.filename}`", color=discord.Color.orange())
        if guardar_cache:
            await guardar_analisis_db(clave, "file", "malicioso", embed, mal)
            await set_cache_mem(clave, "malicioso", embed, mal)
            meta_clave = f"file:{archivo.filename}:{archivo.size}"
            await guardar_metadatos_hash(meta_clave, file_hash)
            dummy = discord.Embed(title="File Meta")
            await set_cache_mem(meta_clave, json.dumps({"hash": file_hash}), dummy, 0)
        return "malicioso", embed, mal
    else:
        embed = discord.Embed(title=f"{EMOJI_CORRECTO} Archivo Seguro", description=f"{EMOJI_FILE} `{archivo.filename}` parece limpio (0 detecciones)", color=discord.Color.green())
        if guardar_cache:
            await guardar_analisis_db(clave, "file", "seguro", embed, 0)
            await set_cache_mem(clave, "seguro", embed, 0)
            meta_clave = f"file:{archivo.filename}:{archivo.size}"
            await guardar_metadatos_hash(meta_clave, file_hash)
            dummy = discord.Embed(title="File Meta")
            await set_cache_mem(meta_clave, json.dumps({"hash": file_hash}), dummy, 0)
        await update_stats(guild_id, "seguro")
        return "seguro", embed, 0

async def _post_threat_side_effects(guild_id: int, tipo_str: str, valor: str, mal: int, mensaje_original: discord.Message, vt_link: Optional[str], eid: str) -> None:
    try:
        await update_stats(guild_id, "malicioso")
        await registrar_infraccion(guild_id, mensaje_original.author.id, eid)
        if vt_link:
            await enviar_log_guild(guild_id, tipo_str, valor, f"{mal} detecciones", mensaje_original.author, vt_link, elemento_id=eid)
        else:
            await enviar_log_guild(guild_id, tipo_str, valor, f"{mal} detecciones", mensaje_original.author, elemento_id=eid)
        config = await obtener_config_guild(guild_id)
        if config["strict_mode"]:
            try:
                await mensaje_original.delete()
            except (discord.errors.Forbidden, discord.errors.NotFound):
                pass
    except Exception as e:
        log.error(f"Error en post-threat side effects: {e}")


async def _on_threat_found(tipo_str: str, valor: str, mal: int, guild_id: Optional[int], mensaje_original: Optional[discord.Message], vt_link: Optional[str] = None, results: Optional[dict] = None, guardar_cache: bool = True, elemento_id: Optional[str] = None) -> None:
    if guild_id and mensaje_original:
        eid = elemento_id or (f"url:{valor}" if tipo_str in ("URL", "url") else f"hash:{valor}" if tipo_str == "hash" else f"ip:{valor}")
        task = asyncio.create_task(_post_threat_side_effects(guild_id, tipo_str, valor, mal, mensaje_original, vt_link, eid))
        task.add_done_callback(lambda t: log.error(f"Post-threat error: {t.exception()}", exc_info=t.exception()) if t.exception() else None)

async def _finalizar_error(guild_id: Optional[int], tipo: str, valor: str) -> None:
    await update_stats(guild_id, "error")
