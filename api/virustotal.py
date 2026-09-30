import time
import asyncio
import hashlib
import json
import base64
from typing import Optional
import logging
import aiohttp
import discord
from core import state
from core.config import (
    VT_API_KEYS, SE_API_KEYS_PAIRS, MAX_FILE_SIZE,
    VT_MAX_ANALYSES_PER_MINUTE, VT_MAX_ANALYSES_PER_DAY,
    SE_MAX_REQUESTS_PER_MINUTE, SE_MAX_OPS_PER_DAY, SE_OPS_PER_CALL,
)
from core.cache import set_cache_mem
from core.database import guardar_analisis_db
from core.utils import obtener_top_antivirus, es_hash_valido
from ui.views import LogActionView
from ui import embed as emb
from core.guild_config import obtener_config_guild, update_stats, registrar_infraccion

log = logging.getLogger("virustotal")

VT_TIMEOUT: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=180)
_vt_lock = asyncio.Lock()
_se_lock = asyncio.Lock()

async def _consumir_vt(key: str) -> bool:
    """Registra el consumo de UNA petición HTTP a VT, de forma atómica.

    El corte de la ventana de 60s y la acumulación ocurren en la misma sección crítica
    que la selección, de modo que N tareas concurrentes no pueden pasar juntas el mismo
    hueco de cuota (esto producía 429 de VT).

    Devuelve False si la key ya agotó su ventana de 60s o su cupo diario.
    """
    async with _vt_lock:
        ahora = time.time()
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        ventana = [t for t in state.bot.vt_key_usage.get(key, []) if ahora - t <= 60]
        state.bot.vt_key_usage[key] = ventana
        diario = state.bot.vt_key_daily_usage.get(key)
        if diario is None or diario["date"] != hoy:
            diario = {"count": 0, "date": hoy}
            state.bot.vt_key_daily_usage[key] = diario
        # Los límites se comprueban ANTES de contar: una petición rechazada no debe
        # inflar el contador diario, o la key quedaría inutilizable de forma permanente.
        if len(ventana) >= VT_MAX_ANALYSES_PER_MINUTE:
            log.debug(f"VT key rate-limited: {key[:8]}... ({len(ventana)} req in 60s)")
            return False
        if diario["count"] >= VT_MAX_ANALYSES_PER_DAY:
            log.debug(f"VT key daily limit: {key[:8]}... ({VT_MAX_ANALYSES_PER_DAY} req/day)")
            return False
        ventana.append(ahora)
        diario["count"] += 1
        state.bot.vt_key_total_requests[key] = state.bot.vt_key_total_requests.get(key, 0) + 1
        return True


async def obtener_siguiente_key() -> Optional[str]:
    """Devuelve la siguiente key de VT en round-robin que todavía tenga cuota.

    No reserva: la reserva la hace `adquirir_vt()` justo antes de cada petición, para
    que selección y conteo sean la misma operación.
    """
    async with _vt_lock:
        if not VT_API_KEYS:
            return None
        ahora = time.time()
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        for _ in range(len(VT_API_KEYS)):
            key = VT_API_KEYS[state.bot.vt_key_index]
            state.bot.vt_key_index = (state.bot.vt_key_index + 1) % len(VT_API_KEYS)
            ventana = state.bot.vt_key_usage.get(key, [])
            if len([t for t in ventana if ahora - t <= 60]) >= VT_MAX_ANALYSES_PER_MINUTE:
                log.debug(f"VT key sin ventana: {key[:8]}...")
                continue
            diario = state.bot.vt_key_daily_usage.get(key)
            if diario and diario["date"] == hoy and diario["count"] >= VT_MAX_ANALYSES_PER_DAY:
                log.debug(f"VT key sin cupo diario: {key[:8]}...")
                continue
            return key
        log.warning("Todas las keys de VT están rate-limited")
        return None


async def adquirir_vt() -> Optional[str]:
    """Devuelve una key lista para hacer UNA petición, o None si no hay cuota.

    Es el único punto por el que deben pasar las peticiones a VirusTotal: cada llamada
    reserva su propio hueco de cuota de forma atómica.
    """
    for _ in range(len(VT_API_KEYS)):
        key = await obtener_siguiente_key()
        if key is not None and await _consumir_vt(key):
            return key
    return None


async def obtener_siguiente_se_key() -> Optional[tuple[str, str]]:
    """Selecciona el siguiente par de SightEngine con cuota y lo RESERVA (4 ops por llamada).

    Una llamada a SightEngine es una única petición HTTP, así que reservar en la
    selección es equivalente y exacto.
    """
    async with _se_lock:
        if not SE_API_KEYS_PAIRS:
            return None
        ahora = time.time()
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        for _ in range(len(SE_API_KEYS_PAIRS)):
            pair = SE_API_KEYS_PAIRS[state.bot.se_key_index]
            state.bot.se_key_index = (state.bot.se_key_index + 1) % len(SE_API_KEYS_PAIRS)
            api_key = pair[0]

            ventana = [t for t in state.bot.se_key_usage.get(api_key, []) if ahora - t <= 60]
            state.bot.se_key_usage[api_key] = ventana

            if len(ventana) >= SE_MAX_REQUESTS_PER_MINUTE:
                log.debug(f"SE key rate-limited: {api_key[:8]}... ({len(ventana)} req in 60s)")
                continue

            diario = state.bot.se_key_daily_usage.get(api_key)
            if diario is not None and diario["date"] == hoy and diario["count"] + SE_OPS_PER_CALL > SE_MAX_OPS_PER_DAY:
                log.debug(f"SE key daily limit: {api_key[:8]}... ({SE_MAX_OPS_PER_DAY} ops/day)")
                continue

            if diario is None or diario["date"] != hoy:
                diario = {"count": 0, "date": hoy}
            diario["count"] += SE_OPS_PER_CALL
            state.bot.se_key_daily_usage[api_key] = diario
            state.bot.se_key_total_requests[api_key] = state.bot.se_key_total_requests.get(api_key, 0) + SE_OPS_PER_CALL
            ventana.append(ahora)
            return pair

        log.warning("Todas las keys de SightEngine están rate-limited")
        return None

async def enviar_log_guild(guild_id: int, tipo: str, valor: str, detalles: str, usuario: discord.User, url_vt: Optional[str] = None, elemento_id: Optional[str] = None, es_nsfw: bool = False) -> Optional[discord.Message]:
    config = await obtener_config_guild(guild_id)
    log_channel_id = config["log_channel_id"]
    if log_channel_id is None:
        return None
    channel = state.bot.get_channel(log_channel_id)
    if channel is None:
        return None
    if es_nsfw:
        embed = emb.nsfw(tipo, valor, detalles)
    else:
        embed = emb.amenaza(tipo, valor, detalles, usuario, vt_link=url_vt)
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

async def _sin_cuota() -> tuple[str, discord.Embed, int]:
    return "error", emb.error_cuota(), 0


def _error_tamanio(filename: str) -> discord.Embed:
    return emb.error_analisis(
        f"`{filename}` supera el tamaño máximo que se puede analizar.",
        detalle=f"Límite de {MAX_FILE_SIZE // (1024 * 1024)} MB por archivo.",
    )


async def analizar_url(url: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT URL INICIO → {url}")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    key = await adquirir_vt()
    if not key:
        log.debug(f"VT URL ERROR → no hay keys disponibles t={time.time()-_t0:.1f}s")
        return await _sin_cuota()
    _t = time.time()
    async with state.bot.session.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": key}, timeout=VT_TIMEOUT
    ) as resp:
        log.debug(f"VT URL GET → status={resp.status} t={time.time()-_t:.1f}s")
        if resp.status == 200:
            data = await resp.json()
            attrs = data["data"]["attributes"]
            if attrs.get("last_analysis_stats"):
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
        key = await adquirir_vt()
        if not key:
            await _finalizar_error(guild_id, "url", url)
            return await _sin_cuota()
        async with state.bot.session.post("https://www.virustotal.com/api/v3/urls", headers={"x-apikey": key}, data={"url": url}, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT URL POST → status={resp.status} t={time.time()-_t:.1f}s")
            if resp.status == 200:
                data = await resp.json()
                scan_id = data["data"]["id"]
                log.debug(f"VT URL SCAN ID → {scan_id} t={time.time()-_t0:.1f}s")
                for intento in range(2):
                    if intento > 0:
                        await asyncio.sleep(55)
                    key = await adquirir_vt()
                    if not key:
                        break
                    _t2 = time.time()
                    async with state.bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers={"x-apikey": key}, timeout=VT_TIMEOUT) as resp2:
                        log.debug(f"VT URL POLL → intento={intento+1}/2 status={resp2.status} t={time.time()-_t2:.1f}s acum={time.time()-_t0:.1f}s")
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            status = analysis["data"]["attributes"]["status"]
                            if status == "completed":
                                log.debug(f"VT URL COMPLETED → url={url} t={time.time()-_t0:.1f}s")
                                return await _procesar_resultado_vt(analysis, "url", url, guild_id, mensaje_original, guardar_cache)
                            else:
                                log.debug(f"VT URL STATUS → {status} intento={intento+1}/2")
                log.debug(f"VT URL POST-POLL CHECK → {url} t={time.time()-_t0:.1f}s")
                key = await adquirir_vt()
                if key:
                    async with state.bot.session.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers={"x-apikey": key}, timeout=VT_TIMEOUT
                    ) as final_resp:
                        if final_resp.status == 200:
                            data = await final_resp.json()
                            attrs = data["data"]["attributes"]
                            if attrs.get("last_analysis_stats"):
                                log.debug(f"VT URL POST-POLL CACHED → {url} t={time.time()-_t0:.1f}s")
                                normalized = {
                                    "data": {
                                        "attributes": {
                                            "stats": attrs["last_analysis_stats"],
                                            "results": attrs.get("last_analysis_results", {}),
                                        }
                                    }
                                }
                                return await _procesar_resultado_vt(normalized, "url", url, guild_id, mensaje_original, guardar_cache)
                log.debug(f"VT URL TIMEOUT → {url} t={time.time()-_t0:.1f}s")
                await _finalizar_error(guild_id, "url", url)
                return "error", emb.error_analisis(
                    "El análisis no pudo completarse tras varios intentos.",
                    detalle="VirusTotal sigue procesando el envío. Inténtalo de nuevo en unos minutos.",
                ), 0
            else:
                log.debug(f"VT URL ERROR → status={resp.status} url={url} t={time.time()-_t0:.1f}s")
                await _finalizar_error(guild_id, "url", url)
                return "error", emb.error_analisis(
                    "VirusTotal rechazó el análisis de la URL.",
                    detalle=f"Código de respuesta {resp.status}.",
                ), 0
    except asyncio.TimeoutError:
        log.error(f"VT URL TIMEOUT HTTP → {url} t={time.time()-_t0:.1f}s")
        await _finalizar_error(guild_id, "url", url)
        return "error", emb.error_conexion(
            f"La solicitud a VirusTotal expiró tras {VT_TIMEOUT.total or 180:.0f}s."), 0
    except Exception as e:
        log.error(f"VT URL EXCEPTION → {url}: {e} t={time.time()-_t0:.1f}s")
        await _finalizar_error(guild_id, "url", url)
        return "error", emb.error_conexion("No se pudo contactar con VirusTotal.", detalle=type(e).__name__), 0


async def analizar_hash(hash_valor: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT HASH INICIO → {hash_valor}")
    if not es_hash_valido(hash_valor):
        log.debug(f"VT HASH INVALIDO → {hash_valor} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", emb.error_analisis(
            f"`{hash_valor}` no es un hash MD5, SHA-1 o SHA-256 válido.",
            detalle="Formato de hash no reconocido por VirusTotal.",
        ), 0
    key = await adquirir_vt()
    if not key:
        return await _sin_cuota()
    try:
        _t = time.time()
        async with state.bot.session.get(f"https://www.virustotal.com/api/v3/files/{hash_valor}", headers={"x-apikey": key}, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT HASH GET → status={resp.status} t={time.time()-_t:.1f}s")
            if resp.status == 200:
                data = await resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                results = data["data"]["attributes"]["last_analysis_results"]
                vt_link = f"https://www.virustotal.com/gui/file/{hash_valor}"
                mal = stats["malicious"]
                if mal > 0:
                    await _on_threat_found("hash", hash_valor, mal, guild_id, mensaje_original, vt_link, results, guardar_cache)
                    top = obtener_top_antivirus(results)
                    top_text = ", ".join(top) if top else "Varios antivirus"
                else:
                    top_text = None
                datos = {"valor": hash_valor, "vt_link": vt_link, "top_text": top_text}
                embed = emb.resultado("hash", datos, mal)
                if guardar_cache:
                    clave = f"hash:{hash_valor}"
                    veredicto = "malicioso" if mal > 0 else "seguro"
                    await guardar_analisis_db(clave, "hash", veredicto, mal=mal, datos=datos)
                    await set_cache_mem(clave, veredicto, mal=mal, datos=datos)
                if mal > 0:
                    log.debug(f"VT HASH MALICIOSO → {hash_valor} mal={mal} t={time.time()-_t0:.1f}s")
                    return "malicioso", embed, mal
                await update_stats(guild_id, "seguro")
                log.debug(f"VT HASH SEGURO → {hash_valor} t={time.time()-_t0:.1f}s")
                return "seguro", embed, 0
            else:
                await update_stats(guild_id, "error")
                log.debug(f"VT HASH NO ENCONTRADO → {hash_valor} status={resp.status} t={time.time()-_t0:.1f}s")
                return "error", emb.error_analisis(
                    "VirusTotal no conoce este hash.",
                    detalle="Ningún análisis previo registrado para ese archivo.",
                ), 0
    except asyncio.TimeoutError:
        log.error(f"VT HASH TIMEOUT → {hash_valor} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", emb.error_conexion("La solicitud a VirusTotal expiró."), 0
    except Exception as e:
        log.error(f"VT HASH EXCEPTION → {hash_valor}: {e} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", emb.error_conexion("No se pudo consultar el hash.", detalle=type(e).__name__), 0

async def analizar_ip(ip: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT IP INICIO → {ip}")
    key = await adquirir_vt()
    if not key:
        return await _sin_cuota()
    try:
        _t = time.time()
        async with state.bot.session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": key}, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT IP GET → status={resp.status} t={time.time()-_t:.1f}s")
            if resp.status == 200:
                data = await resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                mal = stats["malicious"]
                vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
                if mal > 0:
                    await _on_threat_found("ip", ip, mal, guild_id, mensaje_original, vt_link)
                datos = {"valor": ip, "vt_link": vt_link, "top_text": None}
                embed = emb.resultado("ip", datos, mal)
                if guardar_cache:
                    clave = f"ip:{ip}"
                    veredicto = "malicioso" if mal > 0 else "seguro"
                    await guardar_analisis_db(clave, "ip", veredicto, mal=mal, datos=datos)
                    await set_cache_mem(clave, veredicto, mal=mal, datos=datos)
                if mal > 0:
                    log.debug(f"VT IP MALICIOSA → {ip} mal={mal} t={time.time()-_t0:.1f}s")
                    return "malicioso", embed, mal
                await update_stats(guild_id, "seguro")
                log.debug(f"VT IP SEGURA → {ip} t={time.time()-_t0:.1f}s")
                return "seguro", embed, 0
            else:
                await update_stats(guild_id, "error")
                log.debug(f"VT IP NO ENCONTRADA → {ip} status={resp.status} t={time.time()-_t0:.1f}s")
                return "error", emb.error_analisis(
                    f"VirusTotal no tiene datos de reputación para `{ip}`.",
                    detalle="La dirección no figura en la base de datos de VirusTotal.",
                ), 0
    except asyncio.TimeoutError:
        log.error(f"VT IP TIMEOUT → {ip} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", emb.error_conexion("La solicitud a VirusTotal expiró."), 0
    except Exception as e:
        log.error(f"VT IP EXCEPTION → {ip}: {e} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", emb.error_conexion("No se pudo contactar con VirusTotal.", detalle=type(e).__name__), 0

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
                    return "error", emb.error_analisis(
                        f"No se pudo descargar `{archivo.filename}`.",
                        detalle=f"El servidor respondió con el código {resp.status}.",
                    ), 0
                file_bytes = await resp.read()
                if len(file_bytes) > MAX_FILE_SIZE:
                    log.debug(f"VT FILE DEMASIADO GRANDE → {archivo.filename} bytes={len(file_bytes)} t={time.time()-_t0:.1f}s")
                    await update_stats(guild_id, "error")
                    return "error", _error_tamanio(archivo.filename), 0
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                log.debug(f"VT FILE DESCARGADO → hash={file_hash} bytes={len(file_bytes)} t={time.time()-_t0:.1f}s")
        except Exception as e:
            log.error(f"VT FILE DESCARGAR ERROR → {archivo.filename}: {e} t={time.time()-_t0:.1f}s")
            await update_stats(guild_id, "error")
            return "error", emb.error_conexion(
                f"No se pudo descargar `{archivo.filename}`.", detalle=type(e).__name__), 0

    if archivo.size > MAX_FILE_SIZE:
        log.debug(f"VT FILE DEMASIADO GRANDE → {archivo.filename} size={archivo.size} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", _error_tamanio(archivo.filename), 0

    try:
        _t = time.time()
        key = await adquirir_vt()
        if not key:
            await update_stats(guild_id, "error")
            return await _sin_cuota()
        async with state.bot.session.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": key},
            timeout=VT_TIMEOUT
        ) as check_resp:
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

        key = await adquirir_vt()
        if not key:
            await update_stats(guild_id, "error")
            return await _sin_cuota()
        log.debug(f"VT FILE SUBIENDO → {archivo.filename} size={len(file_bytes) if file_bytes else '?'} t={time.time()-_t0:.1f}s")
        data = aiohttp.FormData()
        data.add_field('file', file_bytes, filename=archivo.filename)
        _t2 = time.time()
        async with state.bot.session.post("https://www.virustotal.com/api/v3/files", headers={"x-apikey": key}, data=data, timeout=VT_TIMEOUT) as resp:
            log.debug(f"VT FILE SUBIDO → status={resp.status} t={time.time()-_t2:.1f}s acum={time.time()-_t0:.1f}s")
            if resp.status == 200:
                result_json = await resp.json()
                scan_id = result_json["data"]["id"]
                log.debug(f"VT FILE SCAN ID → {scan_id} t={time.time()-_t0:.1f}s")
                for i in range(2):
                    if i > 0:
                        await asyncio.sleep(55)
                    key = await adquirir_vt()
                    if not key:
                        break
                    _t3 = time.time()
                    async with state.bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers={"x-apikey": key}, timeout=VT_TIMEOUT) as resp2:
                        log.debug(f"VT FILE POLL → intento={i+1}/2 status={resp2.status} t={time.time()-_t3:.1f}s acum={time.time()-_t0:.1f}s")
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            status = analysis["data"]["attributes"]["status"]
                            stats = analysis["data"]["attributes"].get("stats", {})
                            log.debug(f"VT FILE STATUS → {status} stats={stats} intento={i+1}/2")
                            if status == "completed":
                                log.debug(f"VT FILE COMPLETED → {archivo.filename} t={time.time()-_t0:.1f}s")
                                return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache)
                            elif status == "queued":
                                log.debug(f"VT FILE QUEUED → intento={i+1}/2")
                log.debug(f"VT FILE POST-POLL CHECK HASH → {archivo.filename} t={time.time()-_t0:.1f}s")
                key = await adquirir_vt()
                if key:
                    async with state.bot.session.get(
                        f"https://www.virustotal.com/api/v3/files/{file_hash}",
                        headers={"x-apikey": key}, timeout=VT_TIMEOUT
                    ) as final_resp:
                        if final_resp.status == 200:
                            existing = await final_resp.json()
                            if existing["data"]["attributes"].get("last_analysis_stats"):
                                log.debug(f"VT FILE POST-POLL CACHED → {archivo.filename} t={time.time()-_t0:.1f}s")
                                attrs = existing["data"]["attributes"]
                                analysis_attrs = dict(attrs)
                                analysis_attrs["stats"] = attrs["last_analysis_stats"]
                                analysis = {"data": {"attributes": analysis_attrs}}
                                return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache)
                log.error(f"VT FILE TIMEOUT → {archivo.filename} t={time.time()-_t0:.1f}s")
                await update_stats(guild_id, "error")
                return "error", emb.error_analisis(
                    f"El análisis de `{archivo.filename}` tardó más de lo esperado.",
                    detalle="VirusTotal sigue procesando el archivo. Inténtalo de nuevo en unos minutos.",
                ), 0
            else:
                log.error(f"VT FILE SUBIR ERROR → status={resp.status} t={time.time()-_t0:.1f}s")
                await update_stats(guild_id, "error")
                return "error", emb.error_analisis(
                    f"VirusTotal rechazó `{archivo.filename}`.",
                    detalle=f"Código de respuesta {resp.status}.",
                ), 0
    except asyncio.TimeoutError:
        log.error(f"VT FILE TIMEOUT HTTP → {archivo.filename} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", emb.error_conexion("La solicitud a VirusTotal expiró."), 0
    except Exception as e:
        log.error(f"VT FILE EXCEPTION → {archivo.filename}: {e} t={time.time()-_t0:.1f}s")
        await update_stats(guild_id, "error")
        return "error", emb.error_conexion(
            f"No se pudo analizar `{archivo.filename}`.", detalle=type(e).__name__), 0

async def _procesar_resultado_vt(analysis: dict, tipo: str, valor: str, guild_id: Optional[int], mensaje_original: Optional[discord.Message], guardar_cache: bool) -> tuple[str, discord.Embed, int]:
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    clave = f"{tipo}:{valor}"
    log.debug(f"VT RESULT → {tipo}={valor} mal={mal} harmless={stats.get('harmless',0)} undetected={stats.get('undetected',0)}")
    url_id = base64.urlsafe_b64encode(valor.encode()).decode().rstrip("=")
    vt_link = f"https://www.virustotal.com/gui/url/{url_id}"

    if mal > 0:
        await _on_threat_found(tipo, valor, mal, guild_id, mensaje_original, vt_link)
    top_text = None
    results = analysis["data"]["attributes"].get("results") or {}
    if mal > 0 and results:
        top = obtener_top_antivirus(results)
        top_text = ", ".join(top) if top else "Varios antivirus"

    datos = {"valor": valor, "vt_link": vt_link, "top_text": top_text}
    embed = emb.resultado(tipo, datos, mal)
    tipo_str = "malicioso" if mal > 0 else "seguro"

    if guardar_cache:
        await guardar_analisis_db(clave, tipo, tipo_str, mal=mal, datos=datos)
        await set_cache_mem(clave, tipo_str, mal=mal, datos=datos)
    if tipo_str == "seguro" and guild_id:
        await update_stats(guild_id, "seguro")
    return tipo_str, embed, mal

async def _procesar_analisis_archivo(analysis: dict, archivo: discord.Attachment, file_hash: str, guild_id: Optional[int], mensaje_original: Optional[discord.Message], guardar_cache: bool) -> tuple[str, discord.Embed, int]:
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    clave = f"filehash:{file_hash}"
    log.debug(f"VT FILE RESULT → {archivo.filename} hash={file_hash} mal={mal}")

    if mal > 0:
        await _on_threat_found("Archivo", archivo.filename, mal, guild_id, mensaje_original, None, elemento_id=f"filehash:{file_hash}")

    datos = {"valor": archivo.filename, "vt_link": None, "top_text": None}
    embed = emb.resultado("file", datos, mal)
    tipo_str = "malicioso" if mal > 0 else "seguro"
    if guardar_cache:
        await guardar_analisis_db(clave, "file", tipo_str, mal=mal, datos=datos)
        await set_cache_mem(clave, tipo_str, mal=mal, datos=datos)
    if tipo_str == "seguro":
        await update_stats(guild_id, "seguro")
    return tipo_str, embed, mal

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
