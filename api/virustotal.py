import time
import asyncio
import hashlib
import json
import urllib.parse
import logging
import aiohttp
import discord
from core import state
from core.config import VT_API_KEYS, SE_API_KEYS_PAIRS, MAX_FILE_SIZE, EMOJI_WARNING, EMOJI_CORRECTO, EMOJI_INCORRECTO, EMOJI_LINK, EMOJI_FILE, EMOJI_FINGERPRINT, EMOJI_GUARDIAN, EMOJI_SHIELD
from core.cache import get_from_cache_mem, set_cache_mem
from core.database import guardar_analisis_db, obtener_analisis_db, guardar_metadatos_hash, guardar_datos
from core.utils import obtener_top_antivirus, es_hash_valido
from ui.views import LogActionView
from core.guild_config import obtener_config_guild, update_stats, registrar_infraccion

log = logging.getLogger("virustotal")

_vt_lock = asyncio.Lock()

# ========== ROTACIÓN DE CLAVES VT ==========
async def obtener_siguiente_key():
    async with _vt_lock:
        if not VT_API_KEYS:
            return None
        key = VT_API_KEYS[state.bot.vt_key_index]
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
        state.bot.vt_key_index = (state.bot.vt_key_index + 1) % len(VT_API_KEYS)
        return key

def obtener_siguiente_se_key():
    if not SE_API_KEYS_PAIRS:
        return None
    pair = SE_API_KEYS_PAIRS[state.bot.se_key_index]
    state.bot.se_key_index = (state.bot.se_key_index + 1) % len(SE_API_KEYS_PAIRS)
    return pair

def registrar_uso_se(api_key):
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

# ========== ENVÍO DE LOGS CON BOTONES ==========
async def enviar_log_guild(guild_id, tipo, valor, detalles, usuario, url_vt=None, elemento_id=None):
    config = obtener_config_guild(guild_id)
    log_channel_id = config["log_channel_id"]
    if log_channel_id is None:
        return
    channel = state.bot.get_channel(log_channel_id)
    if channel is None:
        return
    embed = discord.Embed(
        title=f"{EMOJI_WARNING} Amenaza Detectada",
        description=f"**{tipo}** analizado resultó **malicioso**",
        color=discord.Color.red()
    )
    embed.add_field(name=f"{EMOJI_FINGERPRINT} Valor", value=f"`{valor}`", inline=False)
    embed.add_field(name=f"{EMOJI_GUARDIAN} Usuario", value=usuario.mention, inline=True)
    embed.add_field(name=f"{EMOJI_SHIELD} Detalles", value=detalles, inline=True)
    if url_vt:
        embed.add_field(name=f"{EMOJI_LINK} VirusTotal", value=f"[Ver informe]({url_vt})", inline=False)
    embed.set_footer(text=f"ID: {usuario.id} • {time.strftime('%Y-%m-%d %H:%M:%S')}")
    view = LogActionView(guild_id, usuario.id, elemento_id=elemento_id)
    await channel.send(embed=embed, view=view)

# ========== ANÁLISIS URL ==========
async def analizar_url(url, guild_id=None, mensaje_original=None, guardar_cache=True):
    log.debug(f"VT URL → {url}")
    key = await obtener_siguiente_key()
    if not key:
        log.debug(f"VT URL ERROR → no hay keys disponibles")
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}
    try:
        async with state.bot.session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}) as resp:
            if resp.status == 200:
                data = await resp.json()
                scan_id = data["data"]["id"]
                for _ in range(3):
                    await asyncio.sleep(10)
                    async with state.bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers) as resp2:
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            if analysis["data"]["attributes"]["status"] == "completed":
                                return await _procesar_resultado_vt(analysis, "url", url, guild_id, mensaje_original, guardar_cache)
                log.debug(f"VT URL TIMEOUT → {url}")
                await _finalizar_error(guild_id, "url", url)
                return "error", discord.Embed(title="Error en análisis", description="El análisis no se completó a tiempo.", color=discord.Color.red()), 0
            else:
                log.debug(f"VT URL ERROR → status={resp.status} url={url}")
                await _finalizar_error(guild_id, "url", url)
                return "error", discord.Embed(title="Error al analizar URL", description="VirusTotal no procesó la solicitud", color=discord.Color.red()), 0
    except Exception as e:
        log.debug(f"VT URL EXCEPTION → {url}: {e}")
        await _finalizar_error(guild_id, "url", url)
        return "error", discord.Embed(title="Error de conexión", description="No se pudo contactar con VirusTotal", color=discord.Color.red()), 0

# ========== ANÁLISIS HASH ==========
async def analizar_hash(hash_valor, guild_id=None, mensaje_original=None, guardar_cache=True):
    log.debug(f"VT HASH → {hash_valor}")
    if not es_hash_valido(hash_valor):
        log.debug(f"VT HASH INVALIDO → {hash_valor}")
        await update_stats(guild_id, "error")
        return "error", discord.Embed(title=f"{EMOJI_INCORRECTO} Hash inválido", description=f"`{hash_valor}` no es un hash MD5, SHA-1 o SHA-256 válido.", color=discord.Color.red()), 0
    key = await obtener_siguiente_key()
    if not key:
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}
    try:
        async with state.bot.session.get(f"https://www.virustotal.com/api/v3/files/{hash_valor}", headers=headers) as resp:
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
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Hash Malicioso Detectado", description=f"**{mal}** antivirus lo identificaron", color=discord.Color.orange())
                    embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                    embed.add_field(name="Detectado por", value=f"`{top_text}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        await guardar_analisis_db(f"hash:{hash_valor}", "hash", "malicioso", embed, mal)
                        set_cache_mem(f"hash:{hash_valor}", "malicioso", embed, mal)
                    return "malicioso", embed, mal
                else:
                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} Hash Seguro", description="No se encontraron amenazas", color=discord.Color.green())
                    embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        await guardar_analisis_db(f"hash:{hash_valor}", "hash", "seguro", embed, 0)
                        set_cache_mem(f"hash:{hash_valor}", "seguro", embed, 0)
                    await update_stats(guild_id, "seguro")
                    return "seguro", embed, 0
            else:
                await update_stats(guild_id, "error")
                embed = discord.Embed(title="Hash no encontrado", description="No existe en VirusTotal", color=discord.Color.red())
                if guardar_cache:
                    await guardar_analisis_db(f"hash:{hash_valor}", "hash", "error", embed, 0)
                    set_cache_mem(f"hash:{hash_valor}", "error", embed, 0)
                return "error", embed, 0
    except Exception as e:
        print(f"Error en analizar_hash: {e}")
        await update_stats(guild_id, "error")
        embed = discord.Embed(title="Error", description="No se pudo consultar el hash", color=discord.Color.red())
        if guardar_cache:
            await guardar_analisis_db(f"hash:{hash_valor}", "hash", "error", embed, 0)
            set_cache_mem(f"hash:{hash_valor}", "error", embed, 0)
        return "error", embed, 0

# ========== ANÁLISIS IP ==========
async def analizar_ip(ip, guild_id=None, mensaje_original=None, guardar_cache=True):
    log.debug(f"VT IP → {ip}")
    key = await obtener_siguiente_key()
    if not key:
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}
    try:
        async with state.bot.session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers) as resp:
            if resp.status == 200:
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
                        set_cache_mem(f"ip:{ip}", "malicioso", embed, mal)
                    return "malicioso", embed, mal
                else:
                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} IP Segura", description="No se encontraron reportes", color=discord.Color.green())
                    embed.add_field(name="IP", value=f"`{ip}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        await guardar_analisis_db(f"ip:{ip}", "ip", "seguro", embed, 0)
                        set_cache_mem(f"ip:{ip}", "seguro", embed, 0)
                    await update_stats(guild_id, "seguro")
                    return "seguro", embed, 0
            else:
                await update_stats(guild_id, "error")
                return "error", discord.Embed(title="IP no encontrada", description="No se pudo analizar la IP", color=discord.Color.red()), 0
    except Exception as e:
        print(f"Error en analizar_ip: {e}")
        await update_stats(guild_id, "error")
        return "error", discord.Embed(title="Error", description="No se pudo contactar con VirusTotal", color=discord.Color.red()), 0

# ========== ANÁLISIS ARCHIVO ==========
async def analizar_archivo(archivo, file_bytes=None, file_hash=None, guild_id=None, mensaje_original=None, guardar_cache=True):
    log.debug(f"VT FILE → {archivo.filename} hash={file_hash}")
    if file_bytes is None:
        try:
            async with state.bot.session.get(archivo.url) as resp:
                if resp.status != 200:
                    await update_stats(guild_id, "error")
                    return "error", discord.Embed(title="Error al descargar archivo", description="No se pudo obtener el archivo", color=discord.Color.red()), 0
                file_bytes = await resp.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
        except Exception as e:
            await update_stats(guild_id, "error")
            return "error", discord.Embed(title="Error", description="Error al descargar el archivo", color=discord.Color.red()), 0

    if archivo.size > MAX_FILE_SIZE:
        await update_stats(guild_id, "error")
        embed = discord.Embed(title="Archivo demasiado grande", description=f"{EMOJI_FILE} `{archivo.filename}` excede 32 MB", color=discord.Color.red())
        return "error", embed, 0

    key = await obtener_siguiente_key()
    if not key:
        return "error", discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red()), 0
    headers = {"x-apikey": key}
    try:
        data = aiohttp.FormData()
        data.add_field('file', file_bytes, filename=archivo.filename)
        async with state.bot.session.post("https://www.virustotal.com/api/v3/files", headers=headers, data=data) as resp:
            if resp.status == 200:
                result_json = await resp.json()
                scan_id = result_json["data"]["id"]
                log.info(f"VT file uploaded, scan_id={scan_id}, waiting for analysis...")
                for i in range(10):
                    await asyncio.sleep(15)
                    log.info(f"VT polling attempt {i+1}/10 for scan_id={scan_id}")
                    async with state.bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers) as resp2:
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            status = analysis["data"]["attributes"]["status"]
                            log.info(f"VT analysis status: {status}")
                            if status == "completed":
                                return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache)
                            elif status == "queued":
                                log.info("VT still queued, continuing...")
                log.error("VT file analysis timed out after 10 attempts (150s)")
                await update_stats(guild_id, "error")
                return "error", discord.Embed(title="Error en análisis", description="El análisis tardó más de lo esperado. Intenta de nuevo.", color=discord.Color.red()), 0
            else:
                await update_stats(guild_id, "error")
                return "error", discord.Embed(title="Error al subir archivo", description="VirusTotal rechazó el archivo", color=discord.Color.red()), 0
    except Exception as e:
        print(f"Error en analizar_archivo: {e}")
        await update_stats(guild_id, "error")
        return "error", discord.Embed(title="Error", description="No se pudo analizar el archivo", color=discord.Color.red()), 0

# ========== PIPELINE INTERNO ==========
async def _procesar_resultado_vt(analysis, tipo, valor, guild_id, mensaje_original, guardar_cache):
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    clave = f"{tipo}:{valor}"
    log.debug(f"VT RESULT → {tipo}={valor} mal={mal} harmless={stats.get('harmless',0)} undetected={stats.get('undetected',0)}")
    encoded = urllib.parse.quote_plus(valor)
    vt_link = f"https://www.virustotal.com/gui/home/url?url={encoded}"

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

    if guardar_cache:
        await guardar_analisis_db(clave, tipo, tipo_str, embed, mal)
        set_cache_mem(clave, tipo_str, embed, mal)
    await update_stats(guild_id, tipo_str)
    return tipo_str, embed, mal

async def _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache):
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    clave = f"filehash:{file_hash}"
    log.debug(f"VT FILE RESULT → {archivo.filename} hash={file_hash} mal={mal}")

    if mal > 0:
        await _on_threat_found("Archivo", archivo.filename, mal, guild_id, mensaje_original, None, elemento_id=f"filehash:{file_hash}")
        embed = discord.Embed(title=f"{EMOJI_WARNING} Archivo Malicioso Detectado", description=f"**{mal}** antivirus detectaron {EMOJI_FILE} `{archivo.filename}`", color=discord.Color.orange())
        if guardar_cache:
            await guardar_analisis_db(clave, "file", "malicioso", embed, mal)
            set_cache_mem(clave, "malicioso", embed, mal)
            await guardar_metadatos_hash(f"file:{archivo.filename}:{archivo.size}", file_hash)
        await update_stats(guild_id, "malicioso")
        return "malicioso", embed, mal
    else:
        embed = discord.Embed(title=f"{EMOJI_CORRECTO} Archivo Seguro", description=f"{EMOJI_FILE} `{archivo.filename}` parece limpio (0 detecciones)", color=discord.Color.green())
        if guardar_cache:
            await guardar_analisis_db(clave, "file", "seguro", embed, 0)
            set_cache_mem(clave, "seguro", embed, 0)
            await guardar_metadatos_hash(f"file:{archivo.filename}:{archivo.size}", file_hash)
        await update_stats(guild_id, "seguro")
        return "seguro", embed, 0

async def _on_threat_found(tipo_str, valor, mal, guild_id, mensaje_original, vt_link=None, results=None, guardar_cache=True, elemento_id=None):
    if guild_id:
        await update_stats(guild_id, "malicioso")
    if mensaje_original and guild_id:
        if elemento_id:
            eid = elemento_id
        else:
            eid = f"url:{valor}" if tipo_str in ("URL", "url") else f"hash:{valor}" if tipo_str == "hash" else f"ip:{valor}"
        await registrar_infraccion(guild_id, mensaje_original.author.id, eid)
        if vt_link:
            await enviar_log_guild(guild_id, tipo_str, valor, f"{mal} detecciones", mensaje_original.author, vt_link, elemento_id=eid)
        else:
            await enviar_log_guild(guild_id, tipo_str, valor, f"{mal} detecciones", mensaje_original.author, elemento_id=eid)
        config = obtener_config_guild(guild_id)
        if config["strict_mode"]:
            try:
                await mensaje_original.delete()
            except Exception:
                pass

async def _finalizar_error(guild_id, tipo, valor):
    await update_stats(guild_id, "error")
    clave = f"{tipo}:{valor}"
    embed = discord.Embed(title="Error", description="No se pudo completar el análisis", color=discord.Color.red())
    await guardar_analisis_db(clave, tipo, "error", embed, 0)
    set_cache_mem(clave, "error", embed, 0)
