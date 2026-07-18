import re
import aiohttp
import time
import asyncio
import hashlib
import json
import urllib.parse
import base64
from typing import Optional
import logging
import discord
from discord.ext import commands
from core.config import MAX_IMAGE_SIZE, MAX_FILE_SIZE, EMOJI_CORRECTO, EMOJI_INCORRECTO, EMOJI_ERROR, EMOJI_WARNING, EMOJI_WHITELIST, EMOJI_LOADING, EMOJI_LINK, EMOJI_FILE, EMOJI_COOLDOWN, EMOJI_REPLY, EMOJI_NSFW, ANTISPAM_ANALYSIS_PER_HOUR, ANTISPAM_COOLDOWN
from core.utils import safe_remove_loading, safe_add_reaction, safe_send, dominio_en_whitelist, url_es_imagen, es_imagen, expandir_url, tiene_doble_extension, es_url_segura, descargar_url_segura, normalizar_url, check_vt_user_limit
from core.cache import get_from_cache_mem, set_cache_mem
from core.database import obtener_analisis_db, guardar_metadatos_hash, obtener_hash_desde_metadatos
from api.virustotal import analizar_url, analizar_archivo, enviar_log_guild
from api.sightengine import analizar_imagen_multimodelo
from core.guild_config import obtener_config_guild, registrar_infraccion, update_stats
from core.state import ANALYSIS_SEMAPHORE

log = logging.getLogger("handler")

async def _procesar_imagen(
    bot: commands.Bot,
    message: discord.Message,
    img: discord.Attachment,
    guild_id: int,
) -> tuple[str, str, dict, str]:
    log.debug(f"Imagen: {img.filename} ({img.size} bytes)")
    if img.size > MAX_IMAGE_SIZE:
        return (img.filename, "error", {"error": "too_large"}, "")
    try:
        async with bot._download_sem:
            async with bot.session.get(img.url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    return (img.filename, "error", {}, "")
                img_data = await resp.read()
            if len(img_data) > MAX_IMAGE_SIZE:
                return (img.filename, "error", {"error": "too_large"}, "")
            content_hash = hashlib.sha256(img_data).hexdigest()
            async with ANALYSIS_SEMAPHORE:
                is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
            if not models.get("error"):
                await update_stats(guild_id, "nsfw" if is_nsfw else "seguro")
            if is_nsfw and guild_id:
                await registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
            return (img.filename, "nsfw" if is_nsfw else "seguro", models, content_hash)
    except Exception:
        return (img.filename, "error", {}, "")

async def _procesar_archivo(
    bot: commands.Bot,
    message: discord.Message,
    archivo: discord.Attachment,
    guild_id: int,
) -> tuple[str, str, int, str, str]:
    log.debug(f"Archivo: {archivo.filename} ({archivo.size} bytes)")
    doble_ext = tiene_doble_extension(archivo.filename)
    wm = ""
    if doble_ext:
        await safe_add_reaction(message, EMOJI_WARNING)
    if archivo.size > MAX_FILE_SIZE:
        return (archivo.filename, "error", 0, "", "")
    try:
        async with bot._download_sem:
            async with bot.session.get(archivo.url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    return (archivo.filename, "error", 0, "", "")
                file_data = await resp.read()
                if len(file_data) > MAX_FILE_SIZE:
                    return (archivo.filename, "error", 0, "", "")
            file_hash = hashlib.sha256(file_data).hexdigest()
            content_type = resp.headers.get('Content-Type', '')
            ct_lower = content_type.lower()
            if archivo.filename.lower().endswith(('.jpg', '.jpeg')) and ct_lower not in ('image/jpeg', 'image/jpg'):
                wm = f"Extensión .jpg pero tipo real {content_type}"
            elif archivo.filename.lower().endswith('.png') and ct_lower != 'image/png':
                wm = f"Extensión .png pero tipo real {content_type}"
    except Exception:
        return (archivo.filename, "error", 0, "", "")
    tipo, embed, mal = await get_from_cache_mem(f"filehash:{file_hash}")
    if embed is None:
        tipo, embed, mal = await obtener_analisis_db(f"filehash:{file_hash}")
        if embed is not None:
            await set_cache_mem(f"filehash:{file_hash}", tipo, embed, mal)
    if embed is not None:
        if tipo == "malicioso":
            await registrar_infraccion(guild_id, message.author.id, f"filehash:{file_hash}")
        return (archivo.filename, tipo, mal, file_hash, wm)
    async with ANALYSIS_SEMAPHORE:
        tipo, embed, mal = await analizar_archivo(archivo, file_bytes=file_data, file_hash=file_hash, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
    return (archivo.filename, tipo, mal, file_hash, wm)

async def _procesar_adjuntos(
    bot: commands.Bot,
    message: discord.Message,
    guild_id: int,
    silent_mode: bool,
    strict_mode: bool,
    log_channel_id: Optional[int],
) -> None:
    adjuntos = message.attachments[:5]
    omitidos = max(0, len(message.attachments) - 5)
    imagenes = [a for a in adjuntos if es_imagen(a)]
    otros = [a for a in adjuntos if not es_imagen(a)]
    omit_msg = f", {omitidos} omitidos" if omitidos else ""
    log.debug(f"Adjuntos: {len(imagenes)} imágenes, {len(otros)} archivos{omit_msg}")

    await safe_add_reaction(message, EMOJI_LOADING)
    try:
        if imagenes:
            tareas_img = [_procesar_imagen(bot, message, img, guild_id) for img in imagenes]
            resultados_img = await asyncio.gather(*tareas_img)
        else:
            resultados_img = []

        if otros:
            tareas_arch = [_procesar_archivo(bot, message, archivo, guild_id) for archivo in otros]
            resultados_arch = await asyncio.gather(*tareas_arch)
        else:
            resultados_arch = []
    finally:
        await safe_remove_loading(bot, message)

    resultados_img = [r for r in resultados_img if isinstance(r, tuple)]
    resultados_arch = [r for r in resultados_arch if isinstance(r, tuple)]
    total = len(resultados_img) + len(resultados_arch)
    if total == 0:
        return
    maliciosos = sum(1 for _, t, _, _, _ in resultados_arch if t == "malicioso")
    nsfw = sum(1 for _, t, _, _ in resultados_img if t == "nsfw")
    seguros = sum(1 for _, t, _, _ in resultados_img if t == "seguro") + sum(1 for _, t, _, _, _ in resultados_arch if t == "seguro")
    errores = total - maliciosos - nsfw - seguros
    has_doble_ext = any(tiene_doble_extension(a.filename) for a in adjuntos)

    if maliciosos:
        color = discord.Color.orange()
        titulo = f"{EMOJI_WARNING} ¡Amenazas detectadas en archivos adjuntos!"
    elif nsfw:
        color = discord.Color.orange()
        titulo = f"{EMOJI_NSFW} Contenido NSFW detectado"
    elif errores:
        color = discord.Color.red()
        titulo = f"{EMOJI_ERROR} Análisis completado con errores"
    else:
        color = discord.Color.green()
        titulo = f"{EMOJI_CORRECTO} Todos los archivos son seguros"

    descripcion = f"**{total}** archivo(s) analizado(s) en el mensaje de {message.author.mention}:\n"
    descripcion += f"{EMOJI_CORRECTO} Seguros: **{seguros}**\n"
    if nsfw:
        descripcion += f"{EMOJI_NSFW} NSFW: **{nsfw}**\n"
    if maliciosos:
        descripcion += f"{EMOJI_WARNING} Maliciosos: **{maliciosos}**\n"
    descripcion += f"{EMOJI_ERROR} Errores: **{errores}**"
    if omitidos:
        descripcion += f"\n{EMOJI_COOLDOWN} **{omitidos}** archivo(s) omitido(s) (límite 5 por mensaje)"
    embed_resumen = discord.Embed(title=titulo, description=descripcion, color=color)

    campo = ""
    for filename, tipo, models, _ in resultados_img:
        if tipo == "nsfw":
            detalles_img: list[str] = []
            if models.get('nudity', 0.0) >= 0.5: detalles_img.append(f"Desnudez {models['nudity']*100:.0f}%")
            if models.get('weapon', 0.0) >= 0.5: detalles_img.append(f"Armas {models['weapon']*100:.0f}%")
            if models.get('offensive', 0.0) >= 0.7: detalles_img.append(f"Ofensivo {models['offensive']*100:.0f}%")
            if models.get('alcohol', 0.0) >= 0.7: detalles_img.append(f"Alcohol {models['alcohol']*100:.0f}%")
            detalle_str = ", ".join(detalles_img) if detalles_img else "Contenido inapropiado"
            campo += f"{EMOJI_NSFW} `{filename}` (NSFW: {detalle_str})\n"
        elif tipo == "seguro":
            campo += f"{EMOJI_CORRECTO} `{filename}` (imagen)\n"
        else:
            campo += f"{EMOJI_ERROR} `{filename}` (error)\n"

    for filename, tipo, mal, file_hash, wm in resultados_arch:
        if tipo == "malicioso":
            campo += f"{EMOJI_WARNING} `{filename}` ({mal} detecciones)\n"
        elif tipo == "seguro":
            campo += f"{EMOJI_CORRECTO} `{filename}`\n"
        else:
            campo += f"{EMOJI_ERROR} `{filename}`\n"

    embed_resumen.add_field(name="Resultados", value=campo[:1024], inline=False)

    if log_channel_id:
        for filename, tipo, models, content_hash in resultados_img:
            if tipo == "nsfw" and content_hash:
                await enviar_log_guild(guild_id, "Imagen NSFW (múltiples)", filename, "Detectado en análisis múltiple", message.author, elemento_id=f"nsfw:{content_hash}", es_nsfw=True)
        for filename, tipo, mal, file_hash, wm in resultados_arch:
            if tipo == "malicioso" and file_hash:
                await enviar_log_guild(guild_id, "Archivo (múltiples)", filename, f"{mal} detecciones", message.author, elemento_id=f"filehash:{file_hash}")

    if maliciosos or nsfw or omitidos or not silent_mode:
        await safe_send(message, embed_resumen, reference=message)

    if maliciosos:
        await safe_add_reaction(message, EMOJI_WARNING)
    elif nsfw:
        await safe_add_reaction(message, EMOJI_NSFW)
    elif errores:
        await safe_add_reaction(message, EMOJI_ERROR)
    else:
        await safe_add_reaction(message, EMOJI_CORRECTO)

    if (maliciosos or nsfw or has_doble_ext) and strict_mode:
        try:
            await message.delete()
        except (discord.errors.Forbidden, discord.errors.NotFound):
            pass


async def _procesar_adjuntos_si_hay(
    bot: commands.Bot,
    message: discord.Message,
    guild_id: int,
    silent_mode: bool,
    strict_mode: bool,
    log_channel_id: Optional[int],
) -> None:
    if message.attachments:
        await _procesar_adjuntos(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)

def _limpiar_url(url: str) -> str:
    while url and url[-1] in ')]}>.,;:':
        url = url[:-1]
    return url


async def procesar_analisis(bot: commands.Bot, message: discord.Message) -> None:
    if len(message.content) > 5000:
        message.content = message.content[:5000]

    if message.guild is None:
        return
    guild_id = message.guild.id
    config = await obtener_config_guild(guild_id)
    silent_mode = config["silent_mode"]
    strict_mode = config["strict_mode"]
    log_channel_id = config["log_channel_id"]
    whitelist = config.get("whitelist", [])

    if not config.get("auto_scan_enabled", True):
        return

    url_pattern = r'https?://[^\s]+'
    urls = [_limpiar_url(u) for u in re.findall(url_pattern, message.content)]
    log.debug(f"Mensaje de {message.author} en guild={guild_id}: {len(urls)} URLs, {len(message.attachments)} adjuntos")

    if urls:
        todas_urls: list[str] = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            dominio = parsed.netloc.lower()
            if dominio.startswith("www."):
                dominio = dominio[4:]
            if not dominio_en_whitelist(dominio, whitelist):
                todas_urls.append(url)
            else:
                await safe_add_reaction(message, EMOJI_WHITELIST)

        if not todas_urls:
            if not silent_mode:
                try:
                    await message.reply(f"{EMOJI_WHITELIST} **Dominio(s) en whitelist.** No se requiere análisis.", mention_author=False)
                except (discord.errors.Forbidden, discord.errors.NotFound):
                    pass
            await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
            return

        log.debug(f"URLs tras whitelist: {len(todas_urls)} de {len(urls)}")

        ahora = time.time()
        user_id = message.author.id
        spam_key = (guild_id, user_id) if guild_id else user_id

        todas_en_cache = True
        for url in todas_urls:
            clave_check = f"url:{normalizar_url(url)}"
            _, embed_check, _ = await get_from_cache_mem(clave_check)
            if embed_check is None:
                _, embed_check, _ = await obtener_analisis_db(clave_check)
            if embed_check is None:
                todas_en_cache = False
                break

        bot.user_scan_history.setdefault(spam_key, [])
        bot.user_scan_history[spam_key] = [t for t in bot.user_scan_history[spam_key] if ahora - t < 3600]
        if len(bot.user_scan_history[spam_key]) >= ANTISPAM_ANALYSIS_PER_HOUR:
            await safe_add_reaction(message, EMOJI_COOLDOWN)
            await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
            return
        if spam_key in bot.antispam_scan and ahora - bot.antispam_scan[spam_key] < ANTISPAM_COOLDOWN:
            await safe_add_reaction(message, EMOJI_COOLDOWN)
            await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
            return

        if not todas_en_cache:
            bot.antispam_scan[spam_key] = ahora
            bot.user_scan_history[spam_key].append(ahora)

        if len(todas_urls) == 1:
            url = todas_urls[0]
            log.debug(f"URL única: {url}")
            if await url_es_imagen(url, bot):
                log.debug(f"URL es imagen → SSRF check + Sightengine")
                url_hash_key = hashlib.sha256(url.encode()).hexdigest()
                clave_meta_url = f"nsfw_url:{url_hash_key}"
                tipo_meta, embed_meta, _ = await get_from_cache_mem(clave_meta_url)
                cached_hash = None
                if embed_meta is not None:
                    try:
                        cached_hash = json.loads(tipo_meta).get("hash")
                    except Exception:
                        pass
                if not cached_hash:
                    cached_hash = await obtener_hash_desde_metadatos(clave_meta_url)
                if cached_hash:
                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(cached_hash, b"")
                    if from_cache:
                        if is_nsfw:
                            if guild_id:
                                await registrar_infraccion(guild_id, message.author.id, f"nsfw:{cached_hash}")
                            await safe_add_reaction(message, EMOJI_NSFW)
                            detectados: list[str] = []
                            if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                            if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                            if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                            if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                            detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                            embed = discord.Embed(title=f"{EMOJI_NSFW} Contenido Inapropiado Detectado", description=f"{detalles_str}", color=discord.Color.orange())
                            embed.add_field(name="Resultados", value=f"{EMOJI_NSFW} Imagen NSFW\n{detalles_str}", inline=False)
                            await safe_send(message, embed, reference=message)
                            if log_channel_id:
                                await enviar_log_guild(guild_id, "Imagen NSFW", url, detalles_str, message.author, elemento_id=f"nsfw:{cached_hash}", es_nsfw=True)
                            if strict_mode:
                                try:
                                    await message.delete()
                                except (discord.errors.Forbidden, discord.errors.NotFound):
                                    pass
                        else:
                            await safe_add_reaction(message, EMOJI_CORRECTO)
                            if not silent_mode:
                                embed = discord.Embed(title=f"{EMOJI_CORRECTO} Imagen Segura", description="No se detectó contenido inapropiado.", color=discord.Color.green())
                                embed.add_field(name="Resultados", value=f"{EMOJI_CORRECTO} Imagen segura", inline=False)
                                await safe_send(message, embed, reference=message)
                        await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                        return
                await safe_add_reaction(message, EMOJI_LOADING)
                try:
                    async with bot._download_sem:
                        img_data, error = await descargar_url_segura(bot, url, max_size=MAX_IMAGE_SIZE)
                    if error:
                        if error == "too_large":
                            await safe_add_reaction(message, EMOJI_ERROR)
                            if not silent_mode:
                                embed = discord.Embed(title=f"{EMOJI_ERROR} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                                await safe_send(message, embed, reference=message)
                        else:
                            await safe_add_reaction(message, EMOJI_ERROR)
                            await safe_send(message, discord.Embed(title=f"{EMOJI_ERROR} URL bloqueada", description=f"La URL apunta a una dirección interna: {error}", color=discord.Color.red()), reference=message)
                        await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                        return
                    content_hash = hashlib.sha256(img_data).hexdigest()
                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                    if not models.get("error"):
                        await update_stats(guild_id, "nsfw" if is_nsfw else "seguro")
                    dummy = discord.Embed(title="NSFW URL Meta")
                    await set_cache_mem(clave_meta_url, json.dumps({"hash": content_hash}), dummy, 0)
                    await guardar_metadatos_hash(clave_meta_url, content_hash)
                finally:
                    await safe_remove_loading(bot, message)

                if models.get("error") == "too_large":
                    await safe_add_reaction(message, EMOJI_ERROR)
                    if not silent_mode:
                        embed = discord.Embed(title=f"{EMOJI_ERROR} Imagen no analizada", description="Supera el límite de Sightengine", color=discord.Color.orange())
                        await safe_send(message, embed, reference=message)
                    await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                    return

                if is_nsfw:
                    if guild_id:
                        await registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                    await safe_add_reaction(message, EMOJI_NSFW)
                    detectados: list[str] = []
                    if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                    if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                    if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                    if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                    detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                    embed = discord.Embed(title=f"{EMOJI_NSFW} Contenido Inapropiado Detectado", description=f"{detalles_str}", color=discord.Color.orange())
                    embed.add_field(name="Resultados", value=f"{EMOJI_NSFW} Imagen NSFW\n{detalles_str}", inline=False)
                    await safe_send(message, embed, reference=message)
                    if log_channel_id:
                        await enviar_log_guild(guild_id, "Imagen NSFW", url, detalles_str, message.author, elemento_id=f"nsfw:{content_hash}", es_nsfw=True)
                    if strict_mode:
                        try:
                            await message.delete()
                        except (discord.errors.Forbidden, discord.errors.NotFound):
                            pass
                else:
                    await safe_add_reaction(message, EMOJI_CORRECTO)
                    if not silent_mode:
                        embed = discord.Embed(title=f"{EMOJI_CORRECTO} Imagen Segura", description="No se detectó contenido inapropiado.", color=discord.Color.green())
                        embed.add_field(name="Resultados", value=f"{EMOJI_CORRECTO} Imagen segura", inline=False)
                        await safe_send(message, embed, reference=message)
                await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                return
            else:
                url_original = url
                url = await expandir_url(bot, url)
                fue_expandida = url != url_original
                if fue_expandida:
                    parsed_exp = urllib.parse.urlparse(url)
                    dominio_exp = parsed_exp.netloc.lower()
                    if dominio_exp.startswith("www."):
                        dominio_exp = dominio_exp[4:]
                    if dominio_en_whitelist(dominio_exp, whitelist):
                        log.debug(f"URL expandida redirige a dominio en whitelist: {dominio_exp}")
                        await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                        return
                    log.debug(f"URL expandida: {url_original} → {url}")
                clave = f"url:{normalizar_url(url)}"
                tipo, embed, mal = await get_from_cache_mem(clave)
                if embed is not None:
                    log.debug(f"Cache HIT (RAM) para URL → resultado={tipo}")
                else:
                    tipo, embed, mal = await obtener_analisis_db(clave)
                    if embed is not None:
                        log.debug(f"Cache HIT (SQLite) para URL → resultado={tipo}")
                        await set_cache_mem(clave, tipo, embed, mal)
                    else:
                        log.debug(f"Cache MISS para URL → llamando VT")

                if embed is not None:
                    embed = embed.copy()
                    if fue_expandida and not any(f.name.endswith("Redirección") for f in embed.fields):
                        embed.add_field(name=f"{EMOJI_REPLY} Redirección", value=f"Original: `{url_original}`\nExpandida: `{url}`", inline=False)
                    if tipo == "malicioso":
                        await registrar_infraccion(guild_id, message.author.id, f"url:{url}")
                        await safe_send(message, embed, reference=message)
                        if log_channel_id:
                            await enviar_log_guild(guild_id, "URL", url, f"{mal} detecciones (cache)", message.author, elemento_id=f"url:{url}")
                        if strict_mode:
                            try:
                                await message.delete()
                            except (discord.errors.Forbidden, discord.errors.NotFound):
                                pass
                        await safe_add_reaction(message, EMOJI_WARNING)
                    elif tipo == "seguro":
                        if not silent_mode:
                            await safe_send(message, embed, reference=message)
                        await safe_add_reaction(message, EMOJI_CORRECTO)
                    else:
                        if not silent_mode:
                            await safe_send(message, embed, reference=message)
                        await safe_add_reaction(message, EMOJI_ERROR)
                    await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                    return

                if not await check_vt_user_limit(message.author.id):
                    await safe_add_reaction(message, EMOJI_ERROR)
                    embed_rl = discord.Embed(
                        title=f"{EMOJI_ERROR} Límite de análisis alcanzado",
                        description="Demasiadas solicitudes. Espera un momento e intenta de nuevo.",
                        color=discord.Color.red()
                    )
                    await safe_send(message, embed_rl, reference=message)
                    await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                    return

                await safe_add_reaction(message, EMOJI_LOADING)
                try:
                    tipo, embed, mal = await analizar_url(url, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                finally:
                    await safe_remove_loading(bot, message)

                if fue_expandida:
                    embed = embed.copy()
                    embed.add_field(name=f"{EMOJI_REPLY} Redirección", value=f"Original: `{url_original}`\nExpandida: `{url}`", inline=False)
                if tipo == "malicioso":
                    await safe_send(message, embed, reference=message)
                    await safe_add_reaction(message, EMOJI_WARNING)
                elif tipo == "seguro":
                    if not silent_mode:
                        await safe_send(message, embed, reference=message)
                    await safe_add_reaction(message, EMOJI_CORRECTO)
                else:
                    if not silent_mode:
                        await safe_send(message, embed, reference=message)
                    await safe_add_reaction(message, EMOJI_ERROR)
                await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
                return

        log.debug(f"Múltiples URLs ({len(todas_urls)})")
        await safe_add_reaction(message, EMOJI_LOADING)
        try:
            todas_urls = list(dict.fromkeys(todas_urls))[:5]

            async def _expandir_y_cache(url: str) -> Optional[tuple[str, str, str, discord.Embed, int, bool]]:
                url_original = url
                url_exp = await expandir_url(bot, url)
                fue_exp = url_exp != url_original
                if fue_exp:
                    parsed_exp = urllib.parse.urlparse(url_exp)
                    dominio_exp = parsed_exp.netloc.lower()
                    if dominio_exp.startswith("www."):
                        dominio_exp = dominio_exp[4:]
                    if dominio_en_whitelist(dominio_exp, whitelist):
                        return None
                clave = f"url:{normalizar_url(url_exp)}"
                tipo, embed, mal = await get_from_cache_mem(clave)
                if embed is None:
                    tipo, embed, mal = await obtener_analisis_db(clave)
                    if embed is not None:
                        await set_cache_mem(clave, tipo, embed, mal)
                return (url_original, url_exp, tipo, embed, mal, fue_exp)

            expandidos = await asyncio.gather(*[_expandir_y_cache(url) for url in todas_urls], return_exceptions=True)
            expandidos = [r for r in expandidos if isinstance(r, tuple)]

            resultados: list[tuple[str, str, str, int]] = []
            urls_api: list[tuple[str, str, bool]] = []
            for r in expandidos:
                url_original, url_exp, tipo, embed, mal, fue_exp = r
                if embed is not None:
                    resultados.append((url_original, url_exp, tipo, mal))
                else:
                    urls_api.append((url_original, url_exp, fue_exp))

            if urls_api:
                async def _api_url(url_original: str, url_exp: str, fue_exp: bool) -> tuple[str, str, str, int]:
                    if not await check_vt_user_limit(message.author.id):
                        return (url_original, url_exp, "error", 0)
                    async with ANALYSIS_SEMAPHORE:
                        tipo, embed, mal = await analizar_url(url_exp, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                    return (url_original, url_exp, tipo, mal)

                api_resultados = await asyncio.gather(*[_api_url(uo, ue, fe) for uo, ue, fe in urls_api], return_exceptions=True)
                for r in api_resultados:
                    if isinstance(r, tuple):
                        resultados.append(r)

            maliciosas = sum(1 for _, _, t, _ in resultados if t == "malicioso")
            seguras = sum(1 for _, _, t, _ in resultados if t == "seguro")
            errores = sum(1 for _, _, t, _ in resultados if t == "error")

            for url_orig, url_exp, tipo, mal in resultados:
                if tipo == "malicioso":
                    await registrar_infraccion(guild_id, message.author.id, f"url:{url_exp}")

            color = discord.Color.orange() if maliciosas else (discord.Color.red() if errores else discord.Color.green())
            titulo = f"{EMOJI_WARNING} Amenazas detectadas" if maliciosas else (f"{EMOJI_ERROR} Errores en el análisis" if errores else f"{EMOJI_CORRECTO} Todos los enlaces son seguros")
            descripcion = f"Se analizaron **{len(todas_urls)}** enlace(s) en el mensaje de {message.author.mention}:\n" \
                          f"{EMOJI_CORRECTO} Seguros: **{seguras}**\n{EMOJI_WARNING} Maliciosos: **{maliciosas}**\n{EMOJI_ERROR} Errores: **{errores}**"
            embed_resumen = discord.Embed(title=titulo, description=descripcion, color=color)
            valor_campo = ""
            for url_orig, url_exp, tipo, _ in resultados:
                icono = EMOJI_WARNING if tipo == "malicioso" else (EMOJI_CORRECTO if tipo == "seguro" else EMOJI_ERROR)
                txt = f"{icono} `{url_orig}`"
                if url_orig != url_exp:
                    txt += f"\n{EMOJI_REPLY} `{url_exp}`"
                valor_campo += txt + "\n"
            embed_resumen.add_field(name="Resultados", value=valor_campo[:1024], inline=False)
            if maliciosas:
                maliciosas_str = ""
                for url_orig, url_exp, tipo, _ in resultados:
                    if tipo == "malicioso":
                        url_id = base64.urlsafe_b64encode(url_exp.encode()).decode().rstrip("=")
                        vt_link = f"https://www.virustotal.com/gui/url/{url_id}"
                        url_mostrar = url_orig if url_orig == url_exp else f"{url_orig} → {url_exp}"
                        maliciosas_str += f"• `{url_mostrar}` {EMOJI_LINK} [Ver informe]({vt_link})\n"
                embed_resumen.add_field(name=f"{EMOJI_WARNING} Enlaces maliciosos", value=maliciosas_str[:1024], inline=False)
            if maliciosas and log_channel_id:
                for url_orig, url_exp, tipo, _ in resultados:
                    if tipo == "malicioso":
                        await enviar_log_guild(guild_id, "URL (múltiples)", url_orig, "Detectado en análisis múltiple", message.author, elemento_id=f"url:{url_exp}")
            if maliciosas or not silent_mode:
                await safe_send(message, embed_resumen, reference=message)
        finally:
            await safe_remove_loading(bot, message)
        if maliciosas:
            await safe_add_reaction(message, EMOJI_WARNING)
        elif errores:
            await safe_add_reaction(message, EMOJI_ERROR)
        else:
            await safe_add_reaction(message, EMOJI_CORRECTO)
        if maliciosas and strict_mode:
            try:
                await message.delete()
            except (discord.errors.Forbidden, discord.errors.NotFound):
                pass
        await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
        return

    await _procesar_adjuntos_si_hay(bot, message, guild_id, silent_mode, strict_mode, log_channel_id)
