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

async def _construir_embed_unificado(
    message: discord.Message,
    url_results: list[tuple],       # (url_mostrar, tipo, mal, vt_link | None)
    img_url_results: list[tuple],   # (url, tipo, detalles_str)
    img_results: list[tuple],       # (filename, tipo, models, content_hash)
    arch_results: list[tuple],      # (filename, tipo, mal, file_hash, wm)
    omitidos: int,
    url_fue_expandida: bool = False,
    url_original: str = "",
    url_expandida: str = "",
) -> discord.Embed:
    """Construye UN embed con toda la información disponible (URLs + imágenes + archivos)."""
    total_urls = len(url_results) + len(img_url_results)
    total_imgs = len(img_results)
    total_archs = len(arch_results)
    total = total_urls + total_imgs + total_archs

    has_malicious_url = any(t == "malicioso" for _, t, _, _ in url_results)
    has_nsfw_url = any(t == "nsfw" for _, t, _ in img_url_results)
    has_malicious_file = any(t == "malicioso" for _, t, _, _, _ in arch_results)
    has_nsfw_img = any(t == "nsfw" for _, t, _, _ in img_results)
    has_errors_url = any(t == "error" for _, t, _, _ in url_results)
    has_errors_img = any(t == "error" for _, t, _ in img_url_results) or any(t == "error" for _, t, _, _ in img_results)
    has_errors_file = any(t == "error" for _, t, _, _, _ in arch_results)

    is_threat = has_malicious_url or has_nsfw_url or has_malicious_file or has_nsfw_img
    has_errors = has_errors_url or has_errors_img or has_errors_file

    seguros = total - (
        sum(1 for _, t, _, _ in url_results if t == "malicioso") +
        sum(1 for _, t, _ in img_url_results if t != "seguro") +
        sum(1 for _, t, _, _ in img_results if t != "seguro") +
        sum(1 for _, t, _, _, _ in arch_results if t != "seguro") +
        has_errors
    )

    mal_count = sum(1 for _, t, _, _ in url_results if t == "malicioso") + sum(1 for _, t, _, _, _ in arch_results if t == "malicioso")
    nsfw_count = sum(1 for _, t, _ in img_url_results if t == "nsfw") + sum(1 for _, t, _, _ in img_results if t == "nsfw")
    err_count = sum(1 for _, t, _, _ in url_results if t == "error") + sum(1 for _, t, _ in img_url_results if t == "error") + sum(1 for _, t, _, _ in img_results if t == "error") + sum(1 for _, t, _, _, _ in arch_results if t == "error")

    # Determinar título y color
    if is_threat:
        if has_malicious_url or has_malicious_file:
            color = discord.Color.orange()
            titulo = f"{EMOJI_WARNING} Amenazas detectadas"
        else:
            color = discord.Color.orange()
            titulo = f"{EMOJI_NSFW} Contenido NSFW detectado"
    elif has_errors:
        color = discord.Color.red()
        titulo = f"{EMOJI_ERROR} Análisis completado con errores"
    else:
        color = discord.Color.green()
        titulo = f"{EMOJI_CORRECTO} Todos los elementos son seguros"

    # Descripción
    desc = f"**{total}** elemento(s) analizado(s) en el mensaje de {message.author.mention}:\n"
    desc += f"{EMOJI_CORRECTO} Seguros: **{seguros}**\n"
    if mal_count:
        desc += f"{EMOJI_WARNING} Maliciosos: **{mal_count}**\n"
    if nsfw_count:
        desc += f"{EMOJI_NSFW} NSFW: **{nsfw_count}**\n"
    if err_count:
        desc += f"{EMOJI_ERROR} Errores: **{err_count}**\n"
    if omitidos:
        desc += f"{EMOJI_COOLDOWN} **{omitidos}** archivo(s) omitido(s) (límite 5 por mensaje)"

    embed = discord.Embed(title=titulo, description=desc, color=color)

    # --- Campo: URLs ---
    if url_results:
        valor_urls = ""
        for url_mostrar, tipo, mal, vt_link in url_results:
            icono = EMOJI_WARNING if tipo == "malicioso" else (EMOJI_CORRECTO if tipo == "seguro" else EMOJI_ERROR)
            valor_urls += f"{icono} `{url_mostrar}`"
            if vt_link:
                valor_urls += f" {EMOJI_LINK}[VT]({vt_link})"
            valor_urls += "\n"
        embed.add_field(name=f"{EMOJI_LINK} URLs", value=valor_urls[:1024], inline=False)

    # --- Campo: Imágenes (URLs) ---
    if img_url_results:
        valor_img_urls = ""
        for url, tipo, detalles in img_url_results:
            icono = EMOJI_NSFW if tipo == "nsfw" else (EMOJI_CORRECTO if tipo == "seguro" else EMOJI_ERROR)
            valor_img_urls += f"{icono} `{url}`"
            if detalles:
                valor_img_urls += f" ({detalles})"
            valor_img_urls += "\n"
        embed.add_field(name=f"{EMOJI_NSFW} Imágenes (URL)", value=valor_img_urls[:1024], inline=False)

    # --- Campo: Imágenes (adjuntas) ---
    if img_results:
        valor_imgs = ""
        for filename, tipo, models, _ in img_results:
            if tipo == "nsfw":
                detalles: list[str] = []
                if models.get('nudity', 0.0) >= 0.5: detalles.append(f"Desnudez {models['nudity']*100:.0f}%")
                if models.get('weapon', 0.0) >= 0.5: detalles.append(f"Armas {models['weapon']*100:.0f}%")
                if models.get('offensive', 0.0) >= 0.7: detalles.append(f"Ofensivo {models['offensive']*100:.0f}%")
                if models.get('alcohol', 0.0) >= 0.7: detalles.append(f"Alcohol {models['alcohol']*100:.0f}%")
                detalle_str = ", ".join(detalles) if detalles else "Contenido inapropiado"
                valor_imgs += f"{EMOJI_NSFW} `{filename}` (NSFW: {detalle_str})\n"
            elif tipo == "seguro":
                valor_imgs += f"{EMOJI_CORRECTO} `{filename}` (imagen)\n"
            else:
                valor_imgs += f"{EMOJI_ERROR} `{filename}` (error)\n"
        embed.add_field(name=f"{EMOJI_FILE} Imágenes (adjuntas)", value=valor_imgs[:1024], inline=False)

    # --- Campo: Archivos ---
    if arch_results:
        valor_archs = ""
        for filename, tipo, mal, _, wm in arch_results:
            if tipo == "malicioso":
                valor_archs += f"{EMOJI_WARNING} `{filename}` ({mal} detecciones)"
            elif tipo == "seguro":
                valor_archs += f"{EMOJI_CORRECTO} `{filename}`"
            else:
                valor_archs += f"{EMOJI_ERROR} `{filename}` (error)"
            if wm:
                valor_archs += f"\n{EMOJI_REPLY} {wm}"
            valor_archs += "\n"
        embed.add_field(name=f"{EMOJI_FILE} Archivos", value=valor_archs[:1024], inline=False)

    # --- Campo: Redirección (single URL) ---
    if url_fue_expandida:
        embed.add_field(name=f"{EMOJI_REPLY} Redirección", value=f"Original: `{url_original}`\nExpandida: `{url_expandida}`", inline=False)

    # --- Campo: Enlaces maliciosos (VT links) ---
    mal_urls = [(url, vt) for url, tipo, mal, vt in url_results if tipo == "malicioso" and vt]
    if mal_urls:
        valor_mal = ""
        for url, vt_link in mal_urls:
            valor_mal += f"• `{url}` {EMOJI_LINK}[Ver informe]({vt_link})\n"
        embed.add_field(name=f"{EMOJI_WARNING} Enlaces maliciosos", value=valor_mal[:1024], inline=False)

    return embed


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

async def _analizar_adjuntos(
    bot: commands.Bot,
    message: discord.Message,
    guild_id: int,
) -> tuple[list, list, int]:
    """Analiza adjuntos y retorna (img_results, arch_results, omitidos) sin enviar nada."""
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
    return resultados_img, resultados_arch, omitidos


async def _analizar_adjuntos_si_hay(
    bot: commands.Bot,
    message: discord.Message,
    guild_id: int,
) -> tuple[list, list, int]:
    if message.attachments:
        return await _analizar_adjuntos(bot, message, guild_id)
    return [], [], 0

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

    # --- Colectores de resultados para el embed unificado ---
    url_results: list[tuple[str, str, int, str | None]] = []   # (url_mostrar, tipo, mal, vt_link)
    url_logged_internally: list[bool] = []                       # True si VT ya envió log/strict (analizar_url llamó _on_threat_found)
    img_url_results: list[tuple[str, str, str]] = []            # (url, tipo, detalles_str)
    img_results: list[tuple[str, str, dict, str]] = []          # (filename, tipo, models, content_hash)
    arch_results: list[tuple[str, str, int, str, str]] = []     # (filename, tipo, mal, file_hash, wm)
    omitidos = 0

    url_fue_expandida = False
    url_original_str = ""
    url_expandida_str = ""

    # --- Procesar URLs ---
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
            # Todas en whitelist
            if not silent_mode:
                try:
                    await message.reply(f"{EMOJI_WHITELIST} **Dominio(s) en whitelist.** No se requiere análisis.", mention_author=False)
                except (discord.errors.Forbidden, discord.errors.NotFound):
                    pass
            img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)
        else:
            log.debug(f"URLs tras whitelist: {len(todas_urls)} de {len(urls)}")

            ahora = time.time()
            user_id = message.author.id
            spam_key = (guild_id, user_id) if guild_id else user_id

            # Cache check for antispam
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
            antispam_exceeded = len(bot.user_scan_history[spam_key]) >= ANTISPAM_ANALYSIS_PER_HOUR
            is_cooldown = spam_key in bot.antispam_scan and ahora - bot.antispam_scan[spam_key] < ANTISPAM_COOLDOWN

            if antispam_exceeded or is_cooldown:
                await safe_add_reaction(message, EMOJI_COOLDOWN)
                img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)
            else:
                if not todas_en_cache:
                    bot.antispam_scan[spam_key] = ahora
                    bot.user_scan_history[spam_key].append(ahora)

                # --- URL única ---
                if len(todas_urls) == 1:
                    url = todas_urls[0]
                    log.debug(f"URL única: {url}")

                    if await url_es_imagen(url, bot):
                        # --- URL de imagen → NSFW ---
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
                                # Cache hit → todo listo
                                if is_nsfw:
                                    if guild_id:
                                        await registrar_infraccion(guild_id, message.author.id, f"nsfw:{cached_hash}")
                                    detectados: list[str] = []
                                    if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                                    if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                                    if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                                    if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                                    detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                                    img_url_results.append((url, "nsfw", detalles_str))
                                else:
                                    img_url_results.append((url, "seguro", ""))
                                # Procesar adjuntos y mostrar embed unificado
                                img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)
                            else:
                                # Cache hash pero no en SE → continuar a descarga
                                pass
                        else:
                            # No hay hash cacheado
                            pass

                        if not cached_hash or (cached_hash and not from_cache):
                            # Descargar y analizar imagen
                            await safe_add_reaction(message, EMOJI_LOADING)
                            try:
                                async with bot._download_sem:
                                    img_data, error = await descargar_url_segura(bot, url, max_size=MAX_IMAGE_SIZE)
                                if error:
                                    if error == "too_large":
                                        img_url_results.append((url, "error", "too_large"))
                                    else:
                                        img_url_results.append((url, "error", error))
                                else:
                                    content_hash = hashlib.sha256(img_data).hexdigest()
                                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                                    if not models.get("error"):
                                        await update_stats(guild_id, "nsfw" if is_nsfw else "seguro")
                                    dummy = discord.Embed(title="NSFW URL Meta")
                                    await set_cache_mem(clave_meta_url, json.dumps({"hash": content_hash}), dummy, 0)
                                    await guardar_metadatos_hash(clave_meta_url, content_hash)

                                    if models.get("error") == "too_large":
                                        img_url_results.append((url, "error", "Supera el límite de Sightengine"))
                                    elif is_nsfw:
                                        if guild_id:
                                            await registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                                        detectados = []
                                        if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                                        if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                                        if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                                        if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                                        detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                                        img_url_results.append((url, "nsfw", detalles_str))
                                    else:
                                        img_url_results.append((url, "seguro", ""))
                            finally:
                                await safe_remove_loading(bot, message)
                            img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)

                    else:
                        # --- URL normal → VirusTotal ---
                        url_original_str = url
                        url = await expandir_url(bot, url)
                        url_fue_expandida = url != url_original_str
                        url_saltar_por_whitelist = False
                        if url_fue_expandida:
                            url_expandida_str = url
                            parsed_exp = urllib.parse.urlparse(url)
                            dominio_exp = parsed_exp.netloc.lower()
                            if dominio_exp.startswith("www."):
                                dominio_exp = dominio_exp[4:]
                            if dominio_en_whitelist(dominio_exp, whitelist):
                                log.debug(f"URL expandida redirige a dominio en whitelist: {dominio_exp}")
                                url_saltar_por_whitelist = True
                            else:
                                log.debug(f"URL expandida: {url_original_str} → {url}")

                        if not url_saltar_por_whitelist:
                            # Check cache
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
                                # Resultado en cache (VT ya no envía log)
                                if tipo == "malicioso":
                                    await registrar_infraccion(guild_id, message.author.id, f"url:{url}")
                                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if mal > 0 else None
                                url_results.append((url_original_str, tipo, mal, vt_link))
                                url_logged_internally.append(False)
                            else:
                                # No en cache → verificar límite VT
                                if not await check_vt_user_limit(message.author.id):
                                    url_results.append((url_original_str, "error", 0, None))
                                    url_logged_internally.append(False)
                                else:
                                    await safe_add_reaction(message, EMOJI_LOADING)
                                    try:
                                        tipo, embed, mal = await analizar_url(url, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                                    finally:
                                        await safe_remove_loading(bot, message)
                                    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                                    vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if mal > 0 else None
                                    url_results.append((url_original_str, tipo, mal, vt_link))
                                    url_logged_internally.append(True)

                        img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)

                else:
                    # --- Múltiples URLs ---
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

                        resultados_multi: list[tuple[str, str, str, int]] = []
                        urls_api: list[tuple[str, str, bool]] = []
                        multi_logged_internally: list[bool] = []
                        for r in expandidos:
                            url_orig, url_exp, tipo, embed, mal, fue_exp = r
                            if embed is not None:
                                resultados_multi.append((url_orig, url_exp, tipo, mal))
                                multi_logged_internally.append(False)
                            else:
                                urls_api.append((url_orig, url_exp, fue_exp))

                        if urls_api:
                            async def _api_url(url_orig: str, url_exp: str, fue_exp: bool) -> tuple[str, str, str, int]:
                                if not await check_vt_user_limit(message.author.id):
                                    return (url_orig, url_exp, "error", 0)
                                async with ANALYSIS_SEMAPHORE:
                                    tipo, embed, mal = await analizar_url(url_exp, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                                return (url_orig, url_exp, tipo, mal)

                            api_resultados = await asyncio.gather(*[_api_url(uo, ue, fe) for uo, ue, fe in urls_api], return_exceptions=True)
                            for r in api_resultados:
                                if isinstance(r, tuple):
                                    resultados_multi.append(r)
                                    multi_logged_internally.append(True)

                        for (url_orig, url_exp, tipo, mal), _logged in zip(resultados_multi, multi_logged_internally):
                            if tipo == "malicioso":
                                await registrar_infraccion(guild_id, message.author.id, f"url:{url_exp}")
                            url_id = base64.urlsafe_b64encode(url_exp.encode()).decode().rstrip("=")
                            vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if mal > 0 else None
                            url_results.append((url_orig, tipo, mal, vt_link))
                            url_logged_internally.append(_logged)
                    finally:
                        await safe_remove_loading(bot, message)

                    img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)

    else:
        # Solo adjuntos (sin URLs)
        img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)

    # --- Construir y enviar embed unificado ---
    total_elementos = len(url_results) + len(img_url_results) + len(img_results) + len(arch_results)
    if total_elementos == 0:
        return

    has_malicious_url = any(t == "malicioso" for _, t, _, _ in url_results)
    has_nsfw_url = any(t == "nsfw" for _, t, _ in img_url_results)
    has_malicious_file = any(t == "malicioso" for _, t, _, _, _ in arch_results)
    has_nsfw_img = any(t == "nsfw" for _, t, _, _ in img_results)
    has_threat = has_malicious_url or has_nsfw_url or has_malicious_file or has_nsfw_img
    has_errors = any(t == "error" for _, t, _, _ in url_results) or \
                 any(t == "error" for _, t, _ in img_url_results) or \
                 any(t == "error" for _, t, _, _ in img_results) or \
                 any(t == "error" for _, t, _, _, _ in arch_results)
    has_doble_ext = any(w for _, _, _, _, w in arch_results if w)

    embed = await _construir_embed_unificado(
        message, url_results, img_url_results, img_results, arch_results, omitidos,
        url_fue_expandida=url_fue_expandida,
        url_original=url_original_str,
        url_expandida=url_expandida_str,
    )

    # Enviar embed
    if has_threat or has_errors or omitidos or not silent_mode:
        await safe_send(message, embed, reference=message)

    # Reacción única por el peor resultado
    if has_malicious_url or has_malicious_file:
        await safe_add_reaction(message, EMOJI_WARNING)
    elif has_nsfw_url or has_nsfw_img:
        await safe_add_reaction(message, EMOJI_NSFW)
    elif has_errors:
        await safe_add_reaction(message, EMOJI_ERROR)
    else:
        await safe_add_reaction(message, EMOJI_CORRECTO)

    # Strict mode: eliminar mensaje si hay amenazas o doble extensión
    if (has_threat or has_doble_ext) and strict_mode:
        try:
            await message.delete()
        except (discord.errors.Forbidden, discord.errors.NotFound):
            pass

    # Logs por cada amenaza detectada (no duplicar para URLs ya logueadas por VT vía _on_threat_found)
    if log_channel_id:
        for i, (url_mostrar, tipo, mal, vt_link) in enumerate(url_results):
            already_logged = i < len(url_logged_internally) and url_logged_internally[i]
            if tipo == "malicioso" and not already_logged:
                await enviar_log_guild(guild_id, "URL", url_mostrar, f"{mal} detecciones", message.author, elemento_id=f"url:{url_mostrar}")
        for url, tipo, detalles in img_url_results:
            if tipo == "nsfw":
                await enviar_log_guild(guild_id, "Imagen NSFW", url, detalles, message.author, es_nsfw=True)
        for filename, tipo, models, content_hash in img_results:
            if tipo == "nsfw" and content_hash:
                await enviar_log_guild(guild_id, "Imagen NSFW (múltiples)", filename, "Detectado en análisis múltiple", message.author, elemento_id=f"nsfw:{content_hash}", es_nsfw=True)
        for filename, tipo, mal, _, _ in arch_results:
            if tipo == "malicioso":
                await enviar_log_guild(guild_id, "Archivo (múltiples)", filename, f"{mal} detecciones", message.author)
