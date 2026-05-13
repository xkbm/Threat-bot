import re
import time
import asyncio
import hashlib
import json
import urllib.parse
import base64
import logging
import discord
from core.config import MAX_IMAGE_SIZE, MAX_FILE_SIZE, EMOJI_CORRECTO, EMOJI_INCORRECTO, EMOJI_WARNING, EMOJI_WHITELIST, EMOJI_LOADING, EMOJI_LINK, EMOJI_FILE, EMOJI_COOLDOWN, EMOJI_REPLY, ANTISPAM_URLS_PER_HOUR, ANTISPAM_COOLDOWN
from core.utils import safe_remove_loading, safe_add_reaction, safe_send, dominio_en_whitelist, url_es_imagen, es_imagen, expandir_url, tiene_doble_extension, es_url_segura, descargar_url_segura
from core.cache import get_from_cache_mem, set_cache_mem
from core.database import obtener_analisis_db, guardar_metadatos_hash, obtener_hash_desde_metadatos
from api.virustotal import analizar_url, analizar_archivo, enviar_log_guild
from api.sightengine import analizar_imagen_multimodelo
from core.guild_config import obtener_config_guild, registrar_infraccion

log = logging.getLogger("handler")

async def procesar_analisis(bot, message):
    if len(message.content) > 5000:
        message.content = message.content[:5000]

    guild_id = message.guild.id
    config = obtener_config_guild(guild_id)
    silent_mode = config["silent_mode"]
    strict_mode = config["strict_mode"]
    log_channel_id = config["log_channel_id"]
    whitelist = config.get("whitelist", [])

    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, message.content)
    log.debug(f"Mensaje de {message.author} en guild={guild_id}: {len(urls)} URLs, {len(message.attachments)} adjuntos")

    if urls:
        todas_urls = []
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
                await message.reply(f"{EMOJI_WHITELIST} **Dominio(s) en whitelist.** No se requiere análisis.", mention_author=False)
            return

        log.debug(f"URLs tras whitelist: {len(todas_urls)} de {len(urls)}")

        if len(todas_urls) == 1:
            url = todas_urls[0]
            log.debug(f"URL única: {url}")
            if url_es_imagen(url):
                log.debug(f"URL es imagen → SSRF check + Sightengine")
                await safe_add_reaction(message, EMOJI_LOADING)
                try:
                    img_data, error = await descargar_url_segura(bot, url, max_size=MAX_IMAGE_SIZE)
                    if error:
                        if error == "too_large":
                            await safe_add_reaction(message, EMOJI_INCORRECTO)
                            if not silent_mode:
                                embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                                await safe_send(message, embed, reference=message)
                        else:
                            await safe_add_reaction(message, EMOJI_INCORRECTO)
                            await safe_send(message, discord.Embed(title=f"{EMOJI_INCORRECTO} URL bloqueada", description=f"La URL apunta a una dirección interna: {error}", color=discord.Color.red()), reference=message)
                        return
                    content_hash = hashlib.sha256(img_data).hexdigest()
                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                finally:
                    await safe_remove_loading(bot, message)

                if models.get("error") == "too_large":
                    await safe_add_reaction(message, EMOJI_WARNING)
                    if not silent_mode:
                        embed = discord.Embed(title=f"{EMOJI_WARNING} Imagen no analizada", description="Supera el límite de Sightengine", color=discord.Color.orange())
                        await safe_send(message, embed, reference=message)
                    return

                if is_nsfw:
                    if guild_id:
                        await registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                    await safe_add_reaction(message, EMOJI_WARNING)
                    detectados = []
                    if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                    if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                    if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                    if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                    detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Contenido Inapropiado Detectado", description=f"{detalles_str}", color=discord.Color.orange())
                    embed.add_field(name="Resultados", value=f"{EMOJI_WARNING} Imagen NSFW\n{detalles_str}", inline=False)
                    await safe_send(message, embed, reference=message)
                    if log_channel_id:
                        await enviar_log_guild(guild_id, "Imagen NSFW", url, detalles_str, message.author, elemento_id=f"nsfw:{content_hash}")
                    if strict_mode:
                        try:
                            await message.delete()
                        except Exception:
                            pass
                else:
                    await safe_add_reaction(message, EMOJI_CORRECTO)
                    if not silent_mode:
                        embed = discord.Embed(title=f"{EMOJI_CORRECTO} Imagen Segura", description="No se detectó contenido inapropiado.", color=discord.Color.green())
                        embed.add_field(name="Resultados", value=f"{EMOJI_CORRECTO} Imagen segura", inline=False)
                        await safe_send(message, embed, reference=message)
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
                        return
                    log.debug(f"URL expandida: {url_original} → {url}")
                clave = f"url:{url}"
                tipo, embed, mal = get_from_cache_mem(clave)
                if embed is not None:
                    log.debug(f"Cache HIT (RAM) para URL → resultado={tipo}")
                else:
                    tipo, embed, mal = await obtener_analisis_db(clave)
                    if embed is not None:
                        log.debug(f"Cache HIT (SQLite) para URL → resultado={tipo}")
                        set_cache_mem(clave, tipo, embed, mal)
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
                            except Exception:
                                pass
                        await safe_add_reaction(message, EMOJI_WARNING)
                    elif tipo == "seguro":
                        if not silent_mode:
                            await safe_send(message, embed, reference=message)
                        await safe_add_reaction(message, EMOJI_CORRECTO)
                    else:
                        if not silent_mode:
                            await safe_send(message, embed, reference=message)
                        await safe_add_reaction(message, EMOJI_INCORRECTO)
                    return

                ahora = time.time()
                user_id = message.author.id
                bot.user_scan_history.setdefault(user_id, [])
                bot.user_scan_history[user_id] = [t for t in bot.user_scan_history[user_id] if ahora - t < 3600]
                if len(bot.user_scan_history[user_id]) >= ANTISPAM_URLS_PER_HOUR:
                    await safe_add_reaction(message, EMOJI_COOLDOWN)
                    return

                if user_id in bot.antispam_scan and ahora - bot.antispam_scan[user_id] < ANTISPAM_COOLDOWN:
                    await safe_add_reaction(message, EMOJI_COOLDOWN)
                    return
                bot.antispam_scan[user_id] = ahora
                bot.user_scan_history[user_id].append(ahora)

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
                    await safe_add_reaction(message, EMOJI_INCORRECTO)
                return

        log.debug(f"Múltiples URLs ({len(todas_urls)})")
        await safe_add_reaction(message, EMOJI_LOADING)
        try:
            todas_urls = list(dict.fromkeys(todas_urls))[:5]
            resultados = []
            maliciosas = seguras = errores = 0
            for i, url in enumerate(todas_urls, 1):
                url_original = url
                url_exp = await expandir_url(bot, url)
                fue_exp = url_exp != url_original
                if fue_exp:
                    parsed_exp = urllib.parse.urlparse(url_exp)
                    dominio_exp = parsed_exp.netloc.lower()
                    if dominio_exp.startswith("www."):
                        dominio_exp = dominio_exp[4:]
                    if dominio_en_whitelist(dominio_exp, whitelist):
                        log.debug(f"[{i}/{len(todas_urls)}] URL expandida redirige a dominio en whitelist: {dominio_exp}")
                        continue
                    log.debug(f"[{i}/{len(todas_urls)}] URL expandida: {url_original} → {url_exp}")
                clave = f"url:{url_exp}"
                tipo, embed, mal = get_from_cache_mem(clave)
                if embed is not None:
                    log.debug(f"[{i}/{len(todas_urls)}] Cache HIT (RAM) → {url_original} resultado={tipo}")
                else:
                    tipo, embed, mal = await obtener_analisis_db(clave)
                    if embed is not None:
                        log.debug(f"[{i}/{len(todas_urls)}] Cache HIT (SQLite) → {url_original} resultado={tipo}")
                        set_cache_mem(clave, tipo, embed, mal)
                    else:
                        log.debug(f"[{i}/{len(todas_urls)}] Cache MISS → {url_original} llamando VT")
                if embed is not None:
                    resultados.append((url_original, url_exp, tipo, mal))
                    if tipo == "malicioso":
                        maliciosas += 1
                        await registrar_infraccion(guild_id, message.author.id, f"url:{url_exp}")
                    elif tipo == "seguro":
                        seguras += 1
                    else:
                        errores += 1
                    continue
                await asyncio.sleep(1)
                tipo, embed, mal = await analizar_url(url_exp, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                resultados.append((url_original, url_exp, tipo, mal))
                if tipo == "malicioso":
                    maliciosas += 1
                elif tipo == "seguro":
                    seguras += 1
                else:
                    errores += 1

            color = discord.Color.orange() if maliciosas else (discord.Color.red() if errores else discord.Color.green())
            titulo = f"{EMOJI_WARNING} Amenazas detectadas" if maliciosas else (f"{EMOJI_WARNING} Errores en el análisis" if errores else f"{EMOJI_CORRECTO} Todos los enlaces son seguros")
            descripcion = f"Se analizaron **{len(todas_urls)}** enlace(s) en el mensaje de {message.author.mention}:\n" \
                          f"{EMOJI_CORRECTO} Seguros: **{seguras}**\n{EMOJI_WARNING} Maliciosos: **{maliciosas}**\n{EMOJI_INCORRECTO} Errores: **{errores}**"
            embed_resumen = discord.Embed(title=titulo, description=descripcion, color=color)
            valor_campo = ""
            for url_orig, url_exp, tipo, _ in resultados:
                icono = EMOJI_WARNING if tipo == "malicioso" else (EMOJI_CORRECTO if tipo == "seguro" else EMOJI_INCORRECTO)
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
            await safe_send(message, embed_resumen, reference=message)
        finally:
            await safe_remove_loading(bot, message)
        if maliciosas:
            await safe_add_reaction(message, EMOJI_WARNING)
        elif errores:
            await safe_add_reaction(message, EMOJI_WARNING)
        else:
            await safe_add_reaction(message, EMOJI_CORRECTO)
        if maliciosas and strict_mode:
            try:
                await message.delete()
            except Exception:
                pass
        return

    if message.attachments:
        adjuntos = message.attachments[:5]
        imagenes = [a for a in adjuntos if es_imagen(a)]
        otros = [a for a in adjuntos if not es_imagen(a)]
        log.debug(f"Adjuntos: {len(imagenes)} imágenes, {len(otros)} archivos")

        resultados_img = []
        resultados_arch = []

        await safe_add_reaction(message, EMOJI_LOADING)
        try:
            for img in imagenes:
                log.debug(f"Imagen: {img.filename} ({img.size} bytes)")
                if img.size > MAX_IMAGE_SIZE:
                    resultados_img.append((img.filename, "error", {"error": "too_large"}, ""))
                    continue
                clave_meta = f"nsfw_filename:{img.filename}:{img.size}"
                tipo_meta, embed_meta, _ = get_from_cache_mem(clave_meta)
                content_hash = None
                if embed_meta is not None:
                    try:
                        content_hash = json.loads(tipo_meta).get("hash")
                    except Exception:
                        pass
                if not content_hash:
                    content_hash = await obtener_hash_desde_metadatos(clave_meta)
                if content_hash:
                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, b"")
                    if from_cache:
                        resultados_img.append((img.filename, "nsfw" if is_nsfw else "seguro", models, content_hash))
                        continue
                try:
                    async with bot.session.get(img.url) as resp:
                        if resp.status != 200:
                            resultados_img.append((img.filename, "error", {}, ""))
                            continue
                        img_data = await resp.read()
                        if len(img_data) > MAX_IMAGE_SIZE:
                            resultados_img.append((img.filename, "error", {"error": "too_large"}, ""))
                            continue
                        content_hash = hashlib.sha256(img_data).hexdigest()
                        is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                        if is_nsfw and guild_id:
                            await registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                        resultados_img.append((img.filename, "nsfw" if is_nsfw else "seguro", models, content_hash))
                        dummy = discord.Embed(title="NSFW Meta")
                        set_cache_mem(clave_meta, json.dumps({"hash": content_hash}), dummy, 0)
                        await guardar_metadatos_hash(clave_meta, content_hash)
                except Exception:
                    resultados_img.append((img.filename, "error", {}, ""))

            for archivo in otros:
                log.debug(f"Archivo: {archivo.filename} ({archivo.size} bytes)")
                doble_ext = tiene_doble_extension(archivo.filename)
                wm = ""
                if doble_ext:
                    await safe_add_reaction(message, EMOJI_WARNING)
                if archivo.size > MAX_FILE_SIZE:
                    resultados_arch.append((archivo.filename, "error", 0, "", ""))
                    continue
                clave_meta = f"file:{archivo.filename}:{archivo.size}"
                tipo_meta, embed_meta, _ = get_from_cache_mem(clave_meta)
                file_hash = None
                if embed_meta is not None:
                    try:
                        file_hash = json.loads(tipo_meta).get("hash")
                    except Exception:
                        pass
                if not file_hash:
                    file_hash = await obtener_hash_desde_metadatos(clave_meta)
                if file_hash:
                    tipo, embed, mal = get_from_cache_mem(f"filehash:{file_hash}")
                    if embed is None:
                        tipo, embed, mal = await obtener_analisis_db(f"filehash:{file_hash}")
                        if embed is not None:
                            set_cache_mem(f"filehash:{file_hash}", tipo, embed, mal)
                    if embed is not None:
                        if tipo == "malicioso":
                            await registrar_infraccion(guild_id, message.author.id, f"filehash:{file_hash}")
                        resultados_arch.append((archivo.filename, tipo, mal, file_hash, wm))
                        continue
                try:
                    async with bot.session.get(archivo.url) as resp:
                        if resp.status != 200:
                            resultados_arch.append((archivo.filename, "error", 0, "", ""))
                            continue
                        file_data = await resp.read()
                        file_hash = hashlib.sha256(file_data).hexdigest()
                        content_type = resp.headers.get('Content-Type', '')
                        if archivo.filename.endswith('.jpg') and content_type not in ('image/jpeg', 'image/jpg'):
                            wm = f"Extensión .jpg pero tipo real {content_type}"
                        elif archivo.filename.endswith('.png') and content_type != 'image/png':
                            wm = f"Extensión .png pero tipo real {content_type}"
                except Exception:
                    resultados_arch.append((archivo.filename, "error", 0, "", ""))
                    continue
                tipo, embed, mal = get_from_cache_mem(f"filehash:{file_hash}")
                if embed is None:
                    tipo, embed, mal = await obtener_analisis_db(f"filehash:{file_hash}")
                    if embed is not None:
                        set_cache_mem(f"filehash:{file_hash}", tipo, embed, mal)
                if embed is not None:
                    if tipo == "malicioso":
                        await registrar_infraccion(guild_id, message.author.id, f"filehash:{file_hash}")
                    resultados_arch.append((archivo.filename, tipo, mal, file_hash, wm))
                else:
                    tipo, embed, mal = await analizar_archivo(archivo, file_bytes=file_data, file_hash=file_hash, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                    resultados_arch.append((archivo.filename, tipo, mal, file_hash, wm))

        finally:
            await safe_remove_loading(bot, message)

        total = len(resultados_img) + len(resultados_arch)
        if total == 0:
            return
        maliciosos = sum(1 for _, t, _, _ in resultados_img if t == "nsfw") + sum(1 for _, t, _, _, _ in resultados_arch if t == "malicioso")
        nsfw = sum(1 for _, t, _, _ in resultados_img if t == "nsfw")
        seguros = sum(1 for _, t, _, _ in resultados_img if t == "seguro") + sum(1 for _, t, _, _, _ in resultados_arch if t == "seguro")
        errores = total - maliciosos - seguros
        has_doble_ext = any(tiene_doble_extension(a.filename) for a in adjuntos)

        if maliciosos or nsfw:
            color = discord.Color.orange()
            titulo = f"{EMOJI_WARNING} ¡Amenazas detectadas en archivos adjuntos!"
        elif errores:
            color = discord.Color.red()
            titulo = f"{EMOJI_WARNING} Análisis completado con errores"
        else:
            color = discord.Color.green()
            titulo = f"{EMOJI_CORRECTO} Todos los archivos son seguros"

        descripcion = f"**{total}** archivo(s) analizado(s) en el mensaje de {message.author.mention}:\n"
        descripcion += f"{EMOJI_CORRECTO} Seguros: **{seguros}**\n"
        descripcion += f"{EMOJI_WARNING} Maliciosos/NSFW: **{maliciosos}**\n"
        descripcion += f"{EMOJI_INCORRECTO} Errores: **{errores}**"
        embed_resumen = discord.Embed(title=titulo, description=descripcion, color=color)

        campo = ""
        for filename, tipo, models, _ in resultados_img:
            if tipo == "nsfw":
                detalles = []
                if models.get('nudity', 0.0) >= 0.5: detalles.append(f"Desnudez {models['nudity']*100:.0f}%")
                if models.get('weapon', 0.0) >= 0.5: detalles.append(f"Armas {models['weapon']*100:.0f}%")
                if models.get('offensive', 0.0) >= 0.7: detalles.append(f"Ofensivo {models['offensive']*100:.0f}%")
                if models.get('alcohol', 0.0) >= 0.7: detalles.append(f"Alcohol {models['alcohol']*100:.0f}%")
                detalle_str = ", ".join(detalles) if detalles else "Contenido inapropiado"
                campo += f"{EMOJI_WARNING} `{filename}` (NSFW: {detalle_str})\n"
            elif tipo == "seguro":
                campo += f"{EMOJI_CORRECTO} `{filename}` (imagen)\n"
            else:
                campo += f"{EMOJI_INCORRECTO} `{filename}` (error)\n"

        for filename, tipo, mal, file_hash, wm in resultados_arch:
            if tipo == "malicioso":
                campo += f"{EMOJI_WARNING} `{filename}` ({mal} detecciones)\n"
            elif tipo == "seguro":
                campo += f"{EMOJI_CORRECTO} `{filename}`\n"
            else:
                campo += f"{EMOJI_INCORRECTO} `{filename}`\n"

        embed_resumen.add_field(name="Resultados", value=campo[:1024], inline=False)

        if log_channel_id:
            for filename, tipo, models, content_hash in resultados_img:
                if tipo == "nsfw" and content_hash:
                    await enviar_log_guild(guild_id, "Imagen NSFW (múltiples)", filename, "Detectado en análisis múltiple", message.author, elemento_id=f"nsfw:{content_hash}")
            for filename, tipo, mal, file_hash, wm in resultados_arch:
                if tipo == "malicioso" and file_hash:
                    await enviar_log_guild(guild_id, "Archivo (múltiples)", filename, f"{mal} detecciones", message.author, elemento_id=f"filehash:{file_hash}")

        if maliciosos or nsfw or not silent_mode:
            await safe_send(message, embed_resumen, reference=message)

        if maliciosos:
            await safe_add_reaction(message, EMOJI_WARNING)
        elif errores:
            await safe_add_reaction(message, EMOJI_WARNING)
        else:
            await safe_add_reaction(message, EMOJI_CORRECTO)

        if (maliciosos or has_doble_ext) and strict_mode:
            try:
                await message.delete()
            except Exception:
                pass
