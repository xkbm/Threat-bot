import re
import aiohttp
import time
import asyncio
import hashlib
import json
import urllib.parse
import base64
from collections import OrderedDict
from typing import NamedTuple, Optional
import logging
import discord
from discord.ext import commands
from core.config import MAX_IMAGE_SIZE, MAX_FILE_SIZE, EMOJI_CORRECTO, EMOJI_ERROR, EMOJI_WARNING, EMOJI_WHITELIST, EMOJI_LOADING, EMOJI_LINK, EMOJI_FILE, EMOJI_COOLDOWN, EMOJI_REPLY, EMOJI_NSFW
from core.utils import safe_remove_loading, safe_add_reaction, safe_send, dominio_en_whitelist, url_es_imagen, es_imagen, expandir_url, tiene_doble_extension, descargar_url_segura, normalizar_url, comprobar_antispam, check_vt_user_limit
from core.cache import get_from_cache_mem, set_cache_mem
from core.database import obtener_analisis_db, guardar_metadatos_hash, obtener_hash_desde_metadatos
from api.virustotal import analizar_url, analizar_archivo, enviar_log_guild
from api.sightengine import analizar_imagen_multimodelo
from core.guild_config import obtener_config_guild, registrar_infraccion, update_stats
from core.state import ANALYSIS_SEMAPHORE
from ui import embed as emb

log = logging.getLogger("handler")

MAX_ADJUNTOS_POR_MENSAJE = 5
MAX_URLS_POR_MENSAJE = 5

# Huellas de mensajes ya procesados, para no reprocesar un mensaje editado cuyo contenido
# no cambió (o dos eventos on_message/on_message_edit que llegan juntos). Mismo patrón que
# la caché de DNS: OrderedDict con TTL y tope.
_procesados: OrderedDict[int, tuple[float, str]] = OrderedDict()
_HUELLA_TTL: float = 3600.0
_HUELLA_MAX: int = 5000


def _huella_mensaje(message: discord.Message) -> str:
    """Huella del contenido analizable de un mensaje."""
    partes = [message.content[:5000]]
    partes.extend(f"{a.id}:{a.size}" for a in sorted(message.attachments, key=lambda x: x.id))
    return hashlib.sha256("\x1f".join(partes).encode("utf-8", "replace")).hexdigest()


def _marcar_procesado(message: discord.Message) -> bool:
    """True si el mensaje es nuevo o cambió (debe analizarse). False si ya se procesó igual."""
    ahora = time.time()
    huella = _huella_mensaje(message)
    previo = _procesados.get(message.id)
    _procesados[message.id] = (ahora, huella)
    _procesados.move_to_end(message.id)
    while len(_procesados) > _HUELLA_MAX:
        _procesados.popitem(last=False)
    return previo is None or previo[1] != huella or ahora - previo[0] >= _HUELLA_TTL


def limpiar_cache_procesados() -> int:
    """Purga las huellas expiradas. Devuelve cuántas quitó."""
    ahora = time.time()
    expiradas = [k for k, v in _procesados.items() if ahora - v[0] >= _HUELLA_TTL]
    for k in expiradas:
        del _procesados[k]
    return len(expiradas)


class UrlResult(NamedTuple):
    """Resultado del análisis de una URL del mensaje.

    `elemento_id` es la clave con la que se cachea y con la que se registra la infracción.
    Tiene que ser SIEMPRE la URL ya expandida: es lo que la guarda VirusTotal y lo que
    usa el botón "Ignorar" del log de amenazas para descontar la infracción.
    `ya_logueado` indica que api/virustotal._on_threat_found ya mandó el log y aplicó
    el strict mode, para no duplicarlos aquí.
    """
    url: str
    tipo: str
    mal: int
    vt_link: Optional[str]
    elemento_id: str
    ya_logueado: bool


class ImgUrlResult(NamedTuple):
    """Análisis de una URL que resultó ser una imagen (NSFW vía SightEngine).

    `elemento_id` es `nsfw:<sha256 del contenido>`, la misma clave con la que se registra
    la infracción, para que el botón "Ignorar" del log la encuentre.
    """
    url: str
    tipo: str
    detalles: str
    elemento_id: str = ""


async def _construir_embed_unificado(
    message: discord.Message,
    url_results: list[UrlResult],
    img_url_results: list[ImgUrlResult],
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

    has_malicious_url = any(r.tipo == "malicioso" for r in url_results)
    has_nsfw_url = any(r.tipo == "nsfw" for r in img_url_results)
    has_malicious_file = any(t == "malicioso" for _, t, _, _, _ in arch_results)
    has_nsfw_img = any(t == "nsfw" for _, t, _, _ in img_results)
    has_errors_url = any(r.tipo == "error" for r in url_results)
    has_errors_img = any(r.tipo == "error" for r in img_url_results) or any(t == "error" for _, t, _, _ in img_results)
    has_errors_file = any(t == "error" for _, t, _, _, _ in arch_results)

    is_threat = has_malicious_url or has_nsfw_url or has_malicious_file or has_nsfw_img
    has_errors = has_errors_url or has_errors_img or has_errors_file

    mal_count = sum(1 for r in url_results if r.tipo == "malicioso") + sum(1 for _, t, _, _, _ in arch_results if t == "malicioso")
    nsfw_count = sum(1 for r in img_url_results if r.tipo == "nsfw") + sum(1 for _, t, _, _ in img_results if t == "nsfw")
    err_count = (sum(1 for r in url_results if r.tipo == "error")
                 + sum(1 for r in img_url_results if r.tipo == "error")
                 + sum(1 for _, t, _, _ in img_results if t == "error")
                 + sum(1 for _, t, _, _, _ in arch_results if t == "error"))
    seguros = total - mal_count - nsfw_count - err_count

    # Determinar título y color. El color sigue el mismo modelo que el resto de
    # embeds: ámbar/rojo si hay una amenaza, rojo si falló algo, verde si todo limpio.
    if is_threat:
        color = emb.COLOR_NSFW if has_nsfw_url or has_nsfw_img else emb.COLOR_MALICIOSO
        titulo_texto = "Contenido NSFW detectado" if not (has_malicious_url or has_malicious_file) else "Amenazas detectadas"
    elif has_errors:
        color = emb.COLOR_ERROR
        titulo_texto = "Análisis completado con errores"
    else:
        color = emb.COLOR_SEGURO
        titulo_texto = "Todos los elementos son seguros"

    # Descripción: los contadores van siempre, en el mismo orden, para que dos
    # mensajes con resultados distintos se lean igual.
    desc = f"**{total}** elemento(s) analizado(s) en el mensaje de {message.author.mention}:\n"
    desc += f"{EMOJI_CORRECTO} Seguros: **{seguros}**\n"
    if mal_count:
        desc += f"{EMOJI_WARNING} Maliciosos: **{mal_count}**\n"
    if nsfw_count:
        desc += f"{EMOJI_NSFW} NSFW: **{nsfw_count}**\n"
    if err_count:
        desc += f"{EMOJI_ERROR} Errores: **{err_count}**\n"
    if omitidos:
        desc += f"{EMOJI_COOLDOWN} **{omitidos}** archivo(s) omitido(s) (límite {MAX_ADJUNTOS_POR_MENSAJE} por mensaje)"

    embed = emb.aviso(titulo_texto, desc, color=color, icono=emb.EMOJI_SHIELD, con_pie=False)

    # --- Campo: URLs ---
    if url_results:
        valor_urls = ""
        for r in url_results:
            icono = EMOJI_WARNING if r.tipo == "malicioso" else (EMOJI_CORRECTO if r.tipo == "seguro" else EMOJI_ERROR)
            valor_urls += f"{icono} `{r.url}`"
            if r.vt_link:
                valor_urls += f" {EMOJI_LINK}[VT]({r.vt_link})"
            valor_urls += "\n"
        embed.add_field(name=f"{EMOJI_LINK} URLs", value=valor_urls[:1024], inline=False)

    # --- Campo: Imágenes (URLs) ---
    if img_url_results:
        valor_img_urls = ""
        for r in img_url_results:
            icono = EMOJI_NSFW if r.tipo == "nsfw" else (EMOJI_CORRECTO if r.tipo == "seguro" else EMOJI_ERROR)
            valor_img_urls += f"{icono} `{r.url}`"
            if r.detalles:
                valor_img_urls += f" ({r.detalles})"
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
    mal_urls = [(r.url, r.vt_link) for r in url_results if r.tipo == "malicioso" and r.vt_link]
    if mal_urls:
        valor_mal = ""
        for url, vt_link in mal_urls:
            valor_mal += f"• `{url}` {EMOJI_LINK}[Ver informe]({vt_link})\n"
        embed.add_field(name=f"{EMOJI_WARNING} Enlaces maliciosos", value=valor_mal[:1024], inline=False)

    return emb.pie(embed, f"Análisis de mensaje · {total} elemento(s)")


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
                # Leer el Content-Type dentro del contexto: después de salir, aiohttp
                # libera la conexión y no es un lugar fiable para consultar la respuesta.
                content_type = resp.headers.get('Content-Type', '')
            file_hash = hashlib.sha256(file_data).hexdigest()
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
    adjuntos = message.attachments[:MAX_ADJUNTOS_POR_MENSAJE]
    omitidos = max(0, len(message.attachments) - MAX_ADJUNTOS_POR_MENSAJE)
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
    if message.guild is None:
        return
    guild_id = message.guild.id
    config = await obtener_config_guild(guild_id)
    if not config.get("auto_scan_enabled", True):
        return

    # F8: si este mismo contenido ya se analizó (edición sin cambios, o on_message y
    # on_message_edit a la vez), no se vuelve a contar ni a notificar.
    if not _marcar_procesado(message):
        log.debug(f"Mensaje {message.id} sin cambios, se omite el re-análisis")
        return

    if len(message.content) > 5000:
        message.content = message.content[:5000]

    silent_mode = config["silent_mode"]
    strict_mode = config["strict_mode"]
    log_channel_id = config["log_channel_id"]
    whitelist = config.get("whitelist", [])

    url_pattern = r'https?://[^\s]+'
    urls = [_limpiar_url(u) for u in re.findall(url_pattern, message.content)]
    log.debug(f"Mensaje de {message.author} en guild={guild_id}: {len(urls)} URLs, {len(message.attachments)} adjuntos")

    # --- Colectores de resultados para el embed unificado ---
    url_results: list[UrlResult] = []             # ver UrlResult
    img_url_results: list[ImgUrlResult] = []      # ver ImgUrlResult
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

            # Sólo se cobra cuota de antispam si el mensaje va a consumir API de verdad:
            # repetir un enlace que ya está en caché no llama a VirusTotal.
            va_a_consumir_api = bool(message.attachments)
            if not va_a_consumir_api:
                for url in todas_urls:
                    clave_check = f"url:{normalizar_url(url)}"
                    _, embed_check, _ = await get_from_cache_mem(clave_check)
                    if embed_check is None:
                        _, embed_check, _ = await obtener_analisis_db(clave_check)
                    if embed_check is None:
                        va_a_consumir_api = True
                        break

            permitido = True
            espera = 0
            if va_a_consumir_api:
                permitido, espera = await comprobar_antispam(bot, guild_id, message.author.id)
                if not permitido:
                    log.debug(f"ANTISPAM → guild={guild_id} user={message.author.id} espera={espera}s")

            if not permitido:
                await safe_add_reaction(message, EMOJI_COOLDOWN)
                img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)
            else:
                # --- URL única ---
                if len(todas_urls) == 1:
                    url = todas_urls[0]
                    log.debug(f"URL única: {url}")

                    if await url_es_imagen(url, bot):
                        # --- URL de imagen → NSFW ---
                        log.debug("URL es imagen → SSRF check + Sightengine")
                        url_hash_key = hashlib.sha256(url.encode()).hexdigest()
                        clave_meta_url = f"nsfw_url:{url_hash_key}"
                        tipo_meta, embed_meta, _ = await get_from_cache_mem(clave_meta_url)
                        cached_hash = None
                        if tipo_meta is not None:
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
                                    img_url_results.append(ImgUrlResult(url, "nsfw", detalles_str, f"nsfw:{cached_hash}"))
                                else:
                                    img_url_results.append(ImgUrlResult(url, "seguro", ""))
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
                                        img_url_results.append(ImgUrlResult(url, "error", "too_large"))
                                    else:
                                        img_url_results.append(ImgUrlResult(url, "error", error))
                                else:
                                    content_hash = hashlib.sha256(img_data).hexdigest()
                                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                                    if not models.get("error"):
                                        await update_stats(guild_id, "nsfw" if is_nsfw else "seguro")
                                    await set_cache_mem(clave_meta_url, json.dumps({"hash": content_hash}), datos={"hash": content_hash})
                                    await guardar_metadatos_hash(clave_meta_url, content_hash)

                                    if models.get("error") == "too_large":
                                        img_url_results.append(ImgUrlResult(url, "error", "Supera el límite de Sightengine"))
                                    elif is_nsfw:
                                        if guild_id:
                                            await registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                                        detectados = []
                                        if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                                        if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                                        if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                                        if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                                        detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                                        img_url_results.append(ImgUrlResult(url, "nsfw", detalles_str, f"nsfw:{content_hash}"))
                                    else:
                                        img_url_results.append(ImgUrlResult(url, "seguro", ""))
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
                                    log.debug("Cache MISS para URL → llamando VT")

                            if embed is not None:
                                # Resultado en cache (VT ya no envió log)
                                elemento_id = f"url:{url}"
                                if tipo == "malicioso":
                                    await registrar_infraccion(guild_id, message.author.id, elemento_id)
                                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if mal > 0 else None
                                url_results.append(UrlResult(url_original_str, tipo, mal, vt_link, elemento_id, False))
                            else:
                                # No en cache → verificar límite VT
                                if not await check_vt_user_limit(bot, guild_id, message.author.id):
                                    url_results.append(UrlResult(url_original_str, "error", 0, None, f"url:{url}", False))
                                else:
                                    await safe_add_reaction(message, EMOJI_LOADING)
                                    try:
                                        tipo, embed, mal = await analizar_url(url, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                                    finally:
                                        await safe_remove_loading(bot, message)
                                    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                                    vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if mal > 0 else None
                                    # _on_threat_found ya mandó el log con eid = f"url:{valor}"
                                    url_results.append(UrlResult(url_original_str, tipo, mal, vt_link, f"url:{url}", True))

                        img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id)

                else:
                    # --- Múltiples URLs ---
                    await safe_add_reaction(message, EMOJI_LOADING)
                    try:
                        todas_urls = list(dict.fromkeys(todas_urls))[:MAX_URLS_POR_MENSAJE]

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

                        # Los que ya estaban en caché no vuelven a llamar a la API, así que
                        # el bot no mandó log por ellos (ya_logueado=False).
                        pendientes: list[tuple[str, str, bool]] = []
                        for url_orig, url_exp, tipo, embed, mal, _fue_exp in expandidos:
                            if embed is not None:
                                elemento_id = f"url:{url_exp}"
                                if tipo == "malicioso":
                                    await registrar_infraccion(guild_id, message.author.id, elemento_id)
                                url_id = base64.urlsafe_b64encode(url_exp.encode()).decode().rstrip("=")
                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if mal > 0 else None
                                url_results.append(UrlResult(url_orig, tipo, mal, vt_link, elemento_id, False))
                            else:
                                pendientes.append((url_orig, url_exp, _fue_exp))

                        if pendientes:
                            async def _api_url(url_orig: str, url_exp: str, _fue_exp: bool) -> Optional[UrlResult]:
                                if not await check_vt_user_limit(bot, guild_id, message.author.id):
                                    return UrlResult(url_orig, "error", 0, None, f"url:{url_exp}", False)
                                async with ANALYSIS_SEMAPHORE:
                                    tipo, embed, mal = await analizar_url(url_exp, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                                url_id = base64.urlsafe_b64encode(url_exp.encode()).decode().rstrip("=")
                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if mal > 0 else None
                                # _on_threat_found ya mandó el log con eid = f"url:{url_exp}"
                                return UrlResult(url_orig, tipo, mal, vt_link, f"url:{url_exp}", True)

                            api_resultados = await asyncio.gather(*[_api_url(uo, ue, fe) for uo, ue, fe in pendientes], return_exceptions=True)
                            for r in api_resultados:
                                if isinstance(r, UrlResult):
                                    url_results.append(r)
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

    has_malicious_url = any(r.tipo == "malicioso" for r in url_results)
    has_nsfw_url = any(r.tipo == "nsfw" for r in img_url_results)
    has_malicious_file = any(t == "malicioso" for _, t, _, _, _ in arch_results)
    has_nsfw_img = any(t == "nsfw" for _, t, _, _ in img_results)
    has_threat = has_malicious_url or has_nsfw_url or has_malicious_file or has_nsfw_img
    has_errors = (any(r.tipo == "error" for r in url_results)
                  or any(r.tipo == "error" for r in img_url_results)
                  or any(t == "error" for _, t, _, _ in img_results)
                  or any(t == "error" for _, t, _, _, _ in arch_results))
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

    # Logs por cada amenaza detectada. `elemento_id` tiene que ser el MISMO que se usó al
    # registrar la infracción (la URL expandida), o el botón "Ignorar" del log no
    # encontraría la infracción que intentaría descontar.
    if log_channel_id:
        for r in url_results:
            if r.tipo == "malicioso" and not r.ya_logueado:
                await enviar_log_guild(
                    guild_id, "URL", r.url, f"{r.mal} detecciones", message.author,
                    url_vt=r.vt_link, elemento_id=r.elemento_id,
                )
        for r in img_url_results:
            if r.tipo == "nsfw":
                await enviar_log_guild(guild_id, "Imagen NSFW", r.url, r.detalles, message.author, elemento_id=r.elemento_id or None, es_nsfw=True)
        for filename, tipo, models, content_hash in img_results:
            if tipo == "nsfw" and content_hash:
                await enviar_log_guild(guild_id, "Imagen NSFW (múltiples)", filename, "Detectado en análisis múltiple", message.author, elemento_id=f"nsfw:{content_hash}", es_nsfw=True)
        for filename, tipo, mal, file_hash, _wm in arch_results:
            if tipo == "malicioso":
                # Mismo elemento_id que usa _procesar_archivo al registrar la infracción.
                await enviar_log_guild(
                    guild_id, "Archivo (múltiples)", filename, f"{mal} detecciones", message.author,
                    elemento_id=f"filehash:{file_hash}" if file_hash else None,
                )
