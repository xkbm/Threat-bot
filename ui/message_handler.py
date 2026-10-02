import aiohttp
import time
import asyncio
import hashlib
import json
import urllib.parse
import base64
from collections import Counter, OrderedDict
from typing import NamedTuple, Optional
import logging
import discord
from discord.ext import commands
from core.config import (
    MAX_IMAGE_SIZE, MAX_FILE_SIZE, VT_API_KEYS, EMOJI_WHITELIST, EMOJI_LOADING,
    EMOJI_LINK, EMOJI_FILE, EMOJI_COOLDOWN, EMOJI_REPLY, EMOJI_NSFW,
    EMOJI_NOMBRE_SOSPECHOSO,
)
from core.utils import safe_remove_loading, safe_add_reaction, safe_send, dominio_en_whitelist, url_es_imagen, es_imagen, verificar_nombre, expandir_url, tiene_doble_extension, descargar_url_segura, clave_analisis, vuelo, SIN_RESPUESTA, comprobar_antispam, check_vt_user_limit, PATRON_URL_D, limpiar_url
from core import filetypes as F
from core import veredictos
from core.filetypes import CABECERA_BYTES
from core.phishing import detectar as detectar_phishing
from core.cache import get_from_cache_mem, set_cache_mem
from core.database import (
    obtener_analisis_db, obtener_datos_analisis, guardar_analisis_db,
    guardar_metadatos_hash,
    obtener_hash_desde_metadatos, registrar_evento,
)
from api.virustotal import (
    analizar_url, analizar_archivo, enviar_log_guild, reputacion_hash,
)
from api.sightengine import analizar_imagen_multimodelo, evaluar_contenido
from core.veredictos import ORDEN_CONTADORES, Veredicto
from core.state import ANALYSIS_SEMAPHORE
from core.guild_config import (
    obtener_config_guild, registrar_infraccion, update_stats,
)
from core.senales import Elemento, Senales, desde_tuplas
from core.aviso import debe_enviar_embed, reacciones_activas
from core.reacciones import ReactionController, resolver_reaccion
from ui import embed as emb

log = logging.getLogger("handler")

# Alias: el patrón y el limpiado viven en `core.utils` porque el menú contextual los
# necesita también, y duplicarlos haría que cada vía mirara cosas distintas.
PATRON_URL = PATRON_URL_D

# Límites por mensaje. Fijos, y a propósito NO configurables por servidor.
#
# Las claves de las APIs las paga quien mantiene el bot y las comparten todos los
# servidores. Si un administrador de un servidor puede subir su límite de adjuntos, cada
# adjunto de más son más requests de VirusTotal contra la cuota mensual de quien lo
# mantiene: le sale gratis y nadie se entera. Estos valores solo se cambian en el código.
MAX_ADJUNTOS_POR_MENSAJE = 5
MAX_URLS_POR_MENSAJE = 5

# Tipo de la entrada de caché que dice "VirusTotal no ha visto este archivo". Distinto
# de `imgmal:` (la clave, que es el hash) para que se lea qué es cada cosa.
TIPO_HASH_DESCONOCIDO: str = "imgmal_desconocido"

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
    `redireccion` es la URL expandida cuando el enlace era un acortador. Antes vivía en
    tres parámetros sueltos de _construir_embed_unificado que solo se rellenaban en la
    rama de URL única, así que con varias URLs la información se perdía.
    """
    url: str
    tipo: str
    mal: int
    vt_link: Optional[str]
    elemento_id: str
    ya_logueado: bool
    redireccion: Optional[str] = None

    @property
    def es_redireccion(self) -> bool:
        return bool(self.redireccion)


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
    senales: Senales,
) -> discord.Embed:
    """Construye UN embed con toda la información disponible.

    Todo sale de `senales` y de `Veredicto`. Antes esta función reinterpretaba las
    tuplas con su propia lógica y con umbrales escritos a mano, y eso producía mensajes
    que se contradecían a sí mismos: una imagen con alcohol salía con el título
    "Todos los elementos son seguros" en verde, con el contador "Seguros: 1", con el
    icono de error en su línea y con la reacción de bandera. Cuatro cosas distintas
    para el mismo elemento, porque ninguna compartía la tabla de veredictos con las
    demás. Ahora hay una sola y las cuatro salen de ahí.

    Igual con los detalles de SightEngine: se leía `models['nudity']` con umbral 0.5,
    pero `models` ya no tiene esa clave (ahora es `nudity_raw` / `nudity_partial` /
    `gore` / ...), así que el detalle salía siempre como "contenido inapropiado" sin
    decir qué se había detectado. Se usa el `detalle` que ya calcula `evaluar_contenido`.
    """
    elementos = senales.elementos
    total = len(elementos)

    # Título y color: manda el peor veredicto, con la misma precedencia que usa la
    # reacción. Así el embed y el emoji no pueden discrepar.
    # Si lo único que pasó fue la whitelist, el veredicto es `ignorado`, no `seguro`:
    # `peor([])` da SEGURO y el embed decía "Todos los elementos son seguros" en verde
    # junto a "0 elemento(s) analizado(s)", que se contradice a sí mismo.
    veredictos_efectivos = senales.veredictos
    if not veredictos_efectivos and senales.whitelist_omitidos:
        veredictos_efectivos = [Veredicto.IGNORADO]
    peor = veredictos.peor(veredictos_efectivos)
    color, titulo_texto = peor.color, peor.titulo

    conteo = Counter(e.veredicto for e in elementos)

    desc = f"**{total}** elemento(s) analizado(s) en el mensaje de {message.author.mention}:\n"
    # "Seguros" se muestra siempre, incluso a 0: un 0 ahí dice "de esto no había nada
    # limpio", que es información. Los demás solo cuando hay, para no llenar el embed
    # de filas a cero.
    for v in ORDEN_CONTADORES:
        n = conteo.get(v, 0)
        if n or v is Veredicto.SEGURO:
            desc += f"{v.emoji} {v.contador}: **{n}**\n"
    if senales.omitidos:
        desc += (f"{EMOJI_COOLDOWN} **{senales.omitidos}** archivo(s) omitido(s) "
                 f"(límite {MAX_ADJUNTOS_POR_MENSAJE} por mensaje)\n")
    if senales.cooldown:
        desc += f"{EMOJI_COOLDOWN} Límite de análisis alcanzado: no se revisaron los enlaces\n"
    # La whitelist es un dato, no un veredicto. Antes tenía su propia reacción, que se
    # ponía antes de conocer el resultado y nunca se quitaba: un mensaje con un enlace
    # en whitelist y otro malicioso salía marcado con las dos, que se lee contradictorio.
    if senales.whitelist_omitidos:
        desc += (f"{EMOJI_WHITELIST} **{senales.whitelist_omitidos}** enlace(s) en "
                 "whitelist, no analizados")

    embed = emb.aviso(titulo_texto, desc.rstrip("\n"), color=color,
                      icono=emb.EMOJI_SHIELD, con_pie=False)

    def _linea(elemento: Elemento, extra: str = "") -> str:
        linea = f"{elemento.veredicto.emoji} `{elemento.nombre}`"
        if extra:
            linea += f" — {extra}"
        return linea

    def _extra_url(e: Elemento) -> str:
        if e.veredicto is Veredicto.MALICIOSO:
            return f"{e.mal} detecciones"
        if e.veredicto is Veredicto.SOSPECHOSO:
            return "sospechoso"
        if e.veredicto is Veredicto.PHISHING:
            return e.detalle_contenido or "suplanta una marca"
        if e.veredicto is Veredicto.ERROR:
            return _motivo_de_error(e.modelos)
        return ""

    urls = [e for e in elementos if e.tipo == "url"]
    if urls:
        lineas = []
        for e in urls:
            extra = _extra_url(e)
            if e.vt_link:
                etiqueta = emb.enlace_informe(e.vt_link)
                extra = f"{extra} · {etiqueta}" if extra else etiqueta
            lineas.append(_linea(e, extra))
        embed.add_field(name=f"{EMOJI_LINK} URLs", value="\n".join(lineas)[:1024], inline=False)

    imgs_url = [e for e in elementos if e.tipo == "image_url"]
    if imgs_url:
        lineas = [_linea(e, e.detalle_contenido) for e in imgs_url]
        embed.add_field(name=f"{EMOJI_NSFW} Imágenes (URL)",
                        value="\n".join(lineas)[:1024], inline=False)

    imgs = [e for e in elementos if e.tipo == "image"]
    if imgs:
        lineas = []
        for e in imgs:
            if e.veredicto in (Veredicto.NSFW, Veredicto.RESTRINGIDO):
                extra = e.detalle_contenido or e.veredicto.titulo
            elif e.veredicto is Veredicto.MALICIOSO:
                extra = f"{e.mal} detecciones de malware"
            elif e.veredicto is Veredicto.SOSPECHOSO:
                extra = "sospechoso"
            elif e.veredicto is Veredicto.ERROR:
                extra = _motivo_de_error(e.modelos)
            else:
                extra = "imagen"

            # El enlace al informe de VT y los nombres de los antivirus se guardan en
            # `models` pero no se mostraban nunca. Sin eso, el acierto de caché daba
            # menos información que el camino fresco, que es justo al revés de lo que
            # sirve una caché: el moderador de una imagen marcada no tenía forma de ir
            # al informe a comprobarlo.
            vt_link = e.modelos.get("vt_link")
            if vt_link and e.veredicto in (Veredicto.MALICIOSO, Veredicto.SOSPECHOSO):
                extra = f"{extra} · {emb.enlace_informe(vt_link)}"

            linea = _linea(e, extra)
            if e.modelos.get("vt_omitido"):
                linea += f"\n   {EMOJI_REPLY} Sin comprobar en VirusTotal"
            if e.hay_senal_de_nombre:
                linea += _avisos_de_nombre(e)
            lineas.append(linea)
        embed.add_field(name=f"{EMOJI_FILE} Imágenes (adjuntas)",
                        value="\n".join(lineas)[:1024], inline=False)

    archivos = [e for e in elementos if e.tipo == "file"]
    if archivos:
        lineas = []
        for e in archivos:
            if e.veredicto is Veredicto.MALICIOSO:
                extra = f"{e.mal} detecciones"
            elif e.veredicto is Veredicto.SOSPECHOSO:
                extra = "sospechoso"
            elif e.veredicto is Veredicto.ERROR:
                extra = _motivo_de_error(e.modelos)
            else:
                extra = "limpio"
            linea = _linea(e, extra)
            if e.hay_senal_de_nombre:
                linea += _avisos_de_nombre(e)
            lineas.append(linea)
        embed.add_field(name=f"{EMOJI_FILE} Archivos", value="\n".join(lineas)[:1024], inline=False)

    # Redirecciones: se generan desde los propios resultados, así que funciona igual con
    # una URL que con cinco. Antes solo se rellenaba en la rama de URL única.
    redirecciones = [e for e in urls if e.redireccion]
    if redirecciones:
        lineas = [f"`{e.nombre}`\n→ `{e.redireccion}`" for e in redirecciones]
        etiqueta = "Redirección" if len(redirecciones) == 1 else "Redirecciones"
        embed.add_field(name=f"{EMOJI_REPLY} {etiqueta}",
                        value="\n".join(lineas)[:1024], inline=False)

    return emb.pie(embed, f"Análisis de mensaje · {total} elemento(s)")


def _veredicto_de_contenido(config: dict, models: dict) -> tuple[Veredicto, float, str]:
    """Veredicto de contenido de una imagen, con los umbrales de SU servidor.

    Existe para que ninguna rama pueda dejar de mirar la configuración. Las tres que
    deciden el veredicto de una imagen (adjunto, URL con acierto de caché y URL
    descargada) llamaban a `evaluar_contenido(models)` a secas, así que el veredicto
    salía siempre de `core.config.UMBRALES_CONTENIDO`: los seis umbrales de
    `/settings` se guardaban, se leían y no cambiaban nada. Peor, no se notaba: la
    imagen marcaba o no marcaba igual en todos los servidores, y el panel parecía
    funcionar.

    Los umbrales se pasan además al pedir el análisis a SightEngine, pero eso solo
    precalcula lo que `analizar_imagen_multimodelo` guarda en su caché; quien
    devuelve el veredicto es esta función. Los umbrales son del cliente, no de la
    API: la respuesta trae probabilidades y quién decide dónde está la línea lo es
    cada servidor. Por eso se reevalúa aquí, y no se confía en el veredicto cacheado:
    un admin que baja su umbral lo ve aplicar de inmediato, también en un acierto de
    caché, en vez de tener que esperar a que caduque.
    """
    return evaluar_contenido(models, config.get("_umbrales"))


def _motivo_de_error(modelos: Optional[dict]) -> str:
    """Texto legible para un elemento que no se pudo comprobar.

    Nunca dice "seguro". La razón concreta importa: "sin cuota" y "demasiado grande"
    llevan a acciones distintas para quien lee el mensaje.
    """
    if not modelos:
        return "no se pudo comprobar"
    motivo = modelos.get("error")
    if not motivo:
        return "no se pudo comprobar"
    legibles = {
        "too_large": "demasiado grande para analizarlo",
        "sin_claves": "análisis de contenido no configurado",
        "sin_cuota": "cuota de la API agotada",
        "sin_bytes": "no se pudo leer el archivo",
        "sin_modelos": "la API no devolvió resultados",
        "modelo_no_disponible": "modelos no disponibles en la cuenta",
        "error_http": "error de la API de análisis",
        "error_excepcion": "error inesperado en el análisis",
    }
    base = legibles.get(str(motivo), str(motivo))
    detalle = modelos.get("detalle")
    return f"{base} ({detalle})" if detalle else base


def _avisos_de_nombre(elemento: Elemento) -> str:
    """Líneas de aviso sobre el nombre del archivo.

    Indentadas y con el emoji de reply, para que se lean como aviso del archivo de
    arriba y no como un archivo más de la lista.
    """
    texto = ""
    if elemento.doble_extension:
        texto += (f"\n   {EMOJI_NOMBRE_SOSPECHOSO} Doble extensión: el nombre del "
                  f"archivo esconde la real")
    if elemento.aviso_mime:
        texto += f"\n   {EMOJI_NOMBRE_SOSPECHOSO} {elemento.aviso_mime}"
    return texto


def _resumen_breve(senales: Senales) -> str:
    """Una línea con lo esencial, para que `/history` se lea de un vistazo."""
    partes = []
    if senales.malicious:
        partes.append("malicioso")
    if senales.nsfw:
        partes.append("nsfw")
    if senales.restringido:
        partes.append("restringido")
    if senales.phishing:
        partes.append("phishing")
    if senales.suspicious:
        partes.append("sospechoso")
    if senales.error:
        partes.append("sin comprobar")
    if senales.cooldown:
        partes.append("límite alcanzado")
    if senales.whitelist_omitidos:
        partes.append(f"{senales.whitelist_omitidos} en whitelist")
    return ", ".join(partes)


async def _reputacion_de_imagen(
    bot: commands.Bot, content_hash: str, guild_id: int, user_id: int
) -> tuple[str, int, Optional[str], Optional[str]]:
    """Consulta la reputación de malware de una imagen por hash, con caché y antispam.

    Devuelve `("no_consultado", 0, None, None)` si no procede: sin claves de VT, si el
    usuario agotó su cuota, o si el hash ya está en caché de disco. Un fallo aquí NO
    convierte la imagen en error: el análisis de contenido ya se hizo y es válido; lo que
    no se pudo es la comprobación extra de malware, y eso se anota aparte.

    Se hace **después** de `evaluar_contenido` a propósito, y se salta si la imagen
    ya sale como sospechosa o maliciosa, para que el lookup nunca tape el veredicto de
    contenido ni malgaste cuota en una que ya está condemnada.
    """
    if not VT_API_KEYS:
        return "no_consultado", 0, None, None

    clave = clave_analisis("imgmal", content_hash)
    tipo, _embed, mal = await obtener_analisis_db(clave)
    if tipo is not None:
        # El enlace al informe venía de la respuesta de VT y `obtener_analisis_db` no lo
        # devuelve, así que se relee del dato crudo. Sin esto, el acierto de caché
        # mostraba el veredicto pero no dónde comprobarlo, que es el único dato que
        # necesita un moderador ante una imagen marcada.
        bruto = await obtener_datos_analisis(clave) or {}
        return tipo, mal or 0, bruto.get("vt_link"), bruto.get("top")

    if not await check_vt_user_limit(bot, guild_id, user_id):
        return "no_consultado", 0, None, None

    # Cerrojo por hash: una sola consulta a VirusTotal por hash, aunque varias copias
    # del mismo archivo lleguen a la vez.
    #
    # La deduplicación de adjuntos de arriba cubre "subieron cinco veces el mismo
    # archivo", pero no "el mismo archivo con dos nombres distintos en el mismo mensaje",
    # ni dos mensajes simultáneos. Aquí el problema es distinto y más sutil: como las
    # llamadas concurrentes comprueban la caché antes de que ninguna haya escrito, todas
    # ven MISS y todas pagan. Una caché no protege contra una avalancha sobre ella; para
    # eso está `vuelo`, que es lo mismo que ya protege a las URLs.
    async def _consultar() -> tuple[str, int, Optional[str], Optional[str]]:
        v, d, link, top = await reputacion_hash(content_hash)

        if v == "desconocido":
            # VirusTotal no conoce este archivo. Es determinista: mientras nadie lo suba,
            # un 404 seguirá siendo un 404. Sin cachearlo, cada reaparición gastaba una
            # request de la cuota gratuita para volver a aprender lo mismo.
            #
            # Se guarda "no_consultado" y no "desconocido": lo que se relee de caché tiene
            # que ser EXACTAMENTE lo que devuelve el camino fresco, o los dos caminos
            # discreparían en lo que le dicen a `_procesar_imagen`. Con "desconocido", el
            # acierto de caché no ponía la marca de "sin comprobar en VirusTotal".
            await guardar_analisis_db(clave, TIPO_HASH_DESCONOCIDO, "no_consultado")
            return "no_consultado", 0, None, None

        if v in ("sin_cuota", "error"):
            # Estos NO se cachean: son transitorios. La cuota se resetea, la red vuelve, y
            # cachearlos dejaría al bot sin comprobar imágenes de forma permanente por un
            # fallo pasajero.
            return "no_consultado", 0, None, None

        # El enlace al informe y los antivirus se guardan en `datos`, no solo en `mal`. Al
        # releer de caché solo se recupera `(tipo, embed, mal)`, así que sin esto el
        # acierto perdía justo lo que el moderador necesita para comprobar la detección.
        await guardar_analisis_db(
            clave, v, v, mal=d,
            datos={"tipo": v, "mal": d, "vt_link": link, "top": top},
        )
        await set_cache_mem(clave, v, mal=d)
        if v == "malicioso":
            await registrar_infraccion(guild_id, user_id, f"filehash:{content_hash}")
        return v, d, link, top

    return await vuelo(f"imgmal:{content_hash}", _consultar)


async def _procesar_imagen(
    bot: commands.Bot,
    message: discord.Message,
    img: discord.Attachment,
    guild_id: int,
) -> tuple[str, str, dict, str]:
    log.debug(f"Imagen: {img.filename} ({img.size} bytes)")
    # Los umbrales de contenido son por guild; sin esto el panel no serviría de nada.
    config = await obtener_config_guild(guild_id)
    # Señales de nombre, igual que en `_procesar_archivo`. Antes las imágenes no pasaban
    # por esta comprobación porque vivía dentro del handler de archivos: un
    # `foto.exe.png` o un `.png` cuyo contenido es otra cosa se colaba sin avisar.
    doble_ext, aviso_mime = verificar_nombre(
        img.filename, getattr(img, "content_type", None), _deteccion_de(img)
    )
    if img.size > MAX_IMAGE_SIZE:
        return (img.filename, "error", {"error": "too_large", "doble_extension": doble_ext, "aviso_mime": aviso_mime}, "")
    try:
        async with bot._download_sem:
            async with bot.session.get(img.url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    return (img.filename, "error", {"doble_extension": doble_ext, "aviso_mime": aviso_mime}, "")
                img_data = await resp.read()
            if len(img_data) > MAX_IMAGE_SIZE:
                return (img.filename, "error", {"error": "too_large", "doble_extension": doble_ext, "aviso_mime": aviso_mime}, "")
            # Si no se pudo sniffear antes (falló la petición Range), se hace ahora con
            # los bytes que ya están en memoria: no cuesta una descarga extra.
            det = _deteccion_de(img)
            if det is None:
                det = F.detectar(img_data)
                _cachear_deteccion(img, det)
                doble_ext, aviso_mime = verificar_nombre(img.filename, getattr(img, "content_type", None), det)
            content_hash = hashlib.sha256(img_data).hexdigest()
            async with ANALYSIS_SEMAPHORE:
                is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(
                    content_hash, img_data, config.get("_umbrales"))
            # El veredicto de contenido lo decide `evaluar_contenido`, que distingue
            # tres cosas que antes iban todas a "seguro": no había nada, no se pudo
            # comprobar, y era contenido restringido.
            veredicto, confianza, detalle = _veredicto_de_contenido(config, models)

            # Reputación de malware por hash. Una imagen puede estar limpia para
            # SightEngine y aun así ser un ejecutable con extensión .png: son dos
            # dimensiones distintas y el bot solo miraba una. Cuesta una request de VT, y
            # solo si el hash no está ya en caché de disco.
            vt_veredicto, vt_mal, vt_link, vt_top = await _reputacion_de_imagen(
                bot, content_hash, guild_id, message.author.id,
            )

            models = dict(models or {})
            if vt_veredicto in ("malicioso", "sospechoso"):
                models["vt_mal"] = vt_mal
                models["vt_link"] = vt_link
                models["vt_top"] = vt_top
                # El malware manda sobre el contenido: una imagen que es las dos cosas se
                # reporta como maliciosa, que es la etiqueta con la que un moderador
                # actúa.
                if vt_veredicto == "malicioso":
                    veredicto = Veredicto.MALICIOSO
                elif veredicto is Veredicto.SEGURO:
                    veredicto = Veredicto.SOSPECHOSO
            elif vt_veredicto == "no_consultado":
                # Constancia de que la comprobación de malware no se hizo, para que nadie
                # lea "limpio" como "comprobado por los dos lados".
                models["vt_omitido"] = True

            # Antes solo contaba `nsfw`/`seguro`, y solo en la rama de URL de imagen:
            # un adjunto con nudity, restringido o phishing no movía ningún contador, así
            # que `/stats` mostraba un `total_analisis` que no cuadrava con lo que
            # decían los embeds, y las categorías nuevas no existían.
            if not from_cache:
                await update_stats(guild_id, veredicto.value)
            if veredicto in (Veredicto.NSFW, Veredicto.RESTRINGIDO) and guild_id:
                await registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
            if doble_ext or aviso_mime:
                models["doble_extension"] = doble_ext
                models["aviso_mime"] = aviso_mime
            return (img.filename, veredicto.value, models, content_hash)
    except Exception as e:
        # Antes no había ni un log. Cualquier regresión (un bug en `verificar_nombre`, un
        # `KeyError`, la sesión caída) salía como un "error" genérico sin rastro, que es
        # justo lo que hace invisibles los fallos de verdad.
        log.exception(f"Fallo analyzing imagen {img.filename}: {e}")
        return (img.filename, "error", {"doble_extension": doble_ext, "aviso_mime": aviso_mime}, "")

async def _procesar_archivo(
    bot: commands.Bot,
    message: discord.Message,
    archivo: discord.Attachment,
    guild_id: int,
) -> tuple[str, str, int, str, str, bool]:
    """Analiza un adjunto que no es imagen.

    Devuelve (filename, tipo, mal, file_hash, wm, doble_ext). Los dos últimos van
    separados porque el llamante los usa para cosas distintas: `wm` es el aviso de que
    la extensión no cuadra con el tipo real y `doble_ext` es el patrón de scam
    clásico. Estaban fundidos en un solo slot y el modo estricto acababa borrando por el
    primero mientras el segundo se perdía.
    """
    log.debug(f"Archivo: {archivo.filename} ({archivo.size} bytes)")
    doble_ext = tiene_doble_extension(archivo.filename)
    wm = ""
    # La doble extensión ya no pone ninguna reacción aquí: antes ponía un warning a
    # mitad del análisis que luego se acumulaba con el veredicto final y dejaba el
    # mensaje con dos emojis. Ahora viaja como señal hasta `resolver_reaccion`.
    if archivo.size > MAX_FILE_SIZE:
        return (archivo.filename, "error", 0, "", "", doble_ext)
    try:
        async with bot._download_sem:
            async with bot.session.get(archivo.url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    return (archivo.filename, "error", 0, "", "", doble_ext)
                file_data = await resp.read()
                if len(file_data) > MAX_FILE_SIZE:
                    return (archivo.filename, "error", 0, "", "", doble_ext)
                # Leer el Content-Type dentro del contexto: después de salir, aiohttp
                # libera la conexión y no es un lugar fiable para consultar la respuesta.
                content_type = resp.headers.get('Content-Type', '')
            file_hash = hashlib.sha256(file_data).hexdigest()
            # Detecta por bytes si el sniff previo no llegó. Se comparan los bytes con
            # lo que declara el nombre, no solo `Content-Type` contra una lista de dos
            # extensiones: antes solo se miraba .jpg y .png, así que un PDF renombrado a
            # .webp o un ZIP a .gif pasaban sin aviso.
            det = _deteccion_de(archivo)
            if det is None:
                det = F.detectar(file_data)
                _cachear_deteccion(archivo, det)
            doble_ext, wm = verificar_nombre(archivo.filename, content_type, det)
    except Exception as e:
        log.exception(f"Fallo analizando archivo {archivo.filename}: {e}")
        return (archivo.filename, "error", 0, "", wm, doble_ext)
    clave = clave_analisis("file", file_hash)

    async def _resolver() -> tuple[str, discord.Embed, int]:
        tipo, e, m = await get_from_cache_mem(clave)
        if e is None:
            tipo, e, m = await obtener_analisis_db(clave)
            if e is not None:
                await set_cache_mem(clave, tipo, e, m)
        if e is not None:
            return tipo, e, m
        # Sin ANALYSIS_SEMAPHORE: `analizar_archivo` sondea con `sleep(55)` y un hueco
        # del pool no puede quedarse ocupado durmiendo.
        return await analizar_archivo(archivo, file_bytes=file_data, file_hash=file_hash, guild_id=guild_id, mensaje_original=message, guardar_cache=True)

    tipo, embed, mal = await vuelo(clave, _resolver)
    if tipo == "malicioso":
        await registrar_infraccion(guild_id, message.author.id, f"filehash:{file_hash}")
    return (archivo.filename, tipo, mal, file_hash, wm, doble_ext)

_detecciones: dict[int, "F.Deteccion"] = {}


def _cachear_deteccion(archivo: discord.Attachment, det) -> None:
    """Guarda la detección por bytes para que los analizadores no la repitan.

    `_analizar_adjuntos` ya leyó la cabecera; sin esto, `_procesar_imagen` y
    `_procesar_archivo` tendrían que volver a descargar para poder hacer la verificación
    de nombre.

    Si el adjunto no trae `id` no se cachea y el llamante recalcula: es una optimización,
    nunca un requisito. Un `AttributeError` aquí abortaría el análisis entero del
    adjunto y lo dejaría como error sin hash.
    """
    clave = getattr(archivo, "id", None)
    if det is not None and clave is not None:
        _detecciones[clave] = det


def _deteccion_de(archivo: discord.Attachment):
    return _detecciones.get(getattr(archivo, "id", None))


def _liberar_detecciones(adjuntos) -> None:
    for a in adjuntos:
        clave = getattr(a, "id", None)
        if clave is not None:
            _detecciones.pop(clave, None)


async def _detectar_adjunto(bot: commands.Bot, archivo: discord.Attachment):
    """Lee los primeros bytes del adjunto para clasificarlo de verdad.

    Devuelve None si no se pudo leer, y en ese caso el llamante cae a `es_imagen()`,
    que es la decisión por extensión que había antes: peor, pero nunca rompe el
    análisis.

    Solo se leen 4KB. Se pide un Range y, si el servidor lo ignora, se lee del flujo lo
    justo y se sale del contexto, así que un adjunto de 32MB no se descarga entero solo
    para classifying.
    """
    try:
        async with bot._download_sem:
            async with bot.session.get(
                archivo.url,
                headers={"Range": "bytes=0-4095"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status not in (200, 206):
                    return None
                cabecera = await resp.content.read(CABECERA_BYTES)
        if not cabecera:
            return None
        return F.detectar(cabecera)
    except Exception as e:
        log.debug(f"No se pudo detectar el tipo de {archivo.filename}: {type(e).__name__}")
        return None


async def _analizar_adjuntos(
    bot: commands.Bot,
    message: discord.Message,
    guild_id: int,
    config: Optional[dict] = None,
) -> tuple[list, list, int]:
    """Analiza adjuntos y retorna (img_results, arch_results, omitidos) sin enviar nada.

    El reparto entre "imagen" y "archivo" lo deciden los bytes, no el nombre. Antes se
    hacía con `es_imagen()`, que mira la extensión y el `Content-Type` que Discord deduce
    del nombre: un ejecutable llamado `malware.png` pasaba por ahí, se.ibía solo a
    SightEngine y el malware no se escaneaba nunca. Y al revés, `foto.exe.png` entraba
    como imagen y se saltaba la verificación MIME y la detección de doble extensión.
    """
    adjuntos = message.attachments[:MAX_ADJUNTOS_POR_MENSAJE]
    omitidos = max(0, len(message.attachments) - MAX_ADJUNTOS_POR_MENSAJE)

    # Dedupica adjuntos idénticos antes de analizar.
    #
    # Del log de producción: al subir cinco veces el mismo `image.png` en un mensaje se
    #Logged:
    #
    #     SQLITE MISS → imgmal:077d18ed...   x5
    #     VT HASH NUEVO → 077d18ed...         x5
    #
    # Las cinco copias son la misma imagen, pero se analizaban las cinco. El peor detalle:
    # como las cinco comprueban la caché a la vez y ninguna ha terminado de escribir cuando
    # las demás preguntan, las cinco dan MISS y las cinco pagan una request a
    # VirusTotal. La caché no ayuda contra eso: no es un fallo de caché, es una avalancha
    # sobre ella.
    #
    # Se agrupa por nombre y tamaño. Dos archivos distintos con el MISMO nombre y el
    # MISMO tamaño byte a byte no existen en la práctica, así que el riesgo de agrupar de más
    # más es nulo; el de no agrupar es real y lo acabamos de ver.
    unicos: list[discord.Attachment] = []
    vistos: set[tuple[str, int]] = set()
    repetidos = 0
    for a in adjuntos:
        marca = (a.filename.lower(), a.size)
        if marca in vistos:
            repetidos += 1
            continue
        vistos.add(marca)
        unicos.append(a)
    if repetidos:
        log.info(
            f"Mensaje {message.id}: {repetidos} adjunto(s) duplicado(s) no se analizan "
            f"otra vez ({len(adjuntos)} -> {len(unicos)})"
        )
    adjuntos = unicos

    # Detecta por bytes. Va en paralelo porque son peticiones de red y cada una puede
    # tardar; si una falla, `None` hace que ese adjunto use la pista por extensión.
    detecciones = await asyncio.gather(
        *[_detectar_adjunto(bot, a) for a in adjuntos], return_exceptions=True
    )

    imagenes: list[discord.Attachment] = []
    otros: list[discord.Attachment] = []
    for archivo, det in zip(adjuntos, detecciones):
        det = det if isinstance(det, F.Deteccion) else None
        _cachear_deteccion(archivo, det)
        # Los bytes mandan. Solo si no se pudo leer, la extensión.
        es_img = det.es_imagen if det is not None else es_imagen(archivo)
        (imagenes if es_img else otros).append(archivo)

    omit_msg = f", {omitidos} omitidos" if omitidos else ""
    log.debug(f"Adjuntos: {len(imagenes)} imágenes, {len(otros)} archivos{omit_msg}")

    await _controlador_para(bot, message).loading()
    try:
        if imagenes:
            tareas_img = [_procesar_imagen(bot, message, img, guild_id) for img in imagenes]
            resultados_img = await asyncio.gather(*tareas_img, return_exceptions=True)
        else:
            resultados_img = []

        if otros:
            tareas_arch = [_procesar_archivo(bot, message, archivo, guild_id) for archivo in otros]
            resultados_arch = await asyncio.gather(*tareas_arch, return_exceptions=True)
        else:
            resultados_arch = []
    finally:
        await safe_remove_loading(bot, message)
        #Va en el `finally`, no después: si un adjunto revienta, `gather` sin
        # `return_exceptions` propagaba la excepción y `_detecciones` se quedaba con las
        # entradas de ese mensaje para siempre. Como el mapa no tiene TTL, eso es una
        # fuga que crece con cada mensaje problemático.
        _liberar_detecciones(adjuntos)

    resultados_img = [r for r in resultados_img if isinstance(r, tuple)]
    resultados_arch = [r for r in resultados_arch if isinstance(r, tuple)]
    return resultados_img, resultados_arch, omitidos


async def _analizar_adjuntos_si_hay(
    bot: commands.Bot,
    message: discord.Message,
    guild_id: int,
    config: Optional[dict] = None,
) -> tuple[list, list, int]:
    if message.attachments:
        return await _analizar_adjuntos(bot, message, guild_id, config)
    return [], [], 0

_limpiar_url = limpiar_url


def _controlador_para(bot: commands.Bot, message: discord.Message) -> ReactionController:
    """Devuelve el ReactionController del mensaje, creándolo si no existe.

    Vive en el bot y no como variable local a propósito: `on_message` y
    `on_message_edit` pueden procesar el mismo mensaje a la vez, y dos instancias
    compitiendo se quitarían y pondrían emojis sin coordinarse.
    """
    cache = getattr(bot, "_reaction_controllers", None)
    if cache is None:
        cache = {}
        bot._reaction_controllers = cache
    ctrl = cache.get(message.id)
    if ctrl is None:
        ctrl = ReactionController(message)
        cache[message.id] = ctrl
    return ctrl


def _liberar_controlador(bot: commands.Bot, message: discord.Message) -> None:
    """Saca el controlador del cache cuando el análisis ya terminó.

    Sin esto el dict crece con un controlador por cada mensaje analizado, para siempre.
    Es una fuga silenciosa: no da error, solo memoria, y su ritmo depende del tráfico del
    servidor. Se limpia después de poner el veredicto, que es cuando deja de hacer falta.
    """
    cache = getattr(bot, "_reaction_controllers", None)
    if cache is not None:
        cache.pop(message.id, None)


def debe_borrar(has_threat: bool, has_doble_ext: bool, has_mime_mismatch: bool, strict_mode: bool) -> bool:
    """Si el modo estricto debe eliminar el mensaje.

    Las tres señales son "esto no es lo que dice ser": una amenaza confirmada, una doble
    extensión (`informe.pdf.exe`) o una extensión que no cuadra con el tipo que sirve el
    servidor. Las dos últimas son el mismo patrón de scam visto por los dos lados.

    Antes esta condición leía el aviso de MIMEMismatch del slot que la tupla de archivos
    llevaba, así que el modo estricto borraba por el motivo equivocado y nunca borraba
    por doble extensión, que es justo lo que el comando documenta que hace.
    """
    return strict_mode and (has_threat or has_doble_ext or has_mime_mismatch)


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

    # `silent_mode` ya no se lee aquí: la decisión de avisar la toma `debe_enviar_embed`,
    # que conoce los tres interruptores. Tenerla en dos sitios hacía que secould divergieran.
    strict_mode = config["strict_mode"]
    log_channel_id = config["log_channel_id"]
    whitelist = config.get("whitelist", [])

    urls = [_limpiar_url(u) for u in PATRON_URL.findall(message.content)]
    # El `id` del mensaje va al log a propósito. Sin él no se puede distinguir "el
    # usuario publicó tres mensajes con la misma imagen" de "el mismo mensaje se está
    # analizando tres veces", que son fallos muy distintos y con el log anterior no había
    # forma de decidirlo.
    log.debug(
        f"Mensaje {message.id} de {message.author} en guild={guild_id}: "
        f"{len(urls)} URLs, {len(message.attachments)} adjuntos"
    )

    # --- Colectores de resultados para el embed unificado ---
    url_results: list[UrlResult] = []             # ver UrlResult
    img_url_results: list[ImgUrlResult] = []      # ver ImgUrlResult
    img_results: list[tuple[str, str, dict, str]] = []          # (filename, tipo, models, content_hash)
    arch_results: list[tuple[str, str, int, str, str, bool]] = []  # (filename, tipo, mal, file_hash, wm, doble_ext)
    omitidos = 0
    # Antes cada uno de estos eventos ponía su propia reacción. Ahora solo son señales
    # y el embed los cuenta; la única reacción la decide `resolver_reaccion`.
    _cooldown_activado = False
    _whitelist_omitidos = 0

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
                # Solo se cuenta. La reacción la pone al final `resolver_reaccion`, que
                # además tiene en cuenta lo demás: ponerla aquí marcaba como confiable un
                # mensaje que|resultara malicioso.
                _whitelist_omitidos += 1

        # Anti-phishing local, antes de gastar cuota en nada.
        #
        # Va aquí, por encima de las dos ramas de análisis de URL, porque la detección es
        # de texto puro: no necesita red ni VirusTotal. Así los dominios claramente
        # falsos no consumen ni una request de la cuota gratuita, que es el recurso escaso.
        # El veredicto es informativo: no borra ni registra infracción.
        urls_sospechosas: list[UrlResult] = []
        if todas_urls and config.get("detectar_phishing", True):
            urls_limpias: list[str] = []
            for url in todas_urls:
                veredicto = detectar_phishing(url)
                if veredicto.es_phishing:
                    log.info(f"PHISHING → {url} :: {veredicto.razon}")
                    urls_sospechosas.append(UrlResult(
                        url, "phishing", 0, None, f"phish:{url}", True, None,
                    ))
                else:
                    urls_limpias.append(url)
            todas_urls = urls_limpias

        if not todas_urls:
            # Todas en whitelist o ya marcadas como phishing.
            #
            # Aquí ya no se manda ningún mensaje propio. Antes se respondía "Dominio(s)
            # en whitelist" y luego, además, el embed: dos avisos para un solo evento.
            # Y el reply era menos útil que el embed, que además dice cuántos enlaces
            # hubo. Ahora manda el embed y `debe_enviar_embed` decide si se manda, que
            # incluye el caso de la whitelist aunque el modo silencioso esté activo.
            img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id, config)
            url_results = urls_sospechosas
        else:
            url_results = urls_sospechosas
            log.debug(f"URLs tras whitelist: {len(todas_urls)} de {len(urls)}")

            # Sólo se cobra cuota de antispam si el mensaje va a consumir API de verdad:
            # repetir un enlace que ya está en caché no llama a VirusTotal.
            va_a_consumir_api = bool(message.attachments)
            if not va_a_consumir_api:
                for url in todas_urls:
                    clave_check = clave_analisis("url", url)
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
                _cooldown_activado = True
                img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id, config)
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
                            is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(
                                cached_hash, b"", config.get("_umbrales"))
                            if from_cache:
                                # El veredicto y el detalle los compone `evaluar_contenido`, como en
                                # `_procesar_imagen`. Esta rama leia `models['nudity']`, clave que ya no
                                # existe, con umbrales escritos a mano: el detalle salia siempre como
                                # "Contenido inapropiado" sin decir que se detecto, y alcohol o armas
                                # quedaban etiquetados como `nsfw`.
                                _v, _conf, detalles_str = _veredicto_de_contenido(config, models)
                                img_url_results.append(ImgUrlResult(
                                    url, _v.value, detalles_str, f"nsfw:{cached_hash}"))
                                if _v in (Veredicto.NSFW, Veredicto.RESTRINGIDO) and guild_id:
                                    await registrar_infraccion(
                                        guild_id, message.author.id, f"nsfw:{cached_hash}")
                                # Procesar adjuntos y mostrar embed unificado
                                img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(
                                    bot, message, guild_id)
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
                                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(
                                        content_hash, img_data, config.get("_umbrales"))
                                    # Solo en cache-miss, igual que en `_procesar_imagen`
                                    # y que en las URLs.
                                    if not from_cache and not models.get("error"):
                                        await update_stats(guild_id, "nsfw" if is_nsfw else "seguro")
                                    await set_cache_mem(clave_meta_url, json.dumps({"hash": content_hash}), datos={"hash": content_hash})
                                    await guardar_metadatos_hash(clave_meta_url, content_hash)

                                    if models.get("error") == "too_large":
                                        img_url_results.append(ImgUrlResult(url, "error", "Supera el límite de Sightengine"))
                                    else:
                                        # Veredicto y detalle los compone `evaluar_contenido`,
                                        # igual que en el acierto de caché y en los adjuntos.
                                        # Esta rama leía `models['nudity']`, clave que ya no
                                        # existe, con umbrales a mano: el detalle salía siempre
                                        # como "Contenido inapropiado" y alcohol o armas
                                        # quedaban etiquetados como `nsfw`.
                                        _v, _conf, detalles_str = _veredicto_de_contenido(config, models)
                                        img_url_results.append(ImgUrlResult(
                                            url, _v.value, detalles_str, f"nsfw:{content_hash}"))
                                        if _v in (Veredicto.NSFW, Veredicto.RESTRINGIDO) and guild_id:
                                            await registrar_infraccion(
                                                guild_id, message.author.id, f"nsfw:{content_hash}")
                            finally:
                                await safe_remove_loading(bot, message)
                            img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id, config)

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
                            clave = clave_analisis("url", url)

                            async def _resolver_url() -> Optional[tuple[str, discord.Embed, int, bool]]:
                                """Mira caché y, si no hay, llama a VT. Solo esto va en
                                el vuelo: registrar la infracción o reaccionar depende
                                del mensaje de cada uno, no del análisis.

                                El cuarto valor dice si VT mandó ya el log de amenaza
                                por ESTE mensaje. Solo lo es cuando la llamada es la que
                                realmente ha ido a la API: quien espera el vuelo recibe
                                el análisis de otro, así que su mensaje necesita log
                                propio, igual que el que llegó a la caché.

                                Devuelve None cuando a este usuario le toca su propio
                                límite de VT: es una decisión suya, no de la clave, así
                                que no se comparte y quien espere lo reintenta por su
                                cuenta.
                                """
                                t, e, m = await get_from_cache_mem(clave)
                                if e is not None:
                                    log.debug(f"Cache HIT (RAM) para URL → resultado={t}")
                                    return t, e, m, False
                                t, e, m = await obtener_analisis_db(clave)
                                if e is not None:
                                    log.debug(f"Cache HIT (SQLite) para URL → resultado={t}")
                                    await set_cache_mem(clave, t, e, m)
                                    return t, e, m, False
                                log.debug("Cache MISS para URL → llamando VT")
                                if not await check_vt_user_limit(bot, guild_id, message.author.id):
                                    # `SIN_RESPUESTA`, no `None`. `vuelo()` trata `None`
                                    # como resultado legitimo y lo reparte a todos los
                                    # esperadores: un usuario que agota su cupo hacia que
                                    # todos los demas analysing el mismo enlace recibieran
                                    # un error falso y se quedaran sin escanear. Con
                                    # `SIN_RESPUESTA` cada esperador lo reintenta por su
                                    # cuenta, que es justo lo que documenta `vuelo`.
                                    return SIN_RESPUESTA
                                await safe_add_reaction(message, EMOJI_LOADING)
                                try:
                                    t, e, m = await analizar_url(url, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                                    return t, e, m, True
                                finally:
                                    await safe_remove_loading(bot, message)

                            resolucion = await vuelo(clave, _resolver_url)
                            if resolucion is None or resolucion is SIN_RESPUESTA:
                                # Cuota agotada para este usuario: se informa sin informe.
                                url_results.append(UrlResult(
                                    url_original_str, "error", 0, None, f"url:{url}", False,
                                    url_expandida_str if url_fue_expandida else None,
                                ))
                            else:
                                tipo, embed, mal, ya_logueado = resolucion
                                elemento_id = f"url:{url}"
                                if tipo == "malicioso":
                                    await registrar_infraccion(guild_id, message.author.id, elemento_id)
                                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                                # El enlace también para los sospechosos: es justo cuando
                                # el moderador necesita ir a mirar el informe a ver quién
                                # lo marcó y por qué.
                                con_informe = tipo in ("malicioso", "sospechoso")
                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if con_informe else None
                                url_results.append(UrlResult(
                                    url_original_str, tipo, mal, vt_link, elemento_id, ya_logueado,
                                    url_expandida_str if url_fue_expandida else None,
                                ))

                        img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id, config)

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
                                    # `SIN_RESPUESTA` y no `None`, por el mismo motivo que
                                    # las otras dos ramas: `vuelo()` reparte `None` como si
                                    # fuera un resultado y el llamador lo desempaqueta.
                                    return SIN_RESPUESTA
                            clave = clave_analisis("url", url_exp)

                            async def _leer_cache():
                                tipo, e, m = await get_from_cache_mem(clave)
                                if e is None:
                                    tipo, e, m = await obtener_analisis_db(clave)
                                    if e is not None:
                                        await set_cache_mem(clave, tipo, e, m)
                                return tipo, e, m

                            tipo, embed, mal = await vuelo(clave, _leer_cache)
                            return (url_original, url_exp, tipo, embed, mal, fue_exp)

                        expandidos = await asyncio.gather(*[_expandir_y_cache(url) for url in todas_urls], return_exceptions=True)
                        expandidos = [r for r in expandidos if isinstance(r, tuple)]

                        # Los que ya estaban en caché no vuelven a llamar a la API, así que
                        # el bot no mandó log por ellos (ya_logueado=False).
                        pendientes: list[tuple[str, str, Optional[str]]] = []
                        for url_orig, url_exp, tipo, embed, mal, fue_exp in expandidos:
                            redireccion = url_exp if fue_exp else None
                            if embed is not None:
                                elemento_id = f"url:{url_exp}"
                                if tipo == "malicioso":
                                    await registrar_infraccion(guild_id, message.author.id, elemento_id)
                                url_id = base64.urlsafe_b64encode(url_exp.encode()).decode().rstrip("=")
                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if tipo in ("malicioso", "sospechoso") else None
                                url_results.append(UrlResult(
                                    url_orig, tipo, mal, vt_link, elemento_id, False, redireccion,
                                ))
                            else:
                                pendientes.append((url_orig, url_exp, redireccion))

                        if pendientes:
                            async def _api_url(url_orig: str, url_exp: str, redireccion: Optional[str]) -> Optional[UrlResult]:
                                clave_api = clave_analisis("url", url_exp)

                                async def _llamar_vt() -> Optional[tuple[str, discord.Embed, int, bool]]:
                                    if not await check_vt_user_limit(bot, guild_id, message.author.id):
                                        # Ver la nota de la otra rama: `None` envenena a los
                                        # esperadores de `vuelo()`.
                                        return SIN_RESPUESTA
                                    # Sin ANALYSIS_SEMAPHORE: `analizar_url` duerme 55s
                                    # entre sondeos y sostener un hueco del pool durante el
                                    # sueño bloqueaba el análisis del resto. El límite real
                                    # de VT lo aplica `adquirir_vt()` por key.
                                    t, e, m = await analizar_url(url_exp, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                                    return t, e, m, True

                                resolucion = await vuelo(clave_api, _llamar_vt)
                                if resolucion is None or resolucion is SIN_RESPUESTA:
                                    return UrlResult(url_orig, "error", 0, None, f"url:{url_exp}", False, redireccion)
                                tipo, embed, mal, ya_logueado = resolucion
                                url_id = base64.urlsafe_b64encode(url_exp.encode()).decode().rstrip("=")
                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}" if tipo in ("malicioso", "sospechoso") else None
                                # _on_threat_found manda el log con eid = f"url:{url_exp}",
                                # pero solo si esta llamada fue la que fue a la API.
                                # Quien espera el vuelo comparte el análisis, no el log:
                                # su mensaje necesita el suyo.
                                return UrlResult(url_orig, tipo, mal, vt_link, f"url:{url_exp}", ya_logueado, redireccion)

                            api_resultados = await asyncio.gather(*[_api_url(uo, ue, rd) for uo, ue, rd in pendientes], return_exceptions=True)
                            for r in api_resultados:
                                if isinstance(r, UrlResult):
                                    url_results.append(r)
                    finally:
                        await safe_remove_loading(bot, message)

                    img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id, config)

    else:
        # Solo adjuntos (sin URLs)
        img_results, arch_results, omitidos = await _analizar_adjuntos_si_hay(bot, message, guild_id, config)

    # --- Construir y enviar embed unificado ---
    total_elementos = len(url_results) + len(img_url_results) + len(img_results) + len(arch_results)
    if total_elementos == 0 and not _whitelist_omitidos:
        # El controlador se creo al poner el emoji de progreso, asi que tambien hay que
        # soltarlo aqui: sin esto esta salida era la que mas fugaba.
        _liberar_controlador(bot, message)
        return

    # --- Señales: una foto de todo lo que se ha detectado ---
    # Reemplaza a las catorce variables locales que se arrastraban por la función. Las
    # banderas son properties, así que no pueden quedar desincronizadas de los datos.
    senales = desde_tuplas(url_results, img_url_results, img_results, arch_results)
    senales.cooldown = _cooldown_activado
    senales.omitidos = omitidos
    senales.whitelist_omitidos = _whitelist_omitidos

    has_threat = senales.hay_amenaza
    has_doble_ext = senales.doble_ext
    has_mime_mismatch = senales.mime_mismatch

    embed = await _construir_embed_unificado(message, senales)

    # Enviar embed. `debe_enviar_embed` separa los tres interruptores: antes esta
    # condición era una suma de "algo salió mal" que no se podía desactivar por partes.
    if debe_enviar_embed(senales, config):
        await safe_send(message, embed, reference=message)

    # Una sola reacción por mensaje. El controlador es quien garantiza el invariante:
    # antes los emojis se añadían en cinco sitios y solo se quitaba el loading, así que
    # un mensaje con whitelist + doble extensión + NSFW salía con tres a la vez.
    if reacciones_activas(config):
        await _controlador_para(bot, message).set(resolver_reaccion(senales))
    else:
        await safe_remove_loading(bot, message)
    # El analisis termino: el controlador ya no hace falta y el cache debe quedar limpio.
    _liberar_controlador(bot, message)

    # Registro para /history. Nunca lanza: es un extra informativo, y perder un
    # registro no puede tumbar un análisis que ya se ha hecho y publicado.
    if total_elementos:
        try:
            await registrar_evento(
                guild_id, message.channel.id, message.id, message.author.id,
                total_elementos, veredictos.peor(senales.veredictos).value,
                _resumen_breve(senales),
            )
        except Exception as e:
            log.debug(f"No se registró el evento de /history: {type(e).__name__}")

    # Strict mode
    if debe_borrar(has_threat, has_doble_ext, has_mime_mismatch, strict_mode):
        try:
            await message.delete()
        except (discord.errors.Forbidden, discord.errors.NotFound):
            pass

    # Logs por cada amenaza detectada. `elemento_id` tiene que ser el MISMO que se usó al
    # registrar la infracción (la URL expandida), o el botón "Ignorar" del log no
    # encontraría la infracción que intentaría descontar.
    # Los sospechosos no llegan aquí: no hay infracción que ignorar, así que un log con
    # botón "Ignorar" respondería "esa infracción ya no existe".
    if log_channel_id:
        for r in url_results:
            if r.tipo == "malicioso" and not r.ya_logueado:
                await enviar_log_guild(
                    guild_id, "URL", r.url, f"{r.mal} detecciones", message.author,
                    url_vt=r.vt_link, elemento_id=r.elemento_id,
                )
        for r in img_url_results:
            if r.tipo in ("nsfw", "restringido"):
                await enviar_log_guild(guild_id, "Imagen NSFW" if r.tipo == "nsfw" else "Contenido restringido", r.url, r.detalles, message.author, elemento_id=r.elemento_id or None, es_nsfw=(r.tipo == "nsfw"))
        for filename, tipo, models, content_hash in img_results:
            if tipo in ("nsfw", "restringido") and content_hash:
                await enviar_log_guild(guild_id, "Imagen NSFW" if tipo == "nsfw" else "Contenido restringido", filename, models.get("detalle") or "Detectado en análisis múltiple", message.author, elemento_id=f"nsfw:{content_hash}", es_nsfw=(tipo == "nsfw"))
        for filename, tipo, mal, file_hash, _wm, _doble_ext in arch_results:
            if tipo == "malicioso":
                # Mismo elemento_id que usa _procesar_archivo al registrar la infracción.
                await enviar_log_guild(
                    guild_id, "Archivo (múltiples)", filename, f"{mal} detecciones", message.author,
                    elemento_id=f"filehash:{file_hash}" if file_hash else None,
                )
