import re
import time
import asyncio
import socket
import ipaddress
from typing import Optional
import aiohttp
import discord
import urllib.parse
import logging
from collections import OrderedDict
from discord.ext import commands
from core.config import (
    EMOJI_LOADING, ANTIVIRUS_CONOCIDOS, IMAGE_EXTENSIONS,
    VT_MAX_ANALYSES_PER_MINUTE,
    ANTISPAM_ANALYSIS_PER_HOUR, ANTISPAM_COOLDOWN, ANTISPAM_WINDOW,
)

log = logging.getLogger("utils")
_dns_cache: OrderedDict[str, tuple[float, str]] = OrderedDict()
_DNS_CACHE_TTL: float = 300.0
_DNS_CACHE_MAX: int = 5000

# Bloque compartido (RFC 6598). ipaddress.is_private devuelve False y is_global también
# False aquí, así que hay que rechazarlo explícitamente: son direcciones de una red de
# operador que no deberían ser alcanzables desde el contenedor del bot.
_CGNAT: ipaddress.IPv4Network = ipaddress.ip_network("100.64.0.0/10")


def _ip_permitida(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True si la IP es de alcance global y unicast (es decir, alcanzable desde Internet).

    Cubre lo que `is_private` ya cubre (RFC 1918, loopback, link-local, ULA, etc.) más
    los huecos que dejaba: reservado, multicast, sin especificar y CGNAT.
    """
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return False
    if ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified:
        return False
    if ip_obj.version == 4 and ip_obj in _CGNAT:
        return False
    return True


async def _url_a_ip(url: str) -> tuple[Optional[str], Optional[str]]:
    """Reescribe el netloc de `url` a la IP resuelta conservando puerto y esquema IPv6.

    Devuelve (url_por_ip, error). Conectar por IP y mandar el Host original evita el
    DNS rebinding: la resolución que validamos es la misma con la que conectamos.
    """
    try:
        segura, hostname, ip, err = await _resolve_url(url)
    except Exception as e:
        return None, f"Error verificando URL: {e}"
    if not segura or not ip or not hostname:
        return None, err or "URL no segura"
    try:
        parsed = urllib.parse.urlparse(url)
        port_part = f":{parsed.port}" if parsed.port else ""
        ip_netloc = f"[{ip}]{port_part}" if ":" in ip else f"{ip}{port_part}"
        return urllib.parse.urlunparse(parsed._replace(netloc=ip_netloc)), None
    except Exception as e:
        return None, f"Error reconstruyendo URL: {e}"

async def safe_remove_loading(bot: commands.Bot, msg: discord.Message) -> None:
    try:
        await msg.remove_reaction(EMOJI_LOADING, bot.user)
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass

async def safe_add_reaction(msg: discord.Message, emoji: str) -> None:
    try:
        await msg.add_reaction(emoji)
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass

async def safe_send(msg: discord.Message, embed: discord.Embed, reference: Optional[discord.Message] = None) -> None:
    try:
        if reference:
            await msg.channel.send(embed=embed, reference=reference)
        else:
            await msg.channel.send(embed=embed)
    except (discord.NotFound, discord.Forbidden):
        pass
    except discord.HTTPException:
        try:
            await msg.channel.send(embed=embed)
        except (discord.HTTPException, discord.NotFound, discord.Forbidden):
            pass

def dominio_en_whitelist(dominio: str, whitelist: list[str]) -> bool:
    dominio = dominio.lower().strip()
    for d in whitelist:
        d = d.lower().strip()
        if dominio == d or dominio.endswith("." + d):
            return True
    return False

def es_imagen(archivo: discord.Attachment) -> bool:
    if any(archivo.filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
        return True
    if archivo.content_type and archivo.content_type.startswith('image/'):
        return True
    return False

def _texto_exc(exc: BaseException) -> str:
    """str(exc) sin riesgo de que el propio formateador reviente.

    Algunas excepciones de aiohttp lanzan en su __str__ si no se construyeron con
    todos sus atributos (ClientConnectorError accede a _conn_key). Este código corre
    justo cuando algo ya ha fallado, así que no puede permitirse fallar también.
    """
    try:
        return str(exc)
    except Exception:
        return ""


def _motivo_legible(exc: BaseException) -> str:
    """Convierte una excepción de red en un motivo corto y presentable.

    Nunca se muestra str(exc) al usuario: los tracebacks de aiohttp/openssl incluyen IPs
    internas, rutas del servidor y nombres de módulo, y además ocupaban media pantalla
    dentro del embed. El detalle completo va al log; aquí solo el "por qué" útil.
    """
    if isinstance(exc, asyncio.TimeoutError):
        return "La solicitud tardó demasiado"
    if isinstance(exc, aiohttp.TooManyRedirects):
        return "Demasiadas redirecciones"
    nombre = type(exc).__name__
    if "Certificate" in nombre or "CertificateError" in nombre:
        return "No se pudo verificar el certificado de seguridad del sitio"
    if "SSL" in nombre or "SSLError" in nombre:
        return "Error de conexión segura con el sitio"
    if "DNS" in nombre or "NameResolution" in nombre or "getaddrinfo" in _texto_exc(exc):
        return "No se pudo resolver el dominio"
    if isinstance(exc, aiohttp.ClientConnectionError) or "ClientConnector" in nombre:
        return "No se pudo conectar con el sitio"
    if isinstance(exc, OSError):
        return "Error de red al descargar"
    return "No se pudo completar la descarga"


async def url_es_imagen(url: str, bot: Optional[commands.Bot] = None) -> bool:
    ruta = url.split('?')[0]
    if any(ruta.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
        return True
    if bot is None:
        return False
    # Esta es la PRIMERA petición que se hace contra una URL escrita por un usuario, así
    # que tiene que pasar por la misma validación SSRF que el resto de rutas y conectar
    # por IP con el header Host original.
    url_ip, err = await _url_a_ip(url)
    if not url_ip:
        log.debug(f"url_es_imagen bloqueada → {url}: {err}")
        return False
    hostname = urllib.parse.urlparse(url).hostname or ""
    try:
        async with bot.session.head(
            url_ip, allow_redirects=False, headers={"Host": hostname},
            server_hostname=hostname or None,
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            ct = resp.headers.get('Content-Type', '')
            return ct.startswith('image/')
    except Exception:
        return False

def obtener_top_antivirus(results: dict) -> list[str]:
    detectados: list[str] = []
    for antivirus in ANTIVIRUS_CONOCIDOS:
        for key, value in results.items():
            if antivirus.lower() in key.lower() and value.get("category") == "malicious":
                detectados.append(key)
                break
        if len(detectados) >= 3:
            break
    return detectados

def barra_porcentaje(porcentaje: float, longitud: int = 10) -> str:
    lleno = int(round(longitud * (porcentaje / 100)))
    vacio = longitud - lleno
    return "█" * lleno + "░" * vacio

async def _resolve_url(url: str) -> tuple[bool, str, str, str]:
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "", "", "URL sin hostname"
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if not _ip_permitida(ip_obj):
                return False, "", "", f"IP no global: {hostname}"
            return True, hostname, hostname, ""
        except ValueError:
            pass
        ahora = time.time()
        cached = _dns_cache.get(hostname)
        if cached and ahora < cached[0]:
            _dns_cache.move_to_end(hostname)
            return True, hostname, cached[1], ""
        addrs = await asyncio.get_running_loop().getaddrinfo(hostname, 80, type=socket.SOCK_STREAM)
        ips: list[str] = []
        for addr in addrs:
            ip_str = addr[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if not _ip_permitida(ip_obj):
                return False, "", "", f"El hostname {hostname} resuelve a IP no global: {ip_str}"
            ips.append(ip_str)
        if not ips:
            return False, "", "", f"No se pudo resolver {hostname}"
        _dns_cache[hostname] = (ahora + _DNS_CACHE_TTL, ips[0])
        _dns_cache.move_to_end(hostname)
        while len(_dns_cache) > _DNS_CACHE_MAX:
            _dns_cache.popitem(last=False)
        return True, hostname, ips[0], ""
    except Exception as e:
        return False, "", "", f"Error verificando URL: {e}"

async def es_url_segura(url: str) -> tuple[bool, str]:
    segura, _, _, err = await _resolve_url(url)
    return segura, err

def normalizar_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.netloc or "").lower()
    if ":80" in hostname and scheme == "http":
        hostname = hostname[:-3]
    elif ":443" in hostname and scheme == "https":
        hostname = hostname[:-4]
    path = parsed.path.rstrip("/") or "/"
    return urllib.parse.urlunparse((scheme, hostname, path, parsed.params, parsed.query, ""))


def clave_analisis(tipo: str, valor: str) -> str:
    """Clave de caché canónica de un elemento analizado. Fuente única de verdad.

    Antes cada sitio construía la clave por su cuenta y uno de ellos normalizaba la URL
    y otro no: la caché de 7 días quedaba de solo-escritura para el autoescaneo, que
    comparaba `url:https://x.com/` contra el `url:https://x.com` que guardaba la API, y
    cada reposteo volvía a gastar las 5 unidades de un análisis de URL desconocido.

    Solo las URLs se normalizan, porque son el único tipo con formas equivalentes
    (barra final, puerto por defecto, mayúsculas). Un hash es un hash y una IP no
    tiene variantes: normalizarlos no aportaría nada.
    """
    if tipo == "url":
        return f"url:{normalizar_url(valor)}"
    # `filehash:` y no `file:` para que coincida con lo que ya hay en RAM y en SQLite,
    # y con el elemento_id que usan las infracciones de archivos.
    if tipo == "file":
        return f"filehash:{valor}"
    return f"{tipo}:{valor}"


_vuelos: dict[str, asyncio.Future] = {}
_vuelos_lock = asyncio.Lock()

# Marca de "no he podido resolverlo": quien la recibe reintenta por su cuenta en vez
# de esperar un resultado que no existe.
class _SinRespuesta:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<SIN_RESPUESTA>"

SIN_RESPUESTA = _SinRespuesta()


async def vuelo(clave: str, calcular):
    """Ejecuta `calcular()` UNA vez por clave y devuelve el resultado a todos.

    Sin esto, veinte personas pegando a la vez el mismo enlace recién publicado
    compartían el mismo cache-miss y disparaban veinte análisis, con veinte filas en
    `/stats` y cien unidades de cuota de VirusTotal para un único enlace.

    Ojo con la tentación de usar un `asyncio.Lock`: serializa, pero no deduplica. Los
    que esperan el lock siguen ejecutando el cuerpo al soltarse, que es justo lo que
    queremos evitar. Aquí el primero pone el resultado en un `Future` compartido y el
    resto solo lo lee.

    `calcular` tiene que devolver SOLO el resultado del análisis. Los efectos que
    dependen de cada mensaje (registrar la infracción, montar el log, reaccionar) los
    hace cada uno el que llama, con el valor devuelto: si fueran parte del vuelo, el
    mensaje que esperó se quedaría sin registrar nada.

    Si el primero falla, el error se propaga a los que estaban esperando: es preferible
    que todos vean el fallo a que uno reciba un "resultado" vacío y lo lea como seguro.

    Si `calcular` devuelve `SIN_RESPUESTA`, no se guarda nada y el que esperaba reintenta
    por su cuenta. Se usa para la tasa por usuario, que es personal: si a quien abrió el
    vuelo le tocó su límite de VT, el resto no puede quedarse sin análisis solo por eso,
    porque su propio contador va aparte.
    """
    loop = asyncio.get_running_loop()
    # Reintento acotado: si el primero no pudo por su propio límite, este reintenta
    # como si fuera el primero. Dos vueltas bastan —si tampoco puede, ya no es un
    # problema de vuelo sino de cuota de VT y hay que devolverlo como error.
    for intento in range(2):
        async with _vuelos_lock:
            pendiente = _vuelos.get(clave)
            soy_el_primero = pendiente is None
            if soy_el_primero:
                pendiente = _vuelos[clave] = loop.create_future()

        if not soy_el_primero:
            log.debug(f"VUELO espera → {clave}")
            # shield: si el que espera se cancela, el Future compartido no se cancela
            # y el resto de los esperadores sigue recibiendo el resultado.
            ok, valor = await asyncio.shield(pendiente)
            if not ok:
                raise valor
            if valor is SIN_RESPUESTA and intento == 0:
                log.debug(f"VUELO reintenta → {clave}")
                continue
            return valor

        log.debug(f"VUELO primero → {clave}")
        try:
            resultado = await calcular()
        except BaseException as e:  # noqa: BLE001 - se re-lanza tras guardarlo
            await _cerrar_vuelo(clave, pendiente, False, e)
            raise
        if resultado is SIN_RESPUESTA:
            # No se resolvió nada: se suelta la clave sin guardar resultado para que el
            # siguiente pueda intentarlo por su cuenta.
            async with _vuelos_lock:
                if _vuelos.get(clave) is pendiente:
                    del _vuelos[clave]
            if not pendiente.done():
                pendiente.set_result((True, SIN_RESPUESTA))
            return SIN_RESPUESTA
        await _cerrar_vuelo(clave, pendiente, True, resultado)
        return resultado


async def _cerrar_vuelo(clave: str, pendiente: asyncio.Future, ok: bool, valor) -> None:
    async with _vuelos_lock:
        if _vuelos.get(clave) is pendiente:
            del _vuelos[clave]
    # El resultado va como tupla (ok, valor) y no con set_exception: un Future con
    # excepción que nadie llega a leer emite un aviso al final del bucle, y aquí es
    # fácil que todos los esperadores se hayan ido antes.
    if not pendiente.done():
        pendiente.set_result((ok, valor))

async def expandir_url(bot: commands.Bot, url: str) -> str:
    try:
        for _ in range(5):
            url_ip, err = await _url_a_ip(url)
            if not url_ip:
                return url
            hostname = urllib.parse.urlparse(url).hostname or ""
            async with bot.session.head(
                url_ip, allow_redirects=False, headers={"Host": hostname},
                server_hostname=hostname or None,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location')
                    if location:
                        url = urllib.parse.urljoin(url, location)
                    else:
                        break
                else:
                    break
    except Exception as e:
        log.error(f"Error expandiendo URL {url}: {e}")
    return url


async def descargar_url_segura(bot: commands.Bot, url: str, max_size: Optional[int] = None) -> tuple[Optional[bytes], Optional[str]]:
    url_ip, err = await _url_a_ip(url)
    if not url_ip:
        return None, err
    hostname = urllib.parse.urlparse(url).hostname or ""
    try:
        async with bot.session.get(
            url_ip, headers={"Host": hostname}, server_hostname=hostname or None,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            if max_size:
                cl = resp.headers.get('Content-Length')
                if cl:
                    try:
                        if int(cl) > max_size:
                            return None, "too_large"
                    except ValueError:
                        pass  # Content-Length malformado, ignorar
                data = await resp.read()
                if len(data) > max_size:
                    return None, "too_large"
                return data, None
            return await resp.read(), None
    except Exception as e:
        log.error(f"descargar_url_segura falló con {url}: {type(e).__name__}: {e}")
        return None, _motivo_legible(e)

PATRON_HASH: re.Pattern = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')

def es_hash_valido(valor: str) -> bool:
    return bool(PATRON_HASH.match(valor.strip()))

# Extensiones que el sistema puede ejecutar al abrir el archivo. Es la única lista que
# hace falta: la pregunta de seguridad es si lo que se descarga se ejecuta, no qué
# extensión de adorno lleva delante.
_EXT_EJECUTABLE = frozenset({
    'exe', 'vbs', 'vbe', 'ps1', 'bat', 'cmd', 'msi', 'msc', 'scr', 'lnk', 'com',
    'pif', 'cpl', 'jar', 'gadget', 'sh', 'app', 'command',
})


def tiene_doble_extension(filename: str) -> bool:
    """Si el nombre esconde el carácter ejecutable de una extensión inocua.

    `informe.pdf.exe` se abre como un PDF y al descargarlo resulta ser un ejecutable:
    ese engaño es lo que se avisa. La condición es que la extensión **real** —la última,
    la que manda— sea ejecutable y que delante haya otra extensión que la disimule.

    Solo mirar la extensión intermedia daba falsos positivos: `r.pdf.exe.md` dispara
    porque el medio es `.exe`, aunque lo que se descarga es un `.md` inofensivo. Y
    exigir que el cebo fuera "de documento" dejaba escapar a `guion.sh.cmd`, que también
    engaña, porque lo que se ejecuta es el `.cmd` del final.
    """
    nombre, _, real = filename.rpartition('.')
    if not nombre or not real:
        return False
    if '.' not in nombre:
        # Una sola extensión (`acceso.lnk`): no hay nada que esconda.
        return False
    return real.strip().lower() in _EXT_EJECUTABLE

import random as _random

REVIEW_PROMPT_URL = "https://top.gg/bot/1038186932456390726#reviews"
REVIEW_PROMPT_CHANCE = 0.05

async def maybe_send_review_prompt(bot, channel: discord.abc.Messageable) -> None:
    if _random.random() >= REVIEW_PROMPT_CHANCE:
        return
    from ui import embed as emb
    embed = emb.topgg(
        "Si te gusta Threat, considera [dejar una reseña en Top.gg]"
        f"({REVIEW_PROMPT_URL}) para apoyar el proyecto."
    )
    try:
        await channel.send(embed=embed)
    except Exception:
        pass

async def comprobar_antispam(bot, guild_id: Optional[int], user_id: int) -> tuple[bool, int]:
    """Comprueba y consume una unidad de antispam para (guild_id, user_id).

    Aplica dos límites: un cooldown de ANTISPAM_COOLDOWN segundos entre envíos y un
    máximo de ANTISPAM_ANALYSIS_PER_HOUR análisis por hora y usuario.

    Devuelve (permitido, segundos hasta poder reintentar). Solo consume cuota si
    permite el paso, de modo que un mensaje bloqueado no agota su propio límite.

    El estado vive en el bot (user_scan_history / antispam_scan) porque es lo que
    persiste `core/database._flush_datos` entre reinicios.
    """
    ahora = time.time()
    key: tuple[int, int] | int = (guild_id, user_id) if guild_id else user_id

    ultima = bot.antispam_scan.get(key)
    if ultima is not None and ahora - ultima < ANTISPAM_COOLDOWN:
        return False, int(ANTISPAM_COOLDOWN - (ahora - ultima))

    historial = [t for t in bot.user_scan_history.get(key, []) if ahora - t < ANTISPAM_WINDOW]
    if len(historial) >= ANTISPAM_ANALYSIS_PER_HOUR:
        return False, int(historial[0] + ANTISPAM_WINDOW - ahora)

    historial.append(ahora)
    bot.user_scan_history[key] = historial
    bot.antispam_scan[key] = ahora
    return True, 0


async def check_vt_user_limit(bot, guild_id: Optional[int], user_id: int) -> bool:
    """Limita a VT_MAX_ANALYSES_PER_MINUTE peticiones por usuario y minuto.

    Se indexa por (guild_id, user_id) y no solo por user_id: con la clave global un
    usuario que analiza en varios servidores a la vez se bloqueaba a sí mismo.
    """
    ahora = time.time()
    key: tuple[int, int] | int = (guild_id, user_id) if guild_id else user_id
    historial = [t for t in bot.vt_user_requests.get(key, []) if ahora - t < 60]
    if len(historial) >= VT_MAX_ANALYSES_PER_MINUTE:
        bot.vt_user_requests[key] = historial
        return False
    historial.append(ahora)
    bot.vt_user_requests[key] = historial
    return True


def formatear_espera(segundos: int) -> str:
    """'4m 12s' o '12s', para los mensajes de límite de tasa."""
    minutos, segs = divmod(max(0, int(segundos)), 60)
    return f"{minutos}m {segs}s" if minutos else f"{segs}s"
