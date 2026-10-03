import time
import asyncio
import hashlib
import base64
from typing import Optional
import logging
import aiohttp
import discord
from core import state
from core.config import (
    VT_API_KEYS, SE_API_KEYS_PAIRS, MAX_FILE_SIZE,
    VT_MAX_ANALYSES_PER_MINUTE, VT_MAX_ANALYSES_PER_DAY,
    SE_MAX_REQUESTS_PER_MINUTE, SE_MAX_REQUESTS_PER_SECOND, SE_MAX_OPS_PER_DAY,
    SE_MAX_OPS_PER_MONTH, SE_OPS_PER_CALL,
)
from core.cache import set_cache_mem
from core.database import guardar_analisis_db
from core.utils import obtener_top_antivirus, es_hash_valido, clave_analisis
from ui.views import LogActionView
from ui import embed as emb
from core.guild_config import obtener_config_guild, update_stats

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


# El plan gratuito de SightEngine permite 1 petición por segundo. Sin esto, cada
# respuesta de la API la devuelve con 429 y el fallo no distingue "límite de tasa" de
# "API caída", así que una racha de 429 no se cachea y se repite.
_se_ultima_peticion: float = 0.0


async def esperar_turno_se() -> None:
    """Espaciala las peticiones a SightEngine según `SE_MAX_REQUESTS_PER_SECOND`."""
    global _se_ultima_peticion
    limite = SE_MAX_REQUESTS_PER_SECOND
    if limite <= 0:
        return
    separacion = 1.0 / limite
    async with _se_lock:
        ahora = time.time()
        espera = _se_ultima_peticion + separacion - ahora
        if espera > 0:
            await asyncio.sleep(espera)
        _se_ultima_peticion = time.time()


def _mes_utc() -> str:
    return time.strftime("%Y-%m", time.gmtime())


def _contador_mensual(api_key: str, mes: str) -> int:
    """Operaciones ya gastadas por esta clave en el mes UTC en curso."""
    registro = state.bot.se_key_monthly_usage.get(api_key)
    if not registro or registro.get("month") != mes:
        return 0
    return int(registro.get("count", 0))


async def obtener_siguiente_se_key() -> Optional[tuple[str, str]]:
    """Selecciona el siguiente par de SightEngine con cuota y RESERVA sus operaciones.

    Antes la reserva era de `SE_OPS_PER_CALL` operaciones por llamada de la API, y la
    docstring daba por hecho "una llamada = una petición". Eso era cierto hasta que se
    añadió el reintento con menos modelos: un mismo análisis puede emitir hasta
    `len(MODELOS_CON_FALLBACK)` peticiones, cada una cobrando su propio número de
    operaciones. Reservar una sola vez hacía que el contador local se quedara corto y
    `pudiéramos` pasarnos del tope diario sin enterarnos.

    Ahora hay dos funciones: `obtener_siguiente_se_key` elige par y comprueba cupos SIN
    reservar, y `reservar_se_key` consume las operaciones de la petición que va a salir.
    Así el contador cuadra con las peticiones realmente emitidas.

    Se comprueban los TRES topes del plan gratuito: por segundo (lo impone la API), por
    día y **por mes**. El mensual es el que de verdad manda, y se—was applying el
    checks —la constante `SE_MAX_OPS_PER_MONTH` estaba escrita y sin usar— así que el bot
    gastaba los 2.000 ops del mes en cuatro días (500/día) y a partir del día 5 lo
    bloqueaba SightEngine sin que el bot supiera por qué. Aplicando el mensual, ese mismo
    presupuesto se reparte en ~13 imágenes al día hasta final de mes y nadie se queda sin
    servicio a mitad.
    """
    async with _se_lock:
        if not SE_API_KEYS_PAIRS:
            return None
        ahora = time.time()
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        mes = _mes_utc()
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

            # El tope que manda. Se comprueba antes de gastar, como los otros dos.
            if _contador_mensual(api_key, mes) + SE_OPS_PER_CALL > SE_MAX_OPS_PER_MONTH:
                log.warning(
                    f"SE key monthly limit: {api_key[:8]}... "
                    f"({_contador_mensual(api_key, mes)}/{SE_MAX_OPS_PER_MONTH} ops/{mes}). "
                    "El plan está agotado hasta el mes que viene; se sigue con VirusTotal."
                )
                continue

            ventana.append(ahora)
            return pair

        log.warning("Todas las keys de SightEngine están rate-limited o sin cuota mensual")
        return None


async def reservar_se_key(pair: tuple[str, str], operaciones: Optional[int] = None) -> int:
    """Consume las operaciones de UNA petición a SightEngine.

    Se llama justo antes de cada POST, no una vez por análisis, para que el contador
    local refleje lo que la API va a cobrar de verdad. Con el reintento de modelos, un
    análisis pueden ser varias peticiones.

    Devuelve las operaciones reservadas para que `liberar_se_key` pueda devolverlas si la
    petición se rechaza. Devolverlas no esDESCUENTO de contabilidad: **un 400 de
    SightEngine no se cobra**. Antes sí se contaba, y con el reintento de modelos eso
    inflaba el contador hasta 15 operaciones por imagen (5+4+3+2+1) cuando la real_costaba
    una. Con el tope mensual aplicado, ese sobrecoste se traducía en servir 133 imágenes
    al mes en vez de 400.

    El patrón es el mismo que ya usa VirusTotal, que sí lo tenía bien: *"una petición
    rechazada no debe inflar el contador diario, o la key quedaría inutilizable de forma
    permanente"*.
    """
    ops = SE_OPS_PER_CALL if operaciones is None else operaciones
    api_key = pair[0]
    async with _se_lock:
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        mes = _mes_utc()
        diario = state.bot.se_key_daily_usage.get(api_key)
        if diario is None or diario["date"] != hoy:
            diario = {"count": 0, "date": hoy}
        diario["count"] += ops
        state.bot.se_key_daily_usage[api_key] = diario

        mensual = state.bot.se_key_monthly_usage.get(api_key)
        if mensual is None or mensual.get("month") != mes:
            mensual = {"count": 0, "month": mes}
        mensual["count"] += ops
        state.bot.se_key_monthly_usage[api_key] = mensual

        state.bot.se_key_total_requests[api_key] = state.bot.se_key_total_requests.get(api_key, 0) + ops
    return ops


async def liberar_se_key(pair: tuple[str, str], operaciones: int) -> None:
    """Devuelve operaciones reservadas de una petición que SightEngine no cobró.

    Se llama cuando la API rechaza la petición antes de hacer nada (un 400 por modelo no
    disponible, tamaño, etc.). Los contadores se guardan con `max(0, ...)` porque una
    corrección que dejara el contador en negativo dejaría la clave con capacidad de sobra
    que ya no se puede justificar.
    """
    if operaciones <= 0:
        return
    api_key = pair[0]
    async with _se_lock:
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        mes = _mes_utc()

        diario = state.bot.se_key_daily_usage.get(api_key)
        if diario is not None and diario["date"] == hoy:
            diario["count"] = max(0, diario["count"] - operaciones)
            state.bot.se_key_daily_usage[api_key] = diario

        mensual = state.bot.se_key_monthly_usage.get(api_key)
        if mensual is not None and mensual.get("month") == mes:
            mensual["count"] = max(0, mensual["count"] - operaciones)
            state.bot.se_key_monthly_usage[api_key] = mensual

        state.bot.se_key_total_requests[api_key] = max(
            0, state.bot.se_key_total_requests.get(api_key, 0) - operaciones
        )

async def enviar_log_agrupado(guild_id: int, detecciones: list[tuple[str, str, str, str]],
                              usuario: discord.User, origen: str = "") -> Optional[discord.Message]:
    """Un único log con todas las detecciones de un mismo mensaje.

    Reemplaza al envío uno por detección. Antes un mensaje con tres URLs maliciosas
    producía tres embeds en el canal de logs: se leían como tres mensajes de tres
    personas, y el enlace al mensaje original no aparecía más que en algunos según qué
    ruta de borrado hubiera ganado la carrera.
    """
    if not detecciones:
        return None
    config = await obtener_config_guild(guild_id)
    log_channel_id = config["log_channel_id"]
    if log_channel_id is None or not config.get("avisar_amenazas", True):
        return None
    channel = state.bot.get_channel(log_channel_id)
    if channel is None:
        return None

    embed = emb.amenaza_agrupada(detecciones, usuario, mensaje=origen)
    view = LogActionView(guild_id, usuario.id,
                         elementos_id=[eid for _, _, _, eid in detecciones if eid])
    try:
        msg = await channel.send(embed=embed, view=view)
        view.message = msg
        return msg
    except discord.errors.Forbidden:
        log.error(f"enviar_log_agrupado: sin permisos en #{channel} (guild {guild_id})")
        return None
    except Exception as e:
        log.error(f"enviar_log_agrupado falló: {type(e).__name__}: {e}")
        return None


async def enviar_log_guild(guild_id: int, tipo: str, valor: str, detalles: str, usuario: discord.User, url_vt: Optional[str] = None, elemento_id: Optional[str] = None, veredicto: str = "malicioso", mensaje: Optional[str] = None) -> Optional[discord.Message]:
    config = await obtener_config_guild(guild_id)
    log_channel_id = config["log_channel_id"]
    if log_channel_id is None:
        return None
    # Interruptor explícito. Antes la única forma de callar este log era dejar el canal
    # vacío, y en el panel eso se lee igual que "todavía no lo he configurado", que son
    # dos intenciones opuestas. Ahora se puede tener el canal puesto y no querer avisos, o
    # no quererlos ahora y activarlos luego sin volver a buscar el canal.
    if not config.get("avisar_amenazas", True):
        return None
    channel = state.bot.get_channel(log_channel_id)
    if channel is None:
        return None
    if veredicto == "nsfw":
        # El usuario va también aquí. Antes este embed no lo llevaba y los botones de
        # Ban/Kick sí apuntaban a él: un moderador podía banear a alguien que el log no
        # nombraba.
        embed = emb.nsfw(tipo, valor, detalles, usuario, mensaje=mensaje or "")
    else:
        # `restringido` también acaba aquí, y antes salía como "resultó malicioso" con un
        # botón de banear. El veredicto viaja explícito para que el texto lo diga, en vez
        # de suponer que todo lo que no es NSFW es malware.
        embed = emb.amenaza(tipo, valor, detalles, usuario, vt_link=url_vt,
                            veredicto=veredicto, mensaje=mensaje or "")
    view = LogActionView(guild_id, usuario.id, elemento_id=elemento_id)
    try:
        msg = await channel.send(embed=embed, view=view)
        view.message = msg
        return msg
    except discord.errors.Forbidden:
        log.error(f"enviar_log_guild: sin permisos send_messages/embed_links en #{channel} (guild {guild_id})")
    except Exception as e:
        log.error(f"enviar_log_guild: error enviando a #{log_channel_id} (guild {guild_id}): {type(e).__name__}: {e}")
    return None

async def _sin_cuota() -> tuple[str, discord.Embed, int]:
    return "error", emb.error_cuota(), 0


def _error_red() -> discord.Embed:
    """Fallo de red o respuesta ilegible. Distinto de "sin cuota" y de "demasiado grande".

    Los tres son `error` como veredicto, pero el motivo distinto es lo que permite al
    usuario entender si esperar, pagar o mandar otro archivo.
    """
    return emb.error_analisis(
        "No se pudo completar el análisis.",
        detalle="Fallo de red o respuesta ilegible de VirusTotal.",
    )


def _error_tamanio(filename: str) -> discord.Embed:
    return emb.error_analisis(
        f"`{filename}` supera el tamaño máximo que se puede analizar.",
        detalle=f"Límite de {MAX_FILE_SIZE // (1024 * 1024)} MB por archivo.",
    )


async def reputacion_hash(file_hash: str) -> tuple[str, int, Optional[str], Optional[str]]:
    """Solo consulta la reputación de un hash, sin subir nada.

    Devuelve `(veredicto, detecciones, vt_link, top_text)`. El veredicto es
    `"desconocido"` cuando VirusTotal no ha visto ese archivo: no se sube, porque subir
    gastaría una request extra del plan gratuito y porque un archivo recién subido no
    tiene análisis todavía.

    Existe para las imágenes, que hasta ahora solo pasaban por SightEngine: una imagen
    marcada como malware por el hash se reportaba como "NSFW limpio". Con el plan
    gratuito el coste es una request por imagen, y solo cuando el hash no está ya en
    caché de disco.
    """
    key = await adquirir_vt()
    if not key:
        return "sin_cuota", 0, None, None
    try:
        async with state.bot.session.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": key},
            timeout=VT_TIMEOUT,
        ) as resp:
            if resp.status == 404:
                log.debug(f"VT HASH NUEVO → {file_hash}")
                return "desconocido", 0, None, None
            if resp.status != 200:
                log.debug(f"VT HASH ERROR → {file_hash} status={resp.status}")
                return "error", 0, None, None
            data = await resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats") or {}
            results = attrs.get("last_analysis_results") or {}
            mal = int(stats.get("malicious", 0))
            veredicto = _veredicto(stats) if stats else "desconocido"
            vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"
            top = obtener_top_antivirus(results) if mal else None
            return veredicto, mal, vt_link, (", ".join(top) if top else None)
    except asyncio.TimeoutError:
        log.error(f"VT HASH TIMEOUT → {file_hash}")
        return "error", 0, None, None
    except Exception as e:
        log.error(f"VT HASH EXCEPTION → {file_hash}: {e}")
        return "error", 0, None, None


async def analizar_url(url: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True, registrar_para: Optional[discord.abc.User] = None) -> tuple[str, discord.Embed, int]:
    _t0 = time.time()
    log.debug(f"VT URL INICIO → {url}")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    key = await adquirir_vt()
    if not key:
        log.debug(f"VT URL ERROR → no hay keys disponibles t={time.time()-_t0:.1f}s")
        return await _sin_cuota()
    _t = time.time()
    # Este GET va dentro del `try` a propósito. Estaba fuera: cualquier timeout, error de
    # red o JSON malformado en la *primera* consulta escapaba de `analizar_url`, se saltaba
    # `_finalizar_error` y la excepción subía por `vuelo()` hasta el `done_callback` del
    # bot. Ese mensaje se quedaba sin embed, sin reacción, sin registro en /history y sin
    # evento, sin ninguna señal visible más que una línea de log.
    try:
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
                    return await _procesar_resultado_vt(normalized, "url", url, guild_id, mensaje_original, guardar_cache, registrar_para)
    except asyncio.TimeoutError:
        log.warning(f"VT URL TIMEOUT en el GET inicial → {url}")
        await _finalizar_error(guild_id, "url", url)
        return "error", _error_red(), 0
    except Exception as e:
        log.error(f"Excepción en el GET inicial de VT para {url}: {e}")
        await _finalizar_error(guild_id, "url", url)
        return "error", _error_red(), 0

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
                                return await _procesar_resultado_vt(analysis, "url", url, guild_id, mensaje_original, guardar_cache, registrar_para)
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
                                return await _procesar_resultado_vt(normalized, "url", url, guild_id, mensaje_original, guardar_cache, registrar_para)
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


async def analizar_hash(hash_valor: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True, registrar_para: Optional[discord.abc.User] = None) -> tuple[str, discord.Embed, int]:
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
                veredicto = _veredicto(stats)
                if mal > 0:
                    await _on_threat_found("hash", hash_valor, mal, guild_id, mensaje_original, vt_link, results, guardar_cache, registrar_para=registrar_para)
                    top = obtener_top_antivirus(results)
                    top_text = ", ".join(top) if top else "Varios antivirus"
                else:
                    top_text = None
                datos = {"valor": hash_valor, "vt_link": vt_link, "top_text": top_text, "veredicto": veredicto, "susp": stats.get("suspicious", 0)}
                embed = emb.resultado("hash", datos, mal)
                if guardar_cache:
                    clave = clave_analisis("hash", hash_valor)
                    await guardar_analisis_db(clave, "hash", veredicto, mal=mal, datos=datos)
                    await set_cache_mem(clave, veredicto, mal=mal, datos=datos)
                if mal > 0:
                    log.debug(f"VT HASH MALICIOSO → {hash_valor} mal={mal} t={time.time()-_t0:.1f}s")
                    return "malicioso", embed, mal
                await update_stats(guild_id, veredicto)
                log.debug(f"VT HASH {veredicto.upper()} → {hash_valor} t={time.time()-_t0:.1f}s")
                return veredicto, embed, 0
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

async def analizar_ip(ip: str, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True, registrar_para: Optional[discord.abc.User] = None) -> tuple[str, discord.Embed, int]:
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
                veredicto = _veredicto(stats)
                vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
                if mal > 0:
                    await _on_threat_found("ip", ip, mal, guild_id, mensaje_original, vt_link, registrar_para=registrar_para)
                datos = {"valor": ip, "vt_link": vt_link, "top_text": None, "veredicto": veredicto, "susp": stats.get("suspicious", 0)}
                embed = emb.resultado("ip", datos, mal)
                if guardar_cache:
                    clave = clave_analisis("ip", ip)
                    await guardar_analisis_db(clave, "ip", veredicto, mal=mal, datos=datos)
                    await set_cache_mem(clave, veredicto, mal=mal, datos=datos)
                if mal > 0:
                    log.debug(f"VT IP MALICIOSA → {ip} mal={mal} t={time.time()-_t0:.1f}s")
                    return "malicioso", embed, mal
                await update_stats(guild_id, veredicto)
                log.debug(f"VT IP {veredicto.upper()} → {ip} t={time.time()-_t0:.1f}s")
                return veredicto, embed, 0
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

async def analizar_archivo(archivo: discord.Attachment, file_bytes: Optional[bytes] = None, file_hash: Optional[str] = None, guild_id: Optional[int] = None, mensaje_original: Optional[discord.Message] = None, guardar_cache: bool = True, registrar_para: Optional[discord.abc.User] = None) -> tuple[str, discord.Embed, int]:
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
                    return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache, registrar_para)

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
                                return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache, registrar_para)
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
                                return await _procesar_analisis_archivo(analysis, archivo, file_hash, guild_id, mensaje_original, guardar_cache, registrar_para)
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

def _veredicto(stats: dict) -> str:
    """Traduce `last_analysis_stats` de VT a uno de nuestros tres veredictos.

    VT separa `suspicious` de `malicious` en su esquema, y leer solo `malicious` —como
    se hacía hasta ahora— hacía que un enlace con tres engines que lo marcan como
    sospechoso y ninguno que lo confirme saliera con el veredicto "seguro".

    No se suman: `suspicious` no es "malicioso pero menos", es una categoría propia. Por
    eso un sospechoso se informa pero no genera infracción ni borra el mensaje, que es
    justo lo que distingue este veredicto de los otros dos.
    """
    if stats.get("malicious", 0) > 0:
        return "malicioso"
    if stats.get("suspicious", 0) > 0:
        return "sospechoso"
    return "seguro"


async def _procesar_resultado_vt(analysis: dict, tipo: str, valor: str, guild_id: Optional[int], mensaje_original: Optional[discord.Message], guardar_cache: bool, registrar_para: Optional[discord.abc.User] = None) -> tuple[str, discord.Embed, int]:
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    susp = stats.get("suspicious", 0)
    veredicto = _veredicto(stats)
    clave = clave_analisis(tipo, valor)
    log.debug(f"VT RESULT → {tipo}={valor} {veredicto} mal={mal} susp={susp} harmless={stats.get('harmless',0)} undetected={stats.get('undetected',0)}")
    url_id = base64.urlsafe_b64encode(valor.encode()).decode().rstrip("=")
    vt_link = f"https://www.virustotal.com/gui/url/{url_id}"

    if mal > 0:
        await _on_threat_found(tipo, valor, mal, guild_id, mensaje_original, vt_link, registrar_para=registrar_para)
    top_text = None
    results = analysis["data"]["attributes"].get("results") or {}
    if mal > 0 and results:
        top = obtener_top_antivirus(results)
        top_text = ", ".join(top) if top else "Varios antivirus"

    datos = {"valor": valor, "vt_link": vt_link, "top_text": top_text, "veredicto": veredicto, "susp": susp}
    embed = emb.resultado(tipo, datos, mal)
    tipo_str = veredicto

    if guardar_cache:
        await guardar_analisis_db(clave, tipo, tipo_str, mal=mal, datos=datos)
        await set_cache_mem(clave, tipo_str, mal=mal, datos=datos)
    if veredicto == "seguro" and guild_id:
        await update_stats(guild_id, "seguro")
    elif veredicto == "sospechoso" and guild_id:
        await update_stats(guild_id, "sospechoso")
    return tipo_str, embed, mal

async def _procesar_analisis_archivo(analysis: dict, archivo: discord.Attachment, file_hash: str, guild_id: Optional[int], mensaje_original: Optional[discord.Message], guardar_cache: bool, registrar_para: Optional[discord.abc.User] = None) -> tuple[str, discord.Embed, int]:
    stats = analysis["data"]["attributes"]["stats"]
    mal = stats["malicious"]
    susp = stats.get("suspicious", 0)
    veredicto = _veredicto(stats)
    clave = clave_analisis("file", file_hash)
    log.debug(f"VT FILE RESULT → {archivo.filename} hash={file_hash} {veredicto} mal={mal} susp={susp}")

    if mal > 0:
        await _on_threat_found("Archivo", archivo.filename, mal, guild_id, mensaje_original, None, elemento_id=f"filehash:{file_hash}", registrar_para=registrar_para)

    datos = {"valor": archivo.filename, "vt_link": None, "top_text": None, "veredicto": veredicto, "susp": susp}
    embed = emb.resultado("file", datos, mal)
    tipo_str = veredicto
    if guardar_cache:
        await guardar_analisis_db(clave, "file", tipo_str, mal=mal, datos=datos)
        await set_cache_mem(clave, tipo_str, mal=mal, datos=datos)
    if veredicto == "seguro":
        await update_stats(guild_id, "seguro")
    elif veredicto == "sospechoso":
        await update_stats(guild_id, "sospechoso")
    return tipo_str, embed, mal

async def _post_threat_side_effects(guild_id: int, tipo_str: str, valor: str, mal: int, autor: discord.abc.User, vt_link: Optional[str], eid: str, mensaje_original: Optional[discord.Message] = None) -> None:
    """Estadística, log de amenaza, y —solo si hubo mensaje— infracción y borrado.

    La infracción va contra quien **publicó** la amenaza, que solo existe en el
    autoescaneo. Con `/scan` no hay tal persona: quien invoca el comando está
    consultando, no distribuyendo, así que recibe el log pero no se le cuenta nada.
    """
    try:
        await update_stats(guild_id, "malicioso")
        if mensaje_original is None:
            # Escaneo manual (`/scan` o menú contextual): no hay un análisis de mensaje
            # al que groupingselo, así que este sitio manda su propio log.
            #
            # Y NO borra: el modo estricto solo borra desde el handler, una vez por
            # mensaje. Antes se borraba aquí también, una vez por cada URL, y las dos
            # rutas compiten: la primera en borrar y la segunda recibe `NotFound`. De ahí
            # salía el síntoma de que un log llevaba el enlace al mensaje y el otro no,
            # y de que el mensaje desapareciera mientras el análisis seguía corriendo.
            if vt_link:
                await enviar_log_guild(guild_id, tipo_str, valor, f"{mal} detecciones",
                                       autor, vt_link, elemento_id=eid)
            else:
                await enviar_log_guild(guild_id, tipo_str, valor, f"{mal} detecciones",
                                       autor, elemento_id=eid)
            return

        # Autoescaneo: aquí no se manda log ni se borra. De las dos cosas se encarga el
        # handler, una sola vez y con todas las detecciones del mensaje juntas.
        #
        # La infracción tampoco se registra aquí. Registrarla en los dos sitios la
        # contaba dos veces, porque el handler la registra para todas las URLs
        # maliciosas del mensaje y esta función también.
    except Exception as e:
        log.error(f"Error en post-threat side effects: {e}")


async def _on_threat_found(tipo_str: str, valor: str, mal: int, guild_id: Optional[int], mensaje_original: Optional[discord.Message], vt_link: Optional[str] = None, results: Optional[dict] = None, guardar_cache: bool = True, elemento_id: Optional[str] = None, registrar_para: Optional[discord.abc.User] = None) -> None:
    """Lanza los efectos de una amenaza: estadística, log, y con mensaje también
    infracción y borrado.

    Actúa si hay `mensaje_original` (autoescaneo) o si `registrar_para` trae a alguien
    a quien atribuir el escaneo (el caso de `/scan`). Antes solo miraba el mensaje, así
    que escanear a mano una URL maliciosa no dejaba ni log ni cambiaba `/stats`: el
    comando y el autoescaneo discrepaban del mismo veredicto.

    `registrar_para` es a quién se nombra en el log, no a quién se le cuenta la
    infracción: esa siempre va contra el autor del mensaje, si lo hay.
    """
    if not guild_id:
        return
    if mensaje_original is None and registrar_para is None:
        return
    eid = elemento_id or (f"url:{valor}" if tipo_str in ("URL", "url") else f"hash:{valor}" if tipo_str == "hash" else f"ip:{valor}")
    autor = mensaje_original.author if mensaje_original is not None else registrar_para
    task = asyncio.create_task(_post_threat_side_effects(guild_id, tipo_str, valor, mal, autor, vt_link, eid, mensaje_original))
    task.add_done_callback(lambda t: log.error(f"Post-threat error: {t.exception()}", exc_info=t.exception()) if t.exception() else None)

async def _finalizar_error(guild_id: Optional[int], tipo: str, valor: str) -> None:
    await update_stats(guild_id, "error")
