"""SightEngine: análisis de contenido de imágenes.

Tres correcciones respecto a como estaba, todas por el mismo motivo: **el bot informaba
como "seguro" cosas que no había comprobado**.

1. `nudity` v1.0 se leía solo por su campo `raw`, que es material explícito tipo X, y se
   descartaba `partial`. `partial` es bikini, lencería, escote: exactamente lo que llega a
   un servidor de Discord. El detector marcaba casi nada. Ahora se usa `nudity-2.1` y se
   leen los dos campos por separado, con umbrales independientes.

2. `weapon` tomaba el máximo de todas sus clases, incluidas `firearm_toy` y
   `firearm_gesture`. Un juguete o una foto con alguien levantando las manos marcaban
   contenido restringido. Esas dos se descartan.

3. Cualquier fallo devolvía `(False, 0.0, {}, False)`, y `models.get("error")` sobre un
   dict vacío es `None`: es decir, "falsy". El llamante lo traducía a "seguro" y lo
   contaba en las estadísticas. Sin claves, sin cuota, HTTP 500 o excepción, ahora la
   misma ruta devuelve ERROR.

Invariante del módulo: **toda salida lleva `{"error": ...}` si no se pudo comprobar**.
Nunca un dict vacío, porque un dict vacío se lee como "no hay nada".
"""

import json
import logging
from typing import Any, Dict, Optional, Tuple

import aiohttp

from core import state
from core.cache import get_from_cache_mem, set_cache_mem
from core.config import (
    SE_API_KEYS_PAIRS,
    SIGHTENGINE_API_URL,
    SIGHTENGINE_MODELS,
    UMBRALES_CONTENIDO,
)
from core.database import guardar_analisis_db, obtener_analisis_db, guardar_datos
from core.veredictos import Veredicto
from api.virustotal import esperar_turno_se, obtener_siguiente_se_key, reservar_se_key, liberar_se_key

SE_TIMEOUT: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=30)

log = logging.getLogger("sightengine")

# Claves de `models`, todas planas y float. Se mantienen planas para que
# `max_confidence` y el embed sigan funcionando sin cambios.
CLAVE_NUDITY_RAW = "nudity_raw"
CLAVE_NUDITY_PARTIAL = "nudity_partial"
CLAVE_GORE = "gore"
CLAVE_WEAPON = "weapon"
CLAVE_ALCOHOL = "alcohol"
CLAVE_OFFENSIVE = "offensive"

CLAVES_CONTENIDO = (
    CLAVE_NUDITY_RAW,
    CLAVE_NUDITY_PARTIAL,
    CLAVE_GORE,
    CLAVE_WEAPON,
    CLAVE_ALCOHOL,
    CLAVE_OFFENSIVE,
)

# Clases de `weapon` que NO son un arma. `firearm_toy` es un juguete o una réplica y
# `firearm_gesture` es alguien levantando las manos: con ellas dentro del máximo, una
# foto de un peluche marcaba contenido restringido.
CLASES_WEAPON_IGNORADAS = frozenset({"firearm_toy", "firearm_gesture"})

# Motivos de fallo. Se comparan por texto en `es_error` y en los tests.
ERROR_SIN_CLAVES = "sin_claves"
ERROR_SIN_CUOTA = "sin_cuota"
ERROR_SIN_BYTES = "sin_bytes"
ERROR_DEMASIADO_GRANDE = "too_large"
ERROR_HTTP = "error_http"
ERROR_EXCEPCION = "error_excepcion"
ERROR_SIN_MODELOS = "sin_modelos"
ERROR_MODELO_NO_DISPONIBLE = "modelo_no_disponible"

# Se prueban en este orden y se va bajando hasta que la API acepte la lista. El primero
# es el de `SIGHTENGINE_MODELS`, que es el que consume el cálculo de cuota
# (`SE_OPS_PER_CALL`), así que ambos no pueden divergir.
#
# El reintento existe porque `nudity-2.1` y `gore-2.0` no están en todos los planes de
# SightEngine: si la cuenta no los tiene, la API responde 400 y sin esto TODAS las
# imágenes quedarían como error. Es lo que hace seguro desplegar el cambio sin saber de
# antemano qué modelos incluye la cuenta.
MODELOS_CON_FALLBACK = (
    SIGHTENGINE_MODELS,
    "nudity-2.1,weapon,alcohol,offensive",
    "nudity-2.1,weapon,offensive",
    "nudity-2.1,offensive",
    "offensive",
)


def _texto_de_error(cuerpo) -> str:
    """Aplana el objeto `error` de SightEngine a texto buscable.

    El error viene como dict con `type` y `message`, o como string plano, según el
    endpoint. Normalizarlo aquí evita repetir el mismo `if isinstance` en cada sitio que
    tiene que mirar dentro del error.
    """
    if not isinstance(cuerpo, dict):
        return str(cuerpo or "").lower()
    err = cuerpo.get("error")
    if isinstance(err, dict):
        return f"{err.get('type', '')} {err.get('message', '')}".lower()
    if isinstance(err, str):
        return err.lower()
    return ""


def _es_cuota_agotada(cuerpo, status: int) -> bool:
    """¿La API está diciendo que se acabó el plan, y no que falló la red?

    Antes cualquier respuesta que no fuera 400 se traducía a `ERROR_HTTP`, y el embed de
    ese error dice *"Fallo de red o respuesta ilegible de SightEngine"*. Cuando se agota
    el plan gratuito el bot loeleya como un fallo de red, durante 26 días al mes, y
    además se cacheaba como transitorio: cada imagen volvía a llamar a la API, volvía a
    fallar, y volvía a intentarlo. Un diagnóstico falso que además Picasso bombardea la
    API.

    Se decide por lo que **dice** la respuesta y no por el status, porque el status con
    el que SightEngine rechaza un plan agotado no está documentado y adivinarlo sería
    peor que no comprobarlo: se lista lo que el plan suele decir y, si además llega un
    402/403, se acepta sin mirar el texto.
    """
    if status in (402, 403):
        return True
    texto = _texto_de_error(cuerpo)
    return any(
        palabra in texto
        for palabra in ("quota", "credit", "plan", "billing", "payment required",
                        "exceeded", "upgrade", "insufficient")
    )


def _clasificar_400(cuerpo: Optional[dict]) -> tuple[str, str]:
    """Un 400 de SightEngine puede ser tamaño, modelo no disponible o parámetro inválido.

    Antes todo 400 se traducía a `too_large`, así que un modelo no soportado se
    reportaba como "la imagen es demasiado grande": un diagnóstico falso que además
    ocultaba la causa real y hacía imposible arreglarlo.
    """
    texto = _texto_de_error(cuerpo)
    if not texto:
        return ERROR_DEMASIADO_GRANDE, "SightEngine rechazó la imagen (HTTP 400)"

    if "model" in texto or "unsupported" in texto or "not available" in texto:
        return ERROR_MODELO_NO_DISPONIBLE, f"SightEngine no admite algún modelo: {texto.strip()}"
    if "large" in texto or "size" in texto or "dimension" in texto:
        return ERROR_DEMASIADO_GRANDE, f"La imagen supera lo admitido por SightEngine: {texto.strip()}"
    return ERROR_HTTP, f"SightEngine rechazó el análisis: {texto.strip()}"


# Motivos de fallo que se cachean, y con qué caducidad. El resto se devuelven sin
# cachear a propósito: son gratis (no llegaron a la API) o duran segundos.
_TIPO_CACHEADO = {
    ERROR_SIN_MODELOS: "se_sin_modelos",
    # La cuota agotada SÍ se cachea, y como cuota. Antes caía en `ERROR_HTTP` y se
    # cacheaba como transitorio: un plan agotado no se arregla esperando segundos, así que
    # cada imagen volvía a llamar a la API y a chocar contra el mismo muro, todo el día.
    ERROR_SIN_CUOTA: "se_sin_cuota",
    ERROR_HTTP: "se_transitorio",
    ERROR_EXCEPCION: "se_transitorio",
}

# Tipos de los fallos transitorios, para el log y los tests.
# `ERROR_SIN_CUOTA` sigue aquí por compatibilidad con lo que ya inspecta `cogs/stats.py`,
# aunque ya no se trata como transitorio: se cachea aparte, con caducidad larga.
TRANSITORIOS = (ERROR_HTTP, ERROR_EXCEPCION, ERROR_SIN_CUOTA)
# Fallos que ya costaron operaciones y por eso hay que recordar.
COSTOSOS = (ERROR_SIN_MODELOS,)


async def _cachear_fallo(cache_key: str, motivo: str, detalle: str) -> None:
    """Guarda un fallo para no repetir la llamada.

    Existe por dos motivos distintos que se confundían:

    - `sin_modelos` es un **200**: la API respondió y cobró sus operaciones. Volver a
      preguntarlo al siguiente repost es gastar 5 operaciones por la misma respuesta
      inválida, y con 2.000 al mes eso son 400 imágenes.
    - Los fallos de red no cuestan operaciones, pero durante una caída cada reaparición
      añadiría otra petición a una API que ya está cayendo, y la-avalancha empeora la
      caída.
    """
    tipo = _TIPO_CACHEADO.get(motivo)
    if not tipo:
        return
    try:
        await guardar_analisis_db(
            cache_key, tipo, motivo, datos={"tipo": motivo, "error": motivo, "detalle": detalle},
        )
    except Exception as e:
        # Cachear un fallo es una optimización: si no se puede, el análisis sigue siendo
        # correcto, solo que se repetirá.
        log.debug(f"No se pudo cachear el fallo de SightEngine: {type(e).__name__}")


def _fallo(motivo: str, detalle: str = "") -> Tuple[bool, float, Dict[str, Any], bool]:
    """Construye una salida de fallo.

    Devuelve la tupla de 4 por compatibilidad con los llamantes, pero `models` SIEMPRE
    lleva `error`. Un `{}` vacío era indistinguible de "todo limpio" aguas arriba.
    """
    models: Dict[str, Any] = {"error": motivo}
    if detalle:
        models["detalle"] = detalle
    return False, 0.0, models, False


def es_error(models: Optional[Dict[str, Any]]) -> bool:
    """¿Este resultado es un fallo y no un análisis? Única fuente de verdad."""
    return bool(models) and "error" in models


def _bloque_crudo(result: dict, nombre: str):
    """El bloque del modelo tal cual vino, sin exigir que sea un dict.

    `_dato_modelo` descarta todo lo que no sea un dict y devuelve `{}`, lo que está bien
    para leer campos con nombre pero mal para los modelos que la documentación también
    devuelve como número suelto (`alcohol`): un `0.8` se perdía antes de que nadie lo
    mirara y el modelo salía con `0.0`, o sea "no hay alcohol".
    """
    bloque = result.get(nombre)
    if bloque is not None:
        return bloque
    return result.get(nombre.split("-")[0])


def _dato_modelo(result: dict, nombre: str) -> dict:
    """Busca el bloque del modelo tolerando el cambio de nombre.

    Se pide `nudity-2.1` pero la respuesta llega bajo `nudity`; se mira el nombre pedido
    y, si no está, el nombre base.
    """
    bloque = _bloque_crudo(result, nombre)
    return bloque if isinstance(bloque, dict) else {}

# --- nudity: conviven dos esquemas de respuesta ------------------------------------
#
# `nudity-1.x` devolvía tres números planos: `raw`, `partial` y `safe`.
#
# `nudity-2.1` **no tiene esos campos**. Devuelve clases: `sexual_activity`,
# `sexual_display`, `erotica`, `sextoy`, `suggestive`, `very_suggestive`,
# `mildly_suggestive`, un `suggestive_classes` con la ropa y la postura, más `none` y
# `context`. Es el mismo modelo con otro nombre de campo.
#
# Leer el 2.1 con las claves del 1.x es lo que dejó la detección de desnudez **muerta**:
# `nudity.get("raw")` daba `None`, `_a_float(None)` daba `0.0`, y la imagen salía con el
# mismo veredicto que una foto de playa. No era un falso negativo puntual: `nudity_raw` y
# `nudity_partial` salían 0.0 en todas las imágenes del mundo desde que se migró al
# 2.1, porque el campo no existía. Los otros cuatro modelos (gore, alcohol, weapon,
# offensive) sí devolvían sus números, y por eso el fallo se veía como "esta imagen
# concreta se coló" en vez de como "la desnudez no funciona".
#
# Los nombres de abajo son los de la respuesta documentada de `nudity-2.1`.
CLASES_NUDITY_EXPLICITAS: Tuple[str, ...] = ("sexual_activity", "sexual_display")
CLASES_NUDITY_SUGERIDAS: Tuple[str, ...] = (
    "erotica", "sextoy", "suggestive", "very_suggestive", "mildly_suggestive",
)


def _escalares(bloque) -> list:
    """Los valores escalares de un dict, **sin entrar** en los sub-dicts.

    Es justo lo que hace falta para `suggestive_classes`: sus claves directas son todas
    ropa y postura, pero hay sub-dicts como `cleavage_categories` que llevan dentro un
    `none` con 0.99. Ese 0.99 quiere decir "no hay escote", no "escote muy marcado": si
    se leyera, TODA imagen saldría con desnudez parcial al 99% y el bot borraría fotos
    normales en modo estricto. Por eso se queda en un solo nivel.
    """
    if not isinstance(bloque, dict):
        return []
    return [_a_float(v) for v in bloque.values() if not isinstance(v, (dict, list))]


def _nudity(nudity) -> Optional[tuple]:
    """(explícito, sugerido) del bloque `nudity`, o `None` si el esquema no se reconoce.

    `None` es "esto no lo sé leer", que es una cosa distinta de "cero": esa diferencia es
    exactamente la que evita que una imagen que nadie ha comprobado se reporte como limpia.
    """
    if not isinstance(nudity, dict) or not nudity:
        return None
    # nudity-1.x
    if "raw" in nudity or "partial" in nudity:
        return _a_float(nudity.get("raw")), _a_float(nudity.get("partial"))
    # nudity-2.1
    if any(c in nudity for c in CLASES_NUDITY_EXPLICITAS) or "suggestive_classes" in nudity:
        explicito = max(
            (_a_float(nudity.get(c)) for c in CLASES_NUDITY_EXPLICITAS), default=0.0
        )
        sugerido = max(
            [_a_float(nudity.get(c)) for c in CLASES_NUDITY_SUGERIDAS]
            + _escalares(nudity.get("suggestive_classes")),
            default=0.0,
        )
        return explicito, sugerido
    return None


def parsear_modelos(result: dict) -> Dict[str, float]:
    """Convierte la respuesta de SightEngine en un dict plano de probabilidades.

    Puras y sin estado: es la parte que más fácil de testear y la que estaba mal.
    """
    modelos: Dict[str, float] = {}

    nudity = _nudity(_dato_modelo(result, "nudity-2.1")) or (0.0, 0.0)
    modelos[CLAVE_NUDITY_RAW] = nudity[0]
    modelos[CLAVE_NUDITY_PARTIAL] = nudity[1]

    gore = _dato_modelo(result, "gore-2.0")
    modelos[CLAVE_GORE] = _a_float(gore.get("prob"))

    weapon = _dato_modelo(result, "weapon")
    clases = {
        nombre: valor
        for nombre, valor in (weapon.get("classes") or {}).items()
        if nombre not in CLASES_WEAPON_IGNORADAS
    }
    modelos[CLAVE_WEAPON] = max((_a_float(v) for v in clases.values()), default=0.0)

    modelos[CLAVE_ALCOHOL] = _prob_de(_bloque_crudo(result, "alcohol"))

    # `offensive` trae `prob` más el detalle por categoría. Se usa `prob`, no el máximo
    # de todos los valores: `max()` mezclaba el resumen con las partes.
    offensive = _dato_modelo(result, "offensive")
    modelos[CLAVE_OFFENSIVE] = _a_float(offensive.get("prob"))

    return modelos


def _a_float(valor) -> float:
    try:
        return float(valor)
    except (TypeError, ValueError):
        return 0.0


def _prob_de(bloque) -> float:
    """La probabilidad de un bloque que puede venir como objeto o como número.

    `alcohol` aparece en la documentación de SightEngine en las dos formas: como objeto
    con `prob` junto a `weapon` y `drugs`, y como un número plano. Se aceptan las dos en
    vez de asumir una: leer `.get("prob")` a ciegas sobre un número da `AttributeError`,
    y con el `.get()` tolerante daba `0.0`, que es "no hay alcohol" dicho sin mirar.
    """
    if isinstance(bloque, (int, float)) and not isinstance(bloque, bool):
        return _a_float(bloque)
    if isinstance(bloque, dict):
        return _a_float(bloque.get("prob"))
    return 0.0


def _modelos_ilegibles(result: dict, pedidos) -> list:
    """De los modelos pedidos, los que la respuesta no trajo en forma utilizable.

    Antes solo se comprobaba que volviera **alguno** (`_llego_alguna_clave`), así que una
    respuesta a la que le faltaba el modelo de desnudez se aceptaba como análisis
    completo: los modelos presentes se leían bien y el ausente se rellenaba con `0.0`,
    que es indistinguible de "no hay nada". Una imagen que nadie miró salía limpia.

    Ahora se pregunta modelo por modelo, contra lo que se pidió de verdad — que tras el
    reintento con menos modelos puede no ser la lista original. Lo que no se pudo leer se
    devuelve, y quien llama lo convierte en `error`, nunca en `seguro`.
    """
    ilegibles = []
    for nombre in pedidos:
        bloque = _bloque_crudo(result, nombre)
        if bloque is None:
            ilegibles.append(nombre)
        elif nombre.startswith("nudity") and _nudity(bloque) is None:
            # Venía el bloque pero con un esquema que no reconocemos: tanto o peor que si
            # no hubiera venido, porque aparenta estar mirado.
            ilegibles.append(nombre)
    return ilegibles


def evaluar_contenido(
    models: Dict[str, Any],
    umbrales: Optional[Dict[str, float]] = None,
) -> Tuple[Veredicto, float, str]:
    """Traduce probabilidades a veredicto.

    Separación clave: **pornografía y gore son `nsfw`; alcohol y armas son
    `restringido`**. Compartían veredicto y borrado, y una foto de una cerveza con
    `prob` 0.75 acababa borrada en modo estricto.

    Devuelve `(veredicto, confianza, detalle)`. Si `models` lleva `error`, el veredicto
    es `ERROR` y no hay confianza: no se puede afirmar nada sobre algo no medido.
    """
    if models is None:
        # `es_error(None)` es False a propósito (None no es un error, es ausencia), pero
        # tres líneas más abajo `models.get` reventaba. La firma acepta Dict y este
        # guardián sugería que aceptaba None.
        return Veredicto.ERROR, 0.0, "sin datos de análisis"
    if es_error(models):
        return Veredicto.ERROR, 0.0, str(models.get("detalle") or models.get("error"))

    lim = dict(UMBRALES_CONTENIDO)
    if umbrales:
        lim.update({k: v for k, v in umbrales.items() if v is not None})

    detectados: list[Tuple[str, float]] = []

    for clave, etiqueta in (
        (CLAVE_NUDITY_RAW, "Desnudez explícita"),
        (CLAVE_NUDITY_PARTIAL, "Desnudez parcial"),
        (CLAVE_GORE, "Gore"),
        (CLAVE_OFFENSIVE, "Ofensivo"),
    ):
        valor = _a_float(models.get(clave))
        if valor >= lim.get(clave, 1.0):
            detectados.append((etiqueta, valor))

    for clave, etiqueta in (
        (CLAVE_ALCOHOL, "Alcohol"),
        (CLAVE_WEAPON, "Armas"),
    ):
        valor = _a_float(models.get(clave))
        if valor >= lim.get(clave, 1.0):
            detectados.append((etiqueta, valor))

    if not detectados:
        return Veredicto.SEGURO, 0.0, ""

    confianza = max(valor for _, valor in detectados)
    detalle = ", ".join(f"{etiqueta} {valor * 100:.0f}%" for etiqueta, valor in detectados)

    # El veredicto depende de QUÉ se detectó, no de si se detectó algo: pornografía y
    # gore son `nsfw`; alcohol y armas son `restringido`.
    ns_fw = any(
        etiqueta in ("Desnudez explícita", "Desnudez parcial", "Gore", "Ofensivo")
        for etiqueta, _ in detectados
    )
    return (Veredicto.NSFW if ns_fw else Veredicto.RESTRINGIDO), confianza, detalle


async def analizar_imagen_multimodelo(
    image_content_hash: str,
    image_bytes: bytes,
    umbrales: Optional[Dict[str, float]] = None,
) -> Tuple[bool, float, Dict[str, Any], bool]:
    """Analiza una imagen. Ver el contrato en el docstring del módulo."""
    # La clave cambia de versión porque el contenido guardado tiene otra forma: las
    # entradas viejas no se pueden reparsear. Se dejan caducar solas.
    #
    # De `nsfw2` a `nsfw3` porque los valores guardados están **envenenados**: con
    # `nudity-2.1` leído como `nudity-1.x`, toda imagen se guardó con `nudity_raw` y
    # `nudity_partial` a 0.0 y `veredicto` "seguro", y eso caduca a 30 días. Sin subir la
    # versión, el arreglo parecería que no hace nada justo en las imágenes que ya se
    # vieron: la caché seguiría devolviendo el "seguro" viejo y nadie lo vería funcionar.
    clave = f"nsfw3:{image_content_hash}"
    log.debug(f"SE check → hash={image_content_hash[:16]}... clave={clave}")

    tipo, _embed_cache, mal = await get_from_cache_mem(clave)
    if tipo is not None:
        try:
            details = json.loads(tipo) if isinstance(tipo, str) else tipo
            log.debug(f"SE HIT (RAM) → {clave} is_nsfw={details['is_nsfw']}")
            return details["is_nsfw"], details["max_confidence"], details["models"], True
        except Exception:
            pass

    tipo_db, _embed_db, mal_db = await obtener_analisis_db(clave)
    if tipo_db is not None:
        try:
            details = json.loads(tipo_db)
            log.debug(f"SE HIT (SQLite) → {clave} is_nsfw={details['is_nsfw']}")
            await set_cache_mem(clave, tipo_db, mal=mal_db, datos=details)
            return details["is_nsfw"], details["max_confidence"], details["models"], True
        except Exception:
            pass

    log.debug(f"SE MISS → llamando API Sightengine para {clave}")

    # Cada motivo de fallo se dice explícitamente. Nada de esto puede acabar como
    # "seguro": quien llama tiene que poder distinguir "no vi nada" de "no vi nada malo".
    if not image_bytes:
        log.debug("SE SKIP → image_bytes vacío, no se puede llamar a la API")
        return _fallo(ERROR_SIN_BYTES, "no hay bytes de la imagen")
    if not SE_API_KEYS_PAIRS:
        log.error("Sightengine no configurado: faltan las claves.")
        return _fallo(ERROR_SIN_CLAVES, "SightEngine no está configurado")

    pair = await obtener_siguiente_se_key()
    if not pair:
        log.warning("Sin cuota de Sightengine disponible.")
        return _fallo(ERROR_SIN_CUOTA, "cuota de SightEngine agotada")

    api_user, api_key = pair

    cuerpo: Optional[dict] = None
    for intento, modelos in enumerate(MODELOS_CON_FALLBACK):
        try:
            # Cada iteración es una petición real, así que cada una reserva sus
            # operaciones y respeta el límite por segundo. Antes se reservaba una vez
            # para todo el análisis y el espaciado no se aplicaba: con hasta cinco
            # peticiones de reintento, el contador local se quedaba corto y no se
            # respetaba el 1 req/s del plan gratuito.
            await esperar_turno_se()
            reservadas = await reservar_se_key(pair, len(modelos.split(",")))

            data = aiohttp.FormData()
            data.add_field("media", image_bytes, filename="image.jpg")
            data.add_field("models", modelos)
            data.add_field("api_user", api_user)
            data.add_field("api_secret", api_key)
            async with state.bot.session.post(SIGHTENGINE_API_URL, data=data, timeout=SE_TIMEOUT) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    break

                cuerpo = None
                try:
                    cuerpo = await resp.json(content_type=None)
                except Exception:
                    pass

                # La API ha rechazado la petición: no ha hecho nada y no la ha cobrado.
                # Se devuelve lo reservado ANTES de clasificar, para que el motivo sea
                # cual sea el contador no mienta. Antes solo se devolvía en el camino de
                # reintento, y hacía que una imagen costara hasta 15 operaciones en el
                # contador local cuando la real costaba una.
                await liberar_se_key(pair, reservadas)

                if _es_cuota_agotada(cuerpo, resp.status):
                    # Plan agotado. Se dice lo que es, porque el embed de ERROR_HTTP dice
                    # "fallo de red" y eso hace que un agotamiento de cuota se diagnostique
                    # como problema de internet durante el resto del mes. Y se cachea como
                    # cuota, no como transitorio: si no, cada imagen vuelve a llamar a la
                    # API y vuelve a chocar contra el mismo muro.
                    detalle = (
                        "Se agotó la cuota del plan de SightEngine ("
                        f"{_texto_de_error(cuerpo).strip() or f'HTTP {resp.status}'})"
                    )
                    log.warning(f"SE CUOTA AGOTADA → {detalle}")
                    await _cachear_fallo(clave, ERROR_SIN_CUOTA, detalle)
                    return _fallo(ERROR_SIN_CUOTA, detalle)

                if resp.status != 400:
                    detalle = f"HTTP {resp.status}"
                    log.warning(f"SE API ERROR → {detalle} models={modelos}")
                    await _cachear_fallo(clave, ERROR_HTTP, detalle)
                    return _fallo(ERROR_HTTP, detalle)

                motivo, detalle = _clasificar_400(cuerpo)
                if motivo != ERROR_MODELO_NO_DISPONIBLE:
                    await _cachear_fallo(clave, motivo, detalle)
                    return _fallo(motivo, detalle)

                # El 400 es por un modelo. Se avisa claro y se prueba con menos.
                log.warning(
                    f"SE: modelos no disponibles en esta cuenta ({modelos}) → "
                    f"reintentando con {MODELOS_CON_FALLBACK[intento + 1] if intento + 1 < len(MODELOS_CON_FALLBACK) else 'ninguno'}"
                )
        except Exception as e:
            log.error(f"Excepción en análisis multimodelo: {e}")
            await _cachear_fallo(clave, ERROR_EXCEPCION, str(e))
            return _fallo(ERROR_EXCEPCION, str(e))
    else:
        detalle = "ninguna combinación de modelos fue aceptada"
        await _cachear_fallo(clave, ERROR_MODELO_NO_DISPONIBLE, detalle)
        return _fallo(ERROR_MODELO_NO_DISPONIBLE, detalle)

    # Se comprueba contra lo que se pidió DE VERDAD en la petición que salió. Con el
    # reintento a menos modelos, la lista original no es la que vale: si el 2.1 no está
    # en la cuenta y la petición buena fue `weapon,alcohol,offensive`, exigir `nudity`
    # daría un error siempre.
    pedidos = [m.strip() for m in str(modelos).split(",") if m.strip()]
    ilegibles = _modelos_ilegibles(result, pedidos)
    if ilegibles:
        # La API respondió 200 pero algo no vino, o vino con un esquema que no sabemos
        # leer. Eso SÍ es un fallo, y antes acababa como "seguro".
        #
        # Lo importante es que sea un fallo y no un cero: un modelo ausente se rellenaba
        # con `0.0`, y `0.0` es exactamente lo que dice una imagen limpia. Así se perdía
        # una dimensión entera —la de desnudez— sin que nada lo delatara.
        #
        # Ojo con la condición: `not any(models.get(c))` era FALSO para una imagen
        # perfectamente limpia en la que todos los valores son 0.0, que es el caso
        # normal. Eso hacía que cada imagen limpia se reportara como error, y como los
        # fallos no se cacheaban, se volvía a subir a SightEngine cada vez que alguien
        # la republicaba: 5 operaciones del plan gratis, indefinidamente.
        #
        # Se loguean las claves de verdad de la respuesta. Este log es lo que permite
        # distinguir "no vino el modelo" de "vino con otro esquema" sin tener que
        # reproducirlo contra la API de pago.
        log.warning(
            f"SE API 200 con modelos ilegibles → pedidos={pedidos} "
            f"ilegibles={ilegibles} claves={sorted(result)}"
        )
        detalle = f"la respuesta no trae datos usables de: {', '.join(ilegibles)}"
        # Un 200 significa que SightEngine YA ha cobrado las operaciones. Sin caché, cada
        # reaparición de esta imagen vuelve a pagar las 5.
        await _cachear_fallo(clave, ERROR_SIN_MODELOS, detalle)
        return _fallo(ERROR_SIN_MODELOS, detalle)

    models = parsear_modelos(result)

    # Los umbrales del guild si vienen; si no, los de `core.config`. Antes el panel
    # ofrecía seis umbrales que nadie leía, así que cambiarlos no hacía nada.
    veredicto, confianza, detalle = evaluar_contenido(models, umbrales)
    is_nsfw = veredicto is Veredicto.NSFW
    max_confidence = max((_a_float(models.get(c)) for c in CLAVES_CONTENIDO), default=0.0)

    log.debug(
        f"SE API OK → veredicto={veredicto.value} max_confidence={max_confidence:.2f} "
        f"models={models} detalle={detalle}"
    )

    cache_details = {
        "is_nsfw": is_nsfw,
        "max_confidence": max_confidence,
        "models": models,
        "veredicto": veredicto.value,
        "detalle": detalle,
    }
    cache_json = json.dumps(cache_details)
    await guardar_analisis_db(clave, "nsfw", cache_json, mal=1 if is_nsfw else 0, datos=cache_details)
    await set_cache_mem(clave, cache_json, mal=1 if is_nsfw else 0, datos=cache_details)
    await guardar_datos()
    return is_nsfw, max_confidence, models, False