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
from api.virustotal import obtener_siguiente_se_key

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


def _clasificar_400(cuerpo: Optional[dict]) -> tuple[str, str]:
    """Un 400 de SightEngine puede ser tamaño, modelo no disponible o parámetro inválido.

    Antes todo 400 se traducía a `too_large`, así que un modelo no soportado se
    reportaba como "la imagen es demasiado grande": un diagnóstico falso que además
    ocultaba la causa real y hacía imposible arreglarlo.
    """
    texto = ""
    if isinstance(cuerpo, dict):
        err = cuerpo.get("error")
        if isinstance(err, dict):
            texto = f"{err.get('type', '')} {err.get('message', '')}".lower()
        elif isinstance(err, str):
            texto = err.lower()
    if not texto:
        return ERROR_DEMASIADO_GRANDE, "SightEngine rechazó la imagen (HTTP 400)"

    if "model" in texto or "unsupported" in texto or "not available" in texto:
        return ERROR_MODELO_NO_DISPONIBLE, f"SightEngine no admite algún modelo: {texto.strip()}"
    if "large" in texto or "size" in texto or "dimension" in texto:
        return ERROR_DEMASIADO_GRANDE, f"La imagen supera lo admitido por SightEngine: {texto.strip()}"
    return ERROR_HTTP, f"SightEngine rechazó el análisis: {texto.strip()}"


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


def _dato_modelo(result: dict, nombre: str) -> dict:
    """Busca el bloque del modelo tolerando el cambio de nombre.

    Se pide `nudity-2.1` pero la respuesta llega bajo `nudity`; se mira el nombre pedido
    y, si no está, el nombre base.
    """
    bloque = result.get(nombre)
    if isinstance(bloque, dict):
        return bloque
    base = nombre.split("-")[0]
    bloque = result.get(base)
    return bloque if isinstance(bloque, dict) else {}


def parsear_modelos(result: dict) -> Dict[str, float]:
    """Convierte la respuesta de SightEngine en un dict plano de probabilidades.

    Puras y sin estado: es la parte que más fácil de testear y la que estaba mal.
    """
    modelos: Dict[str, float] = {}

    nudity = _dato_modelo(result, "nudity-2.1")
    modelos[CLAVE_NUDITY_RAW] = _a_float(nudity.get("raw"))
    modelos[CLAVE_NUDITY_PARTIAL] = _a_float(nudity.get("partial"))

    gore = _dato_modelo(result, "gore-2.0")
    modelos[CLAVE_GORE] = _a_float(gore.get("prob"))

    weapon = _dato_modelo(result, "weapon")
    clases = {
        nombre: valor
        for nombre, valor in (weapon.get("classes") or {}).items()
        if nombre not in CLASES_WEAPON_IGNORADAS
    }
    modelos[CLAVE_WEAPON] = max((_a_float(v) for v in clases.values()), default=0.0)

    alcohol = _dato_modelo(result, "alcohol")
    modelos[CLAVE_ALCOHOL] = _a_float(alcohol.get("prob"))

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
    image_content_hash: str, image_bytes: bytes
) -> Tuple[bool, float, Dict[str, Any], bool]:
    """Analiza una imagen. Ver el contrato en el docstring del módulo."""
    # La clave cambia de versión porque el contenido guardado tiene otra forma: las
    # entradas viejas no se pueden reparsear. Se dejan caducar solas.
    clave = f"nsfw2:{image_content_hash}"
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

                if resp.status != 400:
                    log.warning(f"SE API ERROR → status={resp.status} models={modelos}")
                    return _fallo(ERROR_HTTP, f"HTTP {resp.status}")

                motivo, detalle = _clasificar_400(cuerpo)
                if motivo != ERROR_MODELO_NO_DISPONIBLE:
                    return _fallo(motivo, detalle)

                # El 400 es por un modelo. Se avisa claro y se prueba con menos.
                log.warning(
                    f"SE: modelos no disponibles en esta cuenta ({modelos}) → "
                    f"reintentando con {MODELOS_CON_FALLBACK[intento + 1] if intento + 1 < len(MODELOS_CON_FALLBACK) else 'ninguno'}"
                )
        except Exception as e:
            log.error(f"Excepción en análisis multimodelo: {e}")
            return _fallo(ERROR_EXCEPCION, str(e))
    else:
        return _fallo(ERROR_MODELO_NO_DISPONIBLE, "ninguna combinación de modelos fue aceptada")

    models = parsear_modelos(result)
    if not any(models.get(c) for c in CLAVES_CONTENIDO):
        # La API respondió 200 pero no devolvió ninguno de los modelos pedidos.
        # Antes esto acababa como "seguro"; es un fallo, no una certeza.
        log.warning(f"SE API 200 sin modelos utilizables → claves={sorted(result)}")
        return _fallo(ERROR_SIN_MODELOS, "la respuesta no incluye los modelos pedidos")

    veredicto, confianza, detalle = evaluar_contenido(models)
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