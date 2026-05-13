import json
import logging
import aiohttp
import discord
from core import state
from core.config import SE_API_KEYS_PAIRS, SIGHTENGINE_API_URL, SIGHTENGINE_MODELS, NSFW_CONFIDENCE_THRESHOLD
from core.cache import get_from_cache_mem, set_cache_mem
from core.database import guardar_analisis_db, obtener_analisis_db, guardar_datos
from api.virustotal import obtener_siguiente_se_key, registrar_uso_se

log = logging.getLogger("sightengine")

async def analizar_imagen_multimodelo(image_content_hash, image_bytes):
    clave = f"nsfw:{image_content_hash}"
    log.debug(f"SE check → hash={image_content_hash[:16]}... clave={clave}")
    tipo, embed_cache, mal = get_from_cache_mem(clave)
    if embed_cache is not None:
        try:
            details = json.loads(tipo) if isinstance(tipo, str) else tipo
            log.debug(f"SE HIT (RAM) → {clave} is_nsfw={details['is_nsfw']}")
            return details["is_nsfw"], details["max_confidence"], details["models"], True
        except Exception:
            pass
    tipo_db, embed_db, mal_db = await obtener_analisis_db(clave)
    if embed_db is not None:
        try:
            details = json.loads(tipo_db)
            log.debug(f"SE HIT (SQLite) → {clave} is_nsfw={details['is_nsfw']}")
            set_cache_mem(clave, tipo_db, embed_db, mal_db)
            return details["is_nsfw"], details["max_confidence"], details["models"], True
        except Exception:
            pass
    log.debug(f"SE MISS → llamando API Sightengine para {clave}")
    if not SE_API_KEYS_PAIRS:
        log.error("Sightengine no configurado correctamente.")
        return False, 0.0, {}, False

    pair = await obtener_siguiente_se_key()
    if not pair:
        log.error("No hay pares de Sightengine disponibles.")
        return False, 0.0, {}, False
    api_user, api_key = pair

    try:
        data = aiohttp.FormData()
        data.add_field('media', image_bytes, filename='image.jpg')
        data.add_field('models', SIGHTENGINE_MODELS)
        data.add_field('api_user', api_user)
        data.add_field('api_secret', api_key)
        async with state.bot.session.post(SIGHTENGINE_API_URL, data=data) as resp:
            if resp.status == 200:
                await registrar_uso_se(api_key)
                result = await resp.json()
                models = {}
                for model_name in SIGHTENGINE_MODELS.split(','):
                    model_data = result.get(model_name, {})
                    confidence = model_data.get('raw', 0.0)
                    models[model_name] = confidence
                is_nsfw = (
                    models.get('nudity', 0.0) >= NSFW_CONFIDENCE_THRESHOLD
                    or models.get('weapon', 0.0) >= NSFW_CONFIDENCE_THRESHOLD
                    or models.get('offensive', 0.0) >= 0.7
                )
                max_confidence = max(models.values()) if models else 0.0
                log.debug(f"SE API OK → is_nsfw={is_nsfw} max_confidence={max_confidence:.2f} models={models}")
                cache_details = {"is_nsfw": is_nsfw, "max_confidence": max_confidence, "models": models}
                cache_json = json.dumps(cache_details)
                dummy_embed = discord.Embed(title="NSFW Cache")
                await guardar_analisis_db(clave, "nsfw", cache_json, dummy_embed, 1 if is_nsfw else 0)
                set_cache_mem(clave, cache_json, dummy_embed, 1 if is_nsfw else 0)
                await guardar_datos(inmediato=True)
                return is_nsfw, max_confidence, models, False
            else:
                log.debug(f"SE API ERROR → status={resp.status}")
                if resp.status == 400:
                    error_details = {"is_nsfw": False, "max_confidence": 0.0, "models": {}, "error": "sightengine_400"}
                    error_json = json.dumps(error_details)
                    dummy_embed = discord.Embed(title="NSFW Error Cache")
                    await guardar_analisis_db(clave, "nsfw", error_json, dummy_embed, 0)
                    set_cache_mem(clave, error_json, dummy_embed, 0)
                    return False, 0.0, {"error": "too_large"}, False
    except Exception as e:
        log.error(f"Excepción en análisis multimodelo: {e}")
    return False, 0.0, {}, False
