import time
import asyncio
import logging
from typing import Optional
from collections import OrderedDict
import discord
from core import config

log = logging.getLogger("cache")

_cache_lock = asyncio.Lock()
MAX_CACHE_SIZE: int = 100000
_cache: OrderedDict = OrderedDict()


def _tipo_analisis_de_clave(key: str) -> str:
    """El prefijo de la clave es el tipo de análisis: 'url:…', 'filehash:…'.

    Hace falta porque `set_cache_mem` recibe el VEREDICTO como `tipo`
    ("malicioso"/"seguro"), no el tipo de elemento, y el render lo necesita.
    """
    prefijo = key.split(":", 1)[0] if ":" in key else key
    return "file" if prefijo == "filehash" else prefijo


def _render(tipo_analisis: str, datos: Optional[dict], mal: int) -> Optional[discord.Embed]:
    """Construye el embed desde los datos cacheados (render-on-read).

    Import diferido: ui.embed no depende de core.cache, pero importarlo arriba
    cargaría el módulo de presentación durante el arranque.
    """
    if datos is None:
        return None
    try:
        from ui.embed import resultado
        return resultado(tipo_analisis, datos, mal)
    except Exception as e:
        log.error(f"Error renderizando embed de '{tipo_analisis}': {e}")
        return None


async def get_from_cache_mem(key: str) -> tuple[Optional[str], Optional[discord.Embed], int]:
    """Lee de la caché RAM. El embed se construye al leer, así que siempre sale
    con el diseño vigente aunque la entrada se escribiera hace días.

    Las entradas legacy (sin datos) guardan el dict del embed y lo rehidratan tal cual.
    """
    tipo = None
    mal = 0
    tipo_analisis = "url"
    datos: Optional[dict] = None
    embed_dict = None
    async with _cache_lock:
        if key in _cache:
            tipo, mal, tipo_analisis, datos, embed_dict, timestamp = _cache[key]
            if time.time() - timestamp < config.CACHE_DURATION:
                log.debug(f"MEM HIT → key={key} tipo={tipo} mal={mal} datos={datos is not None}")
                _cache.move_to_end(key)
            else:
                log.debug(f"MEM EXPIRED → key={key}")
                del _cache[key]
                return None, None, 0
        else:
            log.debug(f"MEM MISS → key={key}")
            return None, None, 0

    embed = _render(tipo_analisis, datos, mal)
    if embed is None and embed_dict:
        embed = discord.Embed.from_dict(embed_dict)
    return tipo, embed, mal


async def set_cache_mem(key: str, tipo: str, embed: Optional[discord.Embed] = None, mal: int = 0, datos: Optional[dict] = None) -> None:
    """Guarda en RAM. Si se pasan `datos` no se serializa el embed: se re-renderiza
    en cada lectura. `embed` queda como respaldo para el camino legacy.

    `tipo` es el VEREDICTO ("malicioso"/"seguro"); el tipo de elemento se deduce de
    la clave porque `resultado()` lo necesita para elegir título y color.
    """
    if datos is not None:
        embed_dict = None
    else:
        embed_dict = embed.to_dict() if embed else None
    tipo_analisis = _tipo_analisis_de_clave(key)
    async with _cache_lock:
        log.debug(f"MEM SET → key={key} tipo={tipo} mal={mal} datos={datos is not None}")
        _cache[key] = (tipo, mal, tipo_analisis, datos, embed_dict, time.time())
        _cache.move_to_end(key)
        while len(_cache) > MAX_CACHE_SIZE:
            _cache.popitem(last=False)
