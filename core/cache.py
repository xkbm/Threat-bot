import time
import asyncio
import logging
from typing import Optional
from collections import OrderedDict
import discord
from core import config

log = logging.getLogger("cache")

_cache_lock = asyncio.Lock()
MAX_CACHE_SIZE: int = 1000
_cache: OrderedDict = OrderedDict()

async def get_from_cache_mem(key: str) -> tuple[Optional[str], Optional[discord.Embed], int]:
    async with _cache_lock:
        if key in _cache:
            tipo, mal, embed, timestamp = _cache[key]
            if time.time() - timestamp < config.CACHE_DURATION:
                log.debug(f"MEM HIT → key={key} tipo={tipo} mal={mal}")
                _cache.move_to_end(key)
                return tipo, embed, mal
            else:
                log.debug(f"MEM EXPIRED → key={key}")
                del _cache[key]
        log.debug(f"MEM MISS → key={key}")
        return None, None, 0

async def set_cache_mem(key: str, tipo: str, embed: discord.Embed, mal: int = 0) -> None:
    async with _cache_lock:
        log.debug(f"MEM SET → key={key} tipo={tipo} mal={mal}")
        _cache[key] = (tipo, mal, embed, time.time())
        _cache.move_to_end(key)
        while len(_cache) > MAX_CACHE_SIZE:
            _cache.popitem(last=False)
