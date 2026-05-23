import time
import logging
from typing import Optional
from collections import OrderedDict
import discord
from core import config

log = logging.getLogger("cache")

MAX_CACHE_SIZE: int = 1000
cache_mem: OrderedDict = OrderedDict()

def get_from_cache_mem(key: str) -> tuple[Optional[str], Optional[discord.Embed], int]:
    if key in cache_mem:
        tipo, mal, embed, timestamp = cache_mem[key]
        if time.time() - timestamp < config.CACHE_DURATION:
            log.debug(f"MEM HIT → key={key} tipo={tipo} mal={mal}")
            cache_mem.move_to_end(key)
            return tipo, embed, mal
        else:
            log.debug(f"MEM EXPIRED → key={key}")
            del cache_mem[key]
    log.debug(f"MEM MISS → key={key}")
    return None, None, 0

def set_cache_mem(key: str, tipo: str, embed: discord.Embed, mal: int = 0) -> None:
    log.debug(f"MEM SET → key={key} tipo={tipo} mal={mal}")
    cache_mem[key] = (tipo, mal, embed, time.time())
    cache_mem.move_to_end(key)
    while len(cache_mem) > MAX_CACHE_SIZE:
        cache_mem.popitem(last=False)
