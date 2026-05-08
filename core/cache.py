import time
from core import config

cache_mem = {}

def get_from_cache_mem(key):
    if key in cache_mem:
        tipo, mal, embed, timestamp = cache_mem[key]
        if time.time() - timestamp < config.CACHE_DURATION:
            return tipo, embed, mal
        else:
            del cache_mem[key]
    return None, None, 0

def set_cache_mem(key, tipo, embed, mal=0):
    cache_mem[key] = (tipo, mal, embed, time.time())
