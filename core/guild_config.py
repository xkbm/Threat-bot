import asyncio
from typing import Optional, Any
import logging
from core import state
from core.config import DOMINIOS_PROTEGIDOS
from core.database import guardar_datos

log = logging.getLogger("guild_config")
_guild_locks: dict[int, asyncio.Lock] = {}
_guild_locks_lock = asyncio.Lock()
_global_lock = asyncio.Lock()

async def _get_guild_lock(guild_id: int) -> asyncio.Lock:
    async with _guild_locks_lock:
        if guild_id not in _guild_locks:
            _guild_locks[guild_id] = asyncio.Lock()
        return _guild_locks[guild_id]

async def remove_guild_lock(guild_id: int) -> None:
    async with _guild_locks_lock:
        _guild_locks.pop(guild_id, None)

def _config_por_defecto() -> dict[str, Any]:
    return {
        "silent_mode": True,
        "strict_mode": True,
        "auto_scan_enabled": True,
        "log_channel_id": None,
        "whitelist": list(DOMINIOS_PROTEGIDOS),
        "infracciones": {},
        "infracciones_registradas": {},
    }


def _asegurar_guild(guild_id: int) -> dict[str, Any]:
    """Devuelve la config del guild creándola con los defaults si no existe.

    NO adquirir el lock del guild: el llamador ya lo tiene.
    """
    if guild_id not in state.bot.guilds_data:
        state.bot.guilds_data[guild_id] = _config_por_defecto()
    config = state.bot.guilds_data[guild_id]
    for key, default_val in _config_por_defecto().items():
        config.setdefault(key, default_val)
    return config


async def obtener_config_guild(guild_id: int) -> dict[str, Any]:
    async with await _get_guild_lock(guild_id):
        return _asegurar_guild(guild_id)


async def agregar_dominio(guild_id: int, dominio: str) -> bool:
    """Añade un dominio a la whitelist del guild. Devuelve True si se añadió."""
    async with await _get_guild_lock(guild_id):
        config = _asegurar_guild(guild_id)
        if dominio in config["whitelist"]:
            return False
        config["whitelist"].append(dominio)
    await guardar_datos(inmediato=True)
    log.debug(f"WHITELIST ADD → guild={guild_id} dominio={dominio}")
    return True


async def quitar_dominio(guild_id: int, dominio: str) -> bool:
    """Quita un dominio de la whitelist del guild. Devuelve True si se quitó."""
    async with await _get_guild_lock(guild_id):
        config = _asegurar_guild(guild_id)
        if dominio not in config["whitelist"]:
            return False
        config["whitelist"].remove(dominio)
    await guardar_datos(inmediato=True)
    log.debug(f"WHITELIST REMOVE → guild={guild_id} dominio={dominio}")
    return True

def _stats_vacias() -> dict[str, int]:
    return {"total_analisis": 0, "seguros": 0, "sospechosos": 0, "maliciosos": 0, "nsfw": 0, "errores": 0}


def obtener_stats_globales() -> dict[str, int]:
    if "__global__" not in state.bot.guilds_data:
        state.bot.guilds_data["__global__"] = _stats_vacias()
    return state.bot.guilds_data["__global__"]


async def update_stats(guild_id: Optional[int], tipo: str) -> None:
    async with _global_lock:
        if "__global__" not in state.bot.guilds_data:
            state.bot.guilds_data["__global__"] = _stats_vacias()
        global_stats = state.bot.guilds_data["__global__"]
        # Un `data.json` escrito antes de que existiera el veredicto "sospechoso" no
        # trae la clave. Sin este default, el primer análisis sospechoso lo guardaría
        # pero `/stats` no lo vería hasta que un "seguro" la recreara.
        for key, valor in _stats_vacias().items():
            global_stats.setdefault(key, valor)
        global_stats["total_analisis"] += 1
        if tipo == "seguro":
            global_stats["seguros"] += 1
        elif tipo == "sospechoso":
            global_stats["sospechosos"] += 1
        elif tipo == "malicioso":
            global_stats["maliciosos"] += 1
        elif tipo == "nsfw":
            global_stats["nsfw"] += 1
        else:
            global_stats["errores"] += 1
    await guardar_datos()
    log.debug(f"STATS UPDATE → guild={guild_id} tipo={tipo} total={global_stats['total_analisis']}")

async def registrar_infraccion(guild_id: int, user_id: int, elemento_id: str) -> int:
    async with await _get_guild_lock(guild_id):
        config = _asegurar_guild(guild_id)
        uid = str(user_id)
        config["infracciones_registradas"].setdefault(uid, [])
        if elemento_id in config["infracciones_registradas"][uid]:
            return config["infracciones"].get(uid, 0)
        config["infracciones_registradas"][uid].append(elemento_id)
        config["infracciones"][uid] = config["infracciones"].get(uid, 0) + 1
    await guardar_datos()
    log.debug(f"INFRACCION → guild={guild_id} user={user_id} elemento={elemento_id} total={config['infracciones'][uid]}")
    return config["infracciones"][uid]
