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

async def obtener_config_guild(guild_id: int) -> dict[str, Any]:
    async with await _get_guild_lock(guild_id):
        if guild_id not in state.bot.guilds_data:
            state.bot.guilds_data[guild_id] = {
                "silent_mode": False,
                "strict_mode": False,
                "auto_scan_enabled": True,
                "log_channel_id": None,
                "whitelist": list(DOMINIOS_PROTEGIDOS),
                "stats": {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0},
                "infracciones": {},
                "infracciones_registradas": {},
            }
        return state.bot.guilds_data[guild_id]

def obtener_stats_globales() -> dict[str, int]:
    if "__global__" not in state.bot.guilds_data:
        state.bot.guilds_data["__global__"] = {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0}
    return state.bot.guilds_data["__global__"]

async def update_stats(guild_id: Optional[int], tipo: str) -> None:
    async with _global_lock:
        if "__global__" not in state.bot.guilds_data:
            state.bot.guilds_data["__global__"] = {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0}
        global_stats = state.bot.guilds_data["__global__"]
        global_stats["total_analisis"] += 1
        if tipo == "seguro":
            global_stats["seguros"] += 1
        elif tipo == "malicioso":
            global_stats["maliciosos"] += 1
        else:
            global_stats["errores"] += 1
    await guardar_datos()
    log.debug(f"STATS UPDATE → guild={guild_id} tipo={tipo} total={global_stats['total_analisis']}")

async def registrar_infraccion(guild_id: int, user_id: int, elemento_id: str) -> int:
    async with await _get_guild_lock(guild_id):
        if guild_id not in state.bot.guilds_data:
            state.bot.guilds_data[guild_id] = {
                "silent_mode": False, "strict_mode": False, "log_channel_id": None,
                "whitelist": list(DOMINIOS_PROTEGIDOS),
                "infracciones": {}, "infracciones_registradas": {},
            }
        config = state.bot.guilds_data[guild_id]
        config.setdefault("infracciones", {})
        config.setdefault("infracciones_registradas", {})
        uid = str(user_id)
        config["infracciones_registradas"].setdefault(uid, [])
        if elemento_id in config["infracciones_registradas"][uid]:
            return config["infracciones"].get(uid, 0)
        config["infracciones_registradas"][uid].append(elemento_id)
        config["infracciones"][uid] = config["infracciones"].get(uid, 0) + 1
    await guardar_datos()
    log.debug(f"INFRACCION → guild={guild_id} user={user_id} elemento={elemento_id} total={config['infracciones'][uid]}")
    return config["infracciones"][uid]
