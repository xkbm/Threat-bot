import asyncio
from core import state
from core.config import DOMINIOS_PROTEGIDOS
from core.database import guardar_datos

GUILD_LOCK = asyncio.Lock()

def obtener_config_guild(guild_id):
    if guild_id not in state.bot.guilds_data:
        state.bot.guilds_data[guild_id] = {
            "silent_mode": False,
            "strict_mode": False,
            "log_channel_id": None,
            "whitelist": list(DOMINIOS_PROTEGIDOS),
            "stats": {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0},
            "infracciones": {},
            "infracciones_registradas": {},
        }
    return state.bot.guilds_data[guild_id]

def obtener_stats_globales():
    if "__global__" not in state.bot.guilds_data:
        state.bot.guilds_data["__global__"] = {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0}
    return state.bot.guilds_data["__global__"]

async def update_stats(guild_id, tipo):
    async with GUILD_LOCK:
        if guild_id:
            config = obtener_config_guild(guild_id)
            stats = config["stats"]
            stats["total_analisis"] += 1
            if tipo == "seguro":
                stats["seguros"] += 1
            elif tipo == "malicioso":
                stats["maliciosos"] += 1
            else:
                stats["errores"] += 1
        global_stats = obtener_stats_globales()
        global_stats["total_analisis"] += 1
        if tipo == "seguro":
            global_stats["seguros"] += 1
        elif tipo == "malicioso":
            global_stats["maliciosos"] += 1
        else:
            global_stats["errores"] += 1
    await guardar_datos()

async def registrar_infraccion(guild_id, user_id, elemento_id):
    async with GUILD_LOCK:
        config = obtener_config_guild(guild_id)
        if "infracciones" not in config:
            config["infracciones"] = {}
        if "infracciones_registradas" not in config:
            config["infracciones_registradas"] = {}
        uid = str(user_id)
        if uid not in config["infracciones_registradas"]:
            config["infracciones_registradas"][uid] = []
        if elemento_id in config["infracciones_registradas"][uid]:
            return config["infracciones"].get(uid, 0)
        config["infracciones_registradas"][uid].append(elemento_id)
        config["infracciones"][uid] = config["infracciones"].get(uid, 0) + 1
    await guardar_datos()
    return config["infracciones"][uid]
