# Commit: 5888558
import discord
from discord.ext import commands
import aiohttp
import asyncio
import os
from typing import Optional, Any
import logging
from dotenv import load_dotenv

from core import state
from core.config import TOKEN, VT_API_KEYS, SE_API_KEYS_PAIRS, OWNER_ID
from core.database import init_db, cargar_datos

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
logging.getLogger("cache").setLevel(logging.DEBUG)
logging.getLogger("db").setLevel(logging.DEBUG)
logging.getLogger("handler").setLevel(logging.DEBUG)
logging.getLogger("virustotal").setLevel(logging.DEBUG)
logging.getLogger("sightengine").setLevel(logging.DEBUG)
log = logging.getLogger("bot")

load_dotenv()

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix="-", intents=intents, allowed_mentions=discord.AllowedMentions.none())
state.bot = bot

bot.session: Optional[aiohttp.ClientSession] = None
bot.db: Any = None
bot.db_lock: Any = None
bot.guilds_data: dict[int | str, Any] = {}

bot.antispam_scan: dict[int, float] = {}
bot.user_scan_history: dict[int, list[float]] = {}

bot.vt_key_index: int = 0
bot.vt_key_usage: dict[str, list[float]] = {}
bot.vt_key_total_requests: dict[str, int] = {}
bot.vt_key_daily_usage: dict[str, Any] = {}
bot.vt_key_count: int = 0

bot.se_key_index: int = 0
bot.se_key_usage: dict[str, list[float]] = {}
bot.se_key_total_requests: dict[str, int] = {}
bot.se_key_daily_usage: dict[str, Any] = {}
bot.se_key_count: int = 0

from api.virustotal import analizar_url, analizar_hash, analizar_ip, analizar_archivo, enviar_log_guild, obtener_siguiente_key, obtener_siguiente_se_key, registrar_uso_se, registrar_uso_vt
bot.analizar_url = analizar_url
bot.analizar_hash = analizar_hash
bot.analizar_ip = analizar_ip
bot.analizar_archivo = analizar_archivo
bot.registrar_uso_se = registrar_uso_se
bot.registrar_uso_vt = registrar_uso_vt

from api.sightengine import analizar_imagen_multimodelo
bot.analizar_imagen_nsfw = analizar_imagen_multimodelo

from core.database import guardar_analisis_db, obtener_analisis_db, guardar_datos
bot.guardar_analisis_db = guardar_analisis_db
bot.obtener_analisis_db = obtener_analisis_db
bot.guardar_datos = guardar_datos

from core.cache import get_from_cache_mem, set_cache_mem, cache_mem
bot.get_from_cache_mem = get_from_cache_mem
bot.set_cache_mem = set_cache_mem
bot.cache_mem = cache_mem

from core.guild_config import obtener_config_guild, obtener_stats_globales, update_stats
bot.obtener_config_guild = obtener_config_guild
bot.obtener_stats_globales = obtener_stats_globales
bot.update_stats_guild = update_stats

from core.utils import expandir_url, tiene_doble_extension, dominio_en_whitelist, barra_porcentaje, safe_send
bot.expandir_url = expandir_url
bot.tiene_doble_extension = tiene_doble_extension
bot.dominio_en_whitelist = dominio_en_whitelist
bot.barra_porcentaje = barra_porcentaje
bot.safe_send = safe_send

from core.config import (
    EMOJI_CORRECTO, EMOJI_INCORRECTO, EMOJI_WARNING, EMOJI_LINK, EMOJI_LUPA,
    EMOJI_LOADING, EMOJI_FILE, EMOJI_SHIELD, EMOJI_FINGERPRINT, EMOJI_GUARDIAN,
    EMOJI_STATS, EMOJI_WHITELIST, EMOJI_COOLDOWN, EMOJI_REPLY, EMOJI_KEY,
    EMOJI_KICK, EMOJI_BAN, EMOJI_CLEAN, MAX_FILE_SIZE, CACHE_DURATION, DATA_FILE, DB_FILE,
)
bot.EMOJI_CORRECTO = EMOJI_CORRECTO
bot.EMOJI_INCORRECTO = EMOJI_INCORRECTO
bot.EMOJI_WARNING = EMOJI_WARNING
bot.EMOJI_LINK = EMOJI_LINK
bot.EMOJI_LUPA = EMOJI_LUPA
bot.EMOJI_LOADING = EMOJI_LOADING
bot.EMOJI_FILE = EMOJI_FILE
bot.EMOJI_SHIELD = EMOJI_SHIELD
bot.EMOJI_FINGERPRINT = EMOJI_FINGERPRINT
bot.EMOJI_GUARDIAN = EMOJI_GUARDIAN
bot.EMOJI_STATS = EMOJI_STATS
bot.EMOJI_WHITELIST = EMOJI_WHITELIST
bot.EMOJI_COOLDOWN = EMOJI_COOLDOWN
bot.EMOJI_REPLY = EMOJI_REPLY
bot.EMOJI_KEY = EMOJI_KEY
bot.EMOJI_KICK = EMOJI_KICK
bot.EMOJI_BAN = EMOJI_BAN
bot.EMOJI_CLEAN = EMOJI_CLEAN
bot.MAX_FILE_SIZE = MAX_FILE_SIZE
bot.CACHE_DURATION = CACHE_DURATION
bot.DATA_FILE = DATA_FILE
bot.DB_FILE = DB_FILE

@bot.event
async def setup_hook() -> None:
    await load_cogs()

@bot.event
async def on_ready() -> None:
    bot.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60))
    bot.vt_key_count = len(VT_API_KEYS)
    bot.se_key_count = len(SE_API_KEYS_PAIRS)
    await init_db()
    await cargar_datos()
    await bot.tree.sync()
    asyncio.create_task(_rotar_estado())
    asyncio.create_task(_limpiar_cron())
    log.info(f"Bot conectado como {bot.user}")
    log.info("Bot Ready - comandos slash sincronizados")

async def _rotar_estado() -> None:
    estados = [
        "Escaneando malware - /help",
        "Protegiendo servidores - /help",
        "Analizando enlaces - /help",
        "Detectando amenazas - /help",
        "Vigilando la red - /help",
    ]
    indice = 0
    while True:
        await bot.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name=estados[indice]),
            status=discord.Status.dnd
        )
        log.debug(f"Estado rotated: {estados[indice]}")
        indice = (indice + 1) % len(estados)
        await asyncio.sleep(30)

async def _limpiar_cron() -> None:
    from core.database import limpiar_db_expirados
    while True:
        await asyncio.sleep(3600)
        try:
            await limpiar_db_expirados()
            log.debug("Caché expirada limpiada")
        except Exception as e:
            log.error(f"Error limpiando caché: {e}")

@bot.event
async def on_message(message: discord.Message) -> None:
    if message.author == bot.user or not message.guild:
        await bot.process_commands(message)
        return
    from ui.message_handler import procesar_analisis
    await procesar_analisis(bot, message)
    await bot.process_commands(message)

@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message) -> None:
    if before.author == bot.user or not after.guild:
        return
    if before.content == after.content and len(before.attachments) == len(after.attachments):
        return
    from ui.message_handler import procesar_analisis
    await procesar_analisis(bot, after)

@bot.event
async def on_guild_remove(guild: discord.Guild) -> None:
    bot.guilds_data.pop(guild.id, None)
    log.info(f"Bot removido del guild {guild.name} ({guild.id}) — datos limpiados")
    from core.database import guardar_datos
    await guardar_datos(inmediato=True)

async def shutdown() -> None:
    if bot.db:
        await bot.db.close()
        bot.db = None
    if bot.session:
        await bot.session.close()
        bot.session = None

original_close = bot.close
async def close_with_cleanup() -> None:
    await shutdown()
    await original_close()
bot.close = close_with_cleanup

async def load_cogs() -> None:
    for archivo in os.listdir("./cogs"):
        if archivo.endswith(".py"):
            await bot.load_extension(f"cogs.{archivo[:-3]}")
            log.info(f"Cargado cog: {archivo}")

if __name__ == "__main__":
    if not TOKEN:
        log.error("DISCORD_TOKEN no detectado en el entorno.")
    if not OWNER_ID:
        log.warning("OWNER_ID no configurado. Comandos eval/reboot no disponibles.")
    if not VT_API_KEYS:
        log.warning("No hay claves VT. Análisis de VirusTotal no funcionará.")
    if not SE_API_KEYS_PAIRS:
        log.warning("No hay pares Sightengine. Detección NSFW no funcionará.")
    bot.run(TOKEN)
