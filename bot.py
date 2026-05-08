import discord
from discord.ext import commands
import aiohttp
import asyncio
import os
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

bot.session = None
bot.db = None
bot.db_lock = None
bot.guilds_data = {}

bot.antispam_scan = {}
bot.user_scan_history = {}

bot.vt_key_index = 0
bot.vt_key_usage = {}
bot.vt_key_total_requests = {}
bot.vt_key_daily_usage = {}
bot.vt_key_count = 0

bot.se_key_index = 0
bot.se_key_usage = {}
bot.se_key_total_requests = {}
bot.se_key_daily_usage = {}
bot.se_key_count = 0

# ========== EXPORTACIONES A COGS ==========
from api.virustotal import analizar_url, analizar_hash, analizar_ip, analizar_archivo, enviar_log_guild, obtener_siguiente_key, obtener_siguiente_se_key, registrar_uso_se
bot.analizar_url = analizar_url
bot.analizar_hash = analizar_hash
bot.analizar_ip = analizar_ip
bot.analizar_archivo = analizar_archivo

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

# ========== SETUP ==========
@bot.event
async def setup_hook():
    await load_cogs()

# ========== EVENTOS ==========
@bot.event
async def on_ready():
    bot.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
    bot.vt_key_count = len(VT_API_KEYS)
    bot.se_key_count = len(SE_API_KEYS_PAIRS)
    await init_db()
    cargar_datos()
    await bot.tree.sync()
    await bot.change_presence(
        activity=discord.Activity(type=discord.ActivityType.watching, name="Viendo enlaces - /help"),
        status=discord.Status.dnd
    )
    asyncio.create_task(_limpiar_cron())
    log.info(f"Bot conectado como {bot.user}")
    log.info("Bot Ready - comandos slash sincronizados")

async def _limpiar_cron():
    from core.database import limpiar_db_expirados
    while True:
        await asyncio.sleep(3600)
        try:
            await limpiar_db_expirados()
            log.debug("Caché expirada limpiada")
        except Exception as e:
            log.error(f"Error limpiando caché: {e}")

@bot.event
async def on_message(message):
    if message.author == bot.user or not message.guild:
        await bot.process_commands(message)
        return
    from ui.message_handler import procesar_analisis
    await procesar_analisis(bot, message)
    await bot.process_commands(message)

@bot.event
async def on_message_edit(before, after):
    if before.author == bot.user or not after.guild:
        return
    if before.content == after.content and len(before.attachments) == len(after.attachments):
        return
    from ui.message_handler import procesar_analisis
    await procesar_analisis(bot, after)

async def shutdown():
    if bot.db:
        await bot.db.close()
        bot.db = None
    if bot.session:
        await bot.session.close()
        bot.session = None

original_close = bot.close
async def close_with_cleanup():
    await shutdown()
    await original_close()
bot.close = close_with_cleanup

async def load_cogs():
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
