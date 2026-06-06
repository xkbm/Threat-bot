# Commit: 1fc0ffe
import discord
from discord.ext import commands
import aiohttp
import asyncio
import os
import time
import logging
import json as _json
from datetime import datetime, timezone
from dotenv import load_dotenv

MAX_ANALYSIS_TASKS = 100

from core import state
from core.config import TOKEN, VT_API_KEYS, SE_API_KEYS_PAIRS, OWNER_ID, ANTISPAM_ANALYSIS_PER_HOUR
from core.database import init_db, cargar_datos, guardar_datos

class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        return _json.dumps(log_entry, ensure_ascii=False)

_log_format = os.getenv("LOG_FORMAT", "text")
if _log_format == "json":
    _handler = logging.StreamHandler()
    _handler.setFormatter(StructuredFormatter())
    logging.root.handlers = [_handler]
    logging.root.setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
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
bot.guilds_data = {}

bot.antispam_scan = {}
bot.user_scan_history = {}
bot._ready_done = False
bot._background_tasks: list[asyncio.Task] = []
bot._analysis_sem = asyncio.Semaphore(MAX_ANALYSIS_TASKS)
bot._download_sem = asyncio.Semaphore(5)

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

from core.cache import get_from_cache_mem, set_cache_mem
bot.get_from_cache_mem = get_from_cache_mem
bot.set_cache_mem = set_cache_mem

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
    EMOJI_KICK, EMOJI_BAN, EMOJI_CLEAN, EMOJI_GITHUB, MAX_FILE_SIZE, CACHE_DURATION, DATA_FILE, DB_FILE,
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
bot.EMOJI_GITHUB = EMOJI_GITHUB
bot.MAX_FILE_SIZE = MAX_FILE_SIZE
bot.ANTISPAM_ANALYSIS_PER_HOUR = ANTISPAM_ANALYSIS_PER_HOUR
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
    if bot._ready_done:
        return
    bot._ready_done = True
    bot.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60))
    bot.vt_key_count = len(VT_API_KEYS)
    bot.se_key_count = len(SE_API_KEYS_PAIRS)
    await init_db()
    await cargar_datos()
    await bot.tree.sync()
    task_estado = asyncio.create_task(_rotar_estado())
    task_cron = asyncio.create_task(_limpiar_cron())
    bot._background_tasks = [task_estado, task_cron]
    log.info(f"Bot conectado como {bot.user}")
    log.info("Bot Ready - comandos slash sincronizados")

async def _rotar_estado():
    """Rota el estado del bot cada 30 segundos."""
    estados = [
        "Escaneando malware - /help",
        "Protegiendo servidores - /help",
        "Analizando enlaces - /help",
        "Detectando amenazas - /help",
        "Vigilando la red - /help",
    ]
    indice = 0
    while True:
        try:
            await bot.change_presence(
                activity=discord.Activity(type=discord.ActivityType.watching, name=estados[indice]),
                status=discord.Status.dnd
            )
            log.debug(f"Estado rotated: {estados[indice]}")
            indice = (indice + 1) % len(estados)
        except Exception:
            log.exception("Error rotando estado")
        await asyncio.sleep(30)

async def _limpiar_cron():
    from core.database import limpiar_db_expirados
    while True:
        await asyncio.sleep(3600)
        try:
            await limpiar_db_expirados()
            ahora = time.time()
            expired_history = [k for k, v in bot.user_scan_history.items()
                              if not v or ahora - v[-1] > 3600]
            for k in expired_history:
                del bot.user_scan_history[k]
            expired_anti = [k for k, v in bot.antispam_scan.items()
                           if ahora - v > 3600]
            for k in expired_anti:
                del bot.antispam_scan[k]
            if expired_history or expired_anti:
                log.debug(f"Cleanup: {len(expired_history)} history + {len(expired_anti)} antispam entries removed")
        except Exception as e:
            log.error(f"Error limpiando caché: {e}")

@bot.event
async def on_message(message):
    if message.author == bot.user or not message.guild:
        await bot.process_commands(message)
        return
    from ui.message_handler import procesar_analisis
    async def _analisis_con_sem():
        async with bot._analysis_sem:
            await procesar_analisis(bot, message)
    task = asyncio.create_task(_analisis_con_sem())
    task.add_done_callback(lambda t: log.error(f"Task error: {t.exception()}", exc_info=t.exception()) if t.exception() else None)
    await bot.process_commands(message)

@bot.event
async def on_message_edit(before, after):
    if before.author == bot.user or not after.guild:
        return
    if before.content == after.content and len(before.attachments) == len(after.attachments):
        return
    from ui.message_handler import procesar_analisis
    async def _analisis_edit_con_sem():
        async with bot._analysis_sem:
            await procesar_analisis(bot, after)
    task = asyncio.create_task(_analisis_edit_con_sem())
    task.add_done_callback(lambda t: log.error(f"Task error: {t.exception()}", exc_info=t.exception()) if t.exception() else None)

@bot.event
async def on_guild_remove(guild):
    guild_id = guild.id
    if guild_id in bot.guilds_data:
        bot.guilds_data.pop(guild_id, None)
        await guardar_datos(inmediato=True)
        log.info(f"Guild {guild_id} ({guild.name}) eliminada — datos limpiados")
    from core.guild_config import remove_guild_lock
    await remove_guild_lock(guild_id)

async def shutdown():
    for task in bot._background_tasks:
        task.cancel()
    if bot._background_tasks:
        await asyncio.gather(*bot._background_tasks, return_exceptions=True)
    from core.database import guardar_datos, POOL
    await guardar_datos(inmediato=True, include_runtime=True)
    await POOL.stop()
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
            try:
                await bot.load_extension(f"cogs.{archivo[:-3]}")
                log.info(f"Cargado cog: {archivo}")
            except Exception as e:
                log.error(f"Error cargando cog {archivo}: {e}")

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
