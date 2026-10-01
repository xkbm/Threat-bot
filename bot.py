# Commit: 5aec13e
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
# `members` es un intent privilegiado y el bot no lee miembros en ningún sitio
# (ni `on_member_join` ni iteraciones sobre `guild.members`). Pedirlo obligaba a
# habilitarlo en el developer portal sin ningún beneficio: si el portal no lo tiene,
# el gateway lo rechaza y el bot no arranca.
bot = commands.Bot(command_prefix="-", intents=intents, allowed_mentions=discord.AllowedMentions.none())
state.bot = bot

bot.session = None
bot.guilds_data = {}

bot.antispam_scan = {}
bot.user_scan_history = {}
bot.vt_user_requests = {}
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
from api.virustotal import analizar_url, analizar_hash, analizar_ip, analizar_archivo, enviar_log_guild
bot.analizar_url = analizar_url
bot.analizar_hash = analizar_hash
bot.analizar_ip = analizar_ip
bot.analizar_archivo = analizar_archivo

from api.sightengine import analizar_imagen_multimodelo
bot.analizar_imagen_nsfw = analizar_imagen_multimodelo

from core.database import guardar_analisis_db, obtener_analisis_db
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
    EMOJI_CORRECTO, EMOJI_INCORRECTO, EMOJI_ERROR, EMOJI_WARNING, EMOJI_LINK, EMOJI_LUPA,
    EMOJI_LOADING, EMOJI_LOADING_ERROR, EMOJI_FILE, EMOJI_SHIELD, EMOJI_FINGERPRINT, EMOJI_GUARDIAN,
    EMOJI_STATS, EMOJI_WHITELIST, EMOJI_COOLDOWN, EMOJI_REPLY, EMOJI_KEY,
    EMOJI_KICK, EMOJI_BAN, EMOJI_CLEAN, EMOJI_GITHUB, EMOJI_NSFW,
    EMOJI_RESTRINGIDO, EMOJI_PHISHING,
    COLOR_SEGURO, COLOR_ERROR,
    MAX_FILE_SIZE, CACHE_DURATION, DATA_FILE, DB_FILE,
    ANTISPAM_COOLDOWN, ANTISPAM_WINDOW,
    VT_MAX_ANALYSES_PER_MINUTE, VT_MAX_ANALYSES_PER_DAY,
    SE_MAX_OPS_PER_DAY, SE_OPS_PER_CALL,
)
from ui import embed as emb
bot.EMOJI_CORRECTO = EMOJI_CORRECTO
bot.EMOJI_INCORRECTO = EMOJI_INCORRECTO
bot.EMOJI_ERROR = EMOJI_ERROR
bot.EMOJI_WARNING = EMOJI_WARNING
bot.EMOJI_LINK = EMOJI_LINK
bot.EMOJI_LUPA = EMOJI_LUPA
bot.EMOJI_LOADING = EMOJI_LOADING
bot.EMOJI_LOADING_ERROR = EMOJI_LOADING_ERROR
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
bot.EMOJI_NSFW = EMOJI_NSFW
bot.EMOJI_RESTRINGIDO = EMOJI_RESTRINGIDO
bot.EMOJI_PHISHING = EMOJI_PHISHING
bot.MAX_FILE_SIZE = MAX_FILE_SIZE
bot.ANTISPAM_ANALYSIS_PER_HOUR = ANTISPAM_ANALYSIS_PER_HOUR
bot.ANTISPAM_COOLDOWN = ANTISPAM_COOLDOWN
bot.ANTISPAM_WINDOW = ANTISPAM_WINDOW
bot.VT_MAX_ANALYSES_PER_MINUTE = VT_MAX_ANALYSES_PER_MINUTE
bot.VT_MAX_ANALYSES_PER_DAY = VT_MAX_ANALYSES_PER_DAY
bot.SE_MAX_OPS_PER_DAY = SE_MAX_OPS_PER_DAY
bot.SE_OPS_PER_CALL = SE_OPS_PER_CALL
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
    await bot.change_presence(
        activity=discord.Activity(type=discord.ActivityType.watching, name="tbot-dc.vercel.app - /help"),
        status=discord.Status.dnd
    )
    task_cron = asyncio.create_task(_limpiar_cron())
    bot._background_tasks = [task_cron]
    log.info(f"Bot conectado como {bot.user}")
    log.info("Bot Ready - comandos slash sincronizados")

async def _limpiar_cron():
    from core.database import limpiar_db_expirados, purgar_eventos, purgar_infracciones
    from ui.message_handler import limpiar_cache_procesados
    while True:
        await asyncio.sleep(3600)
        try:
            await limpiar_db_expirados()
            # Las infracciones y los eventos vivían en listas/JSON que crecían sin
            # límite. Ahora son tablas y se pueden purgar por fecha. Sin esto, cada
            # elemento distinto que alguien publica añade una fila para siempre.
            await purgar_infracciones(90)
            await purgar_eventos(30)
            ahora = time.time()
            expired_history = [k for k, v in bot.user_scan_history.items()
                              if not v or ahora - v[-1] > 3600]
            for k in expired_history:
                del bot.user_scan_history[k]
            expired_anti = [k for k, v in bot.antispam_scan.items()
                           if ahora - v > 3600]
            for k in expired_anti:
                del bot.antispam_scan[k]
            expired_vt = [k for k, v in bot.vt_user_requests.items()
                          if not v or ahora - v[-1] > 60]
            for k in expired_vt:
                del bot.vt_user_requests[k]
            expirados_huella = limpiar_cache_procesados()
            # F5: los contadores de uso de API y el antispam solo vivían en RAM y se
            # perdían en cada reinicio, así que /stats volvía a 0% de cuota consumida.
            # El volcado es siempre completo ahora; antes hacía falta `include_runtime`,
            # y como la mayoría de los llamantes no lo pasaban, un solo análisis bastaba
            # para borrar los contadores que este mismo guardado acababa de escribir.
            await guardar_datos(inmediato=True)
            if expired_history or expired_anti or expired_vt or expirados_huella:
                log.debug(
                    f"Cleanup: {len(expired_history)} history + {len(expired_anti)} antispam "
                    f"+ {len(expired_vt)} vt + {expirados_huella} huellas"
                )
        except Exception as e:
            log.error(f"Error limpiando caché: {e}")

def _es_emisor_que_ignoramos(message: discord.Message) -> bool:
    """Mensajes que no disparan análisis.

    Otros bots y webhooks se filtran porque sus mensajes son casi siempre automáticos:
    analizarlos consume cuota de SightEngine y VirusTotal para nada y puede disparar el
    antispam de un usuario que solo está pegando lo que le devuelve otra herramienta.
    """
    if message.author == bot.user:
        return True
    if getattr(message.author, "bot", False):
        return True
    # `webhook_id` no se rellena en todos los caminos de la librería; se comprueba sin
    # asumir que existe.
    if getattr(message, "webhook_id", None):
        return True
    return False


@bot.event
async def on_message(message):
    if not message.guild:
        await bot.process_commands(message)
        return
    if _es_emisor_que_ignoramos(message):
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
    if not after.guild or _es_emisor_que_ignoramos(after):
        return
    if before.content == after.content and len(before.attachments) == len(after.attachments):
        return
    from ui.message_handler import procesar_analisis
    async def _analisis_edit_con_sem():
        async with bot._analysis_sem:
            await procesar_analisis(bot, after)
    task = asyncio.create_task(_analisis_edit_con_sem())
    task.add_done_callback(lambda t: log.error(f"Task error: {t.exception()}", exc_info=t.exception()) if t.exception() else None)

async def _enviar_guild_log(guild: discord.Guild, accion: str, color: int):
    canal = bot.get_channel(758876871173079060)
    if not canal:
        return
    embed = emb.aviso(accion, con_pie=False, color=color)
    embed.add_field(name=f"{EMOJI_LINK} Servidor", value=guild.name, inline=True)
    embed.add_field(name="ID", value=f"`{guild.id}`", inline=True)
    embed.add_field(name="Miembros", value=f"**{guild.member_count}**", inline=True)
    embed.add_field(name="Owner", value=str(guild.owner), inline=True)
    embed.add_field(name="Total servidores", value=f"**{len(bot.guilds)}**", inline=True)
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    emb.pie(embed, f"Servidor · {accion}")
    try:
        await canal.send(embed=embed)
    except Exception as e:
        log.error(f"_enviar_guild_log: error enviando embed: {e}")

@bot.event
async def on_guild_join(guild):
    await _enviar_guild_log(guild, "Añadido a un servidor", COLOR_SEGURO)

@bot.event
async def on_guild_remove(guild):
    """El bot salió del servidor: se borra su rastro entero.

    Antes solo se quitaba de RAM y de `data.json`. Las filas de SQLite (config,
    whitelist, infracciones, eventos) se quedaban, así que si el bot volvía a ser
    invitado `/usercheck` seguía mostrando infracciones del periodo en que no estaba, y
    una whitelist que un admin había borrado reaparecía. Confiar en la purga por fecha no
    vale: 90 días de infracciones y 30 de eventos son mucho.
    """
    guild_id = guild.id
    if guild_id in bot.guilds_data:
        bot.guilds_data.pop(guild_id, None)
        await guardar_datos(inmediato=True)
    from core.database import borrar_guild_db
    from core.guild_config import remove_guild_lock, olvidar_guild
    await remove_guild_lock(guild_id)
    await borrar_guild_db(guild_id)
    await olvidar_guild(guild_id)
    log.info(f"Guild {guild_id} ({guild.name}) eliminada — RAM, data.json y SQLite limpiados")
    await _enviar_guild_log(guild, "Eliminado de un servidor", COLOR_ERROR)

async def shutdown():
    for task in bot._background_tasks:
        task.cancel()
    if bot._background_tasks:
        await asyncio.gather(*bot._background_tasks, return_exceptions=True)
    from core.database import guardar_datos, POOL
    await guardar_datos(inmediato=True)
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
    # Ruta basada en __file__ y no en "./cogs": si el proceso se arranca con otro
    # directorio de trabajo, os.listdir("./cogs") fallaba y el bot cargaba cero cogs
    # sin ningún error visible.
    ruta_cogs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cogs")
    if not os.path.isdir(ruta_cogs):
        log.error(f"load_cogs: no se encontró el directorio {ruta_cogs}")
        return
    for archivo in sorted(os.listdir(ruta_cogs)):
        if archivo.endswith(".py") and not archivo.startswith("_"):
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


