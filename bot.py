# Threat - Sistema de seguridad para Discord (Refactorizado)
# Sesión global, función unificada, aiosqlite, reintentos VT, emojis finally, whitelist robusta

import discord
from discord.ext import commands
from discord import app_commands
import aiohttp
import asyncio
import re
import time
import urllib.parse
import json
import os
import aiosqlite
import hashlib
from dotenv import load_dotenv 

# ========== CARGA DE VARIABLES ==========
load_dotenv(dotenv_path=".env")

TOKEN = os.getenv("DISCORD_TOKEN")

# -------------------- VIRUSTOTAL --------------------
VT_KEYS_RAW = [
    os.getenv("VT_API_KEY"),
    os.getenv("VT_API_KEY_2"),
    os.getenv("VT_API_KEY_3")
]
VT_API_KEYS = [k for k in VT_KEYS_RAW if k]

# -------------------- SIGHTENGINE --------------------
se_vars = [
    (os.getenv("SIGHTENGINE_API_USER"),    os.getenv("SIGHTENGINE_API_KEY")),
    (os.getenv("SIGHTENGINE_API_USER_2"),  os.getenv("SIGHTENGINE_API_KEY_2")),
    (os.getenv("SIGHTENGINE_API_USER_3"),  os.getenv("SIGHTENGINE_API_KEY_3")),
]
SE_API_KEYS_PAIRS = [(u, k) for u, k in se_vars if u and k]

if not TOKEN:
    print("❌ ERROR: DISCORD_TOKEN no detectado en el entorno.")
if not SE_API_KEYS_PAIRS:
    print("⚠️ ADVERTENCIA: No se encontraron pares válidos de Sightengine. La detección NSFW no funcionará.")
# ========================================

MAX_FILE_SIZE = 32 * 1024 * 1024      # 32 MB (VirusTotal)
MAX_IMAGE_SIZE = 2 * 1024 * 1024      # 2 MB (Sightengine)
CACHE_DURATION = 3600
DATA_FILE = "data.json"
DB_FILE = "analisis.db"

EXPIRACION = {
    "url": 7 * 24 * 3600,
    "hash": 30 * 24 * 3600,
    "ip": 7 * 24 * 3600,
    "file": 30 * 24 * 3600,
    "nsfw": 30 * 24 * 3600
}

SIGHTENGINE_API_URL = "https://api.sightengine.com/1.0/check.json"
SIGHTENGINE_MODELS = "nudity,weapon,alcohol,offensive"
NSFW_CONFIDENCE_THRESHOLD = 0.5

# ========== EMOJIS (personalizados) ==========
EMOJI_CORRECTO = "<:SM_Correcto:1015080045410263051>"
EMOJI_INCORRECTO = "<:SM_Incorrecto:1015080005950259300>"
EMOJI_WARNING = "<:SM_Warning:1016367428193767504>"
EMOJI_LINK = "<:SM_Link:1015452825834242088>"
EMOJI_LUPA = "<:SM_Lupa:1020191899258204160>"
EMOJI_LOADING = "<:SM_Loading:1495492361881653258>"
EMOJI_FILE = "<:SM_File:1495493423728427028>"
EMOJI_SHIELD = "<:SM_Shield:1495494358646915172>"
EMOJI_FINGERPRINT = "<:SM_Fingerprint:1495496674833862726>"
EMOJI_GUARDIAN = "<:SM_Guardian:1495497006825603263>"
EMOJI_STATS = "<:SM_Stats:1495498539059646605>"
EMOJI_WHITELIST = "<:SM_Whitelist:1496963945943269498>"
EMOJI_COOLDOWN = "<:SM_Cooldown:1497096698676379752>"
EMOJI_REPLY = "<:SM_Reply:1042590456892104835>"
EMOJI_KEY = "<:SM_Key:1497274741160149153>"
EMOJI_KICK = "<:SM_Kick:1498412609484099626>"
EMOJI_BAN = "<:SM_Ban:1498412610704375848>"
EMOJI_CLEAN = "<:SM_Clean:1498412609056014336>"

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix="-", intents=intents, allowed_mentions=discord.AllowedMentions.none())

# ========== FUNCIONES GLOBALES ==========
async def safe_remove_loading(msg):
    """Elimina de forma segura la reacción de carga, ignorando si el mensaje ya no existe."""
    try:
        await msg.remove_reaction(EMOJI_LOADING, bot.user)
    except discord.NotFound:
        pass

async def safe_add_reaction(msg, emoji):
    """Añade una reacción de forma segura, ignorando si el mensaje ya no existe o no se permite."""
    try:
        await msg.add_reaction(emoji)
    except (discord.NotFound, discord.Forbidden):
        pass

def dominio_en_whitelist(dominio: str, whitelist: list) -> bool:
    """Comprueba si el dominio (sin www.) está en la whitelist de forma robusta."""
    dominio = dominio.lower().strip()
    for d in whitelist:
        d = d.lower().strip()
        if dominio == d or dominio.endswith("." + d):
            return True
    return False

# ========== SEGUIMIENTO DE USO DE APIs ==========
bot.antispam_scan = {}
bot.user_scan_history = {}
bot.vt_key_index = 0
bot.vt_key_usage = {}
bot.vt_key_total_requests = {}
bot.vt_key_daily_usage = {}
bot.vt_key_count = len(VT_API_KEYS)

bot.se_key_index = 0
bot.se_key_usage = {}
bot.se_key_total_requests = {}
bot.se_key_daily_usage = {}
bot.se_key_count = len(SE_API_KEYS_PAIRS)

# ========== FUNCIONES DE ROTACIÓN ==========
def obtener_siguiente_key():
    if not VT_API_KEYS:
        return None
    key = VT_API_KEYS[bot.vt_key_index]
    ahora = time.time()
    hoy = time.strftime("%Y-%m-%d", time.gmtime())
    if key not in bot.vt_key_usage:
        bot.vt_key_usage[key] = []
    if key not in bot.vt_key_total_requests:
        bot.vt_key_total_requests[key] = 0
    if key not in bot.vt_key_daily_usage:
        bot.vt_key_daily_usage[key] = {"count": 0, "date": hoy}
    bot.vt_key_usage[key] = [t for t in bot.vt_key_usage[key] if ahora - t <= 60]
    bot.vt_key_usage[key].append(ahora)
    if bot.vt_key_daily_usage[key]["date"] != hoy:
        bot.vt_key_daily_usage[key] = {"count": 1, "date": hoy}
    else:
        bot.vt_key_daily_usage[key]["count"] += 1
    bot.vt_key_total_requests[key] += 1
    bot.vt_key_index = (bot.vt_key_index + 1) % len(VT_API_KEYS)
    return key

def obtener_siguiente_se_key():
    if not SE_API_KEYS_PAIRS:
        return None
    pair = SE_API_KEYS_PAIRS[bot.se_key_index]
    bot.se_key_index = (bot.se_key_index + 1) % len(SE_API_KEYS_PAIRS)
    return pair

def registrar_uso_se(api_key):
    ahora = time.time()
    hoy = time.strftime("%Y-%m-%d", time.gmtime())
    if api_key not in bot.se_key_usage:
        bot.se_key_usage[api_key] = []
    if api_key not in bot.se_key_total_requests:
        bot.se_key_total_requests[api_key] = 0
    if api_key not in bot.se_key_daily_usage:
        bot.se_key_daily_usage[api_key] = {"count": 0, "date": hoy}
    bot.se_key_usage[api_key] = [t for t in bot.se_key_usage[api_key] if ahora - t <= 60]
    bot.se_key_usage[api_key].append(ahora)
    if bot.se_key_daily_usage[api_key]["date"] != hoy:
        bot.se_key_daily_usage[api_key] = {"count": 4, "date": hoy}
    else:
        bot.se_key_daily_usage[api_key]["count"] += 4
    bot.se_key_total_requests[api_key] += 4
    asyncio.create_task(guardar_datos())

# ========== BASE DE DATOS ASÍNCRONA ==========
async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS analisis (clave TEXT PRIMARY KEY, tipo TEXT, resultado TEXT, embed_json TEXT, timestamp REAL, expira REAL)''')
        await db.execute('CREATE INDEX IF NOT EXISTS idx_expira ON analisis(expira)')
        await db.commit()

async def guardar_analisis_db(clave, tipo_analisis, resultado, embed):
    async with aiosqlite.connect(DB_FILE) as db:
        now = time.time()
        expira = now + EXPIRACION.get(tipo_analisis, 7*24*3600)
        embed_dict = embed.to_dict() if embed else None
        embed_json = json.dumps(embed_dict) if embed_dict else None
        await db.execute('''INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira) VALUES (?, ?, ?, ?, ?, ?)''',
                        (clave, tipo_analisis, resultado, embed_json, now, expira))
        await db.commit()

async def obtener_analisis_db(clave):
    async with aiosqlite.connect(DB_FILE) as db:
        now = time.time()
        async with db.execute('SELECT resultado, embed_json, expira FROM analisis WHERE clave = ?', (clave,)) as cursor:
            row = await cursor.fetchone()
    if row:
        resultado, embed_json, expira = row
        if now < expira:
            embed = None
            if embed_json:
                try:
                    embed_dict = json.loads(embed_json)
                    embed = discord.Embed.from_dict(embed_dict)
                except:
                    pass
            return resultado, embed
    return None, None

async def limpiar_db_expirados():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('DELETE FROM analisis WHERE expira < ?', (time.time(),))
        await db.commit()

async def obtener_hash_desde_metadatos(clave_metadatos):
    async with aiosqlite.connect(DB_FILE) as db:
        now = time.time()
        async with db.execute('SELECT resultado, expira FROM analisis WHERE clave = ?', (clave_metadatos,)) as cursor:
            row = await cursor.fetchone()
    if row:
        resultado, expira = row
        if now < expira:
            try:
                data = json.loads(resultado)
                return data.get("hash")
            except:
                pass
    return None

async def guardar_metadatos_hash(clave_metadatos, file_hash):
    data = json.dumps({"hash": file_hash})
    async with aiosqlite.connect(DB_FILE) as db:
        now = time.time()
        expira = now + EXPIRACION.get("file", 30*24*3600)
        await db.execute('''INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira) VALUES (?, ?, ?, ?, ?, ?)''',
                        (clave_metadatos, "metadata", data, None, now, expira))
        await db.commit()

# ========== JSON SINCRÓNICO (datos pequeños) ==========
guilds_data = {}

def cargar_datos():
    global guilds_data
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            api_usage = data.get("__api_usage__", {})
            guilds_data = {}
            for gid, val in data.items():
                if gid == "__global__":
                    guilds_data["__global__"] = val
                elif gid == "__api_usage__":
                    continue
                else:
                    guilds_data[int(gid)] = val
            bot.vt_key_total_requests = api_usage.get("total_requests", {})
            bot.vt_key_daily_usage = api_usage.get("daily_usage", {})
            if not hasattr(bot, 'vt_key_usage') or not bot.vt_key_usage:
                bot.vt_key_usage = {}
            se_data = api_usage.get("sightengine", {})
            bot.se_key_total_requests = se_data.get("total_requests", {})
            bot.se_key_daily_usage = se_data.get("daily_usage", {})
            if not hasattr(bot, 'se_key_usage') or not bot.se_key_usage:
                bot.se_key_usage = {}
        except Exception as e:
            print(f"Error al cargar datos: {e}")
            guilds_data = {}

async def guardar_datos():
    guilds_data["__api_usage__"] = {
        "total_requests": bot.vt_key_total_requests,
        "daily_usage": bot.vt_key_daily_usage,
        "sightengine": {
            "total_requests": bot.se_key_total_requests,
            "daily_usage": bot.se_key_daily_usage
        }
    }
    data_to_save = {str(gid): val for gid, val in guilds_data.items()}
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=4)
    except Exception as e:
        print(f"Error al guardar datos: {e}")

def obtener_config_guild(guild_id):
    if guild_id not in guilds_data:
        guilds_data[guild_id] = {
            "silent_mode": False,
            "strict_mode": False,
            "log_channel_id": None,
            "whitelist": ["youtube.com", "youtu.be", "google.com", "wikipedia.org", "github.com", "stackoverflow.com", "reddit.com", "twitter.com", "x.com", "twitch.tv", "spotify.com", "microsoft.com", "apple.com", "amazon.com", "discord.com"],
            "stats": {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0},
            "infracciones": {},
            "infracciones_registradas": {}
        }
        asyncio.create_task(guardar_datos())
    return guilds_data[guild_id]

def obtener_stats_globales():
    if "__global__" not in guilds_data:
        guilds_data["__global__"] = {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0}
        asyncio.create_task(guardar_datos())
    return guilds_data["__global__"]

def update_stats_global(tipo):
    stats = obtener_stats_globales()
    stats["total_analisis"] += 1
    if tipo == "seguro": stats["seguros"] += 1
    elif tipo == "malicioso": stats["maliciosos"] += 1
    else: stats["errores"] += 1
    asyncio.create_task(guardar_datos())

def update_stats_guild(guild_id, tipo):
    config = obtener_config_guild(guild_id)
    stats = config["stats"]
    stats["total_analisis"] += 1
    if tipo == "seguro": stats["seguros"] += 1
    elif tipo == "malicioso": stats["maliciosos"] += 1
    else: stats["errores"] += 1
    update_stats_global(tipo)
    asyncio.create_task(guardar_datos())

def registrar_infraccion(guild_id, user_id, elemento_id):
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
    asyncio.create_task(guardar_datos())
    return config["infracciones"][uid]

# Cache en memoria (mismo esquema)
cache_mem = {}
def get_from_cache_mem(key):
    if key in cache_mem:
        tipo, embed, timestamp = cache_mem[key]
        if time.time() - timestamp < CACHE_DURATION:
            return tipo, embed
        else:
            del cache_mem[key]
    return None, None

def set_cache_mem(key, tipo, embed):
    cache_mem[key] = (tipo, embed, time.time())

# ========== FUNCIONES AUXILIARES ==========
def es_imagen(archivo: discord.Attachment) -> bool:
    extensiones_imagen = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic', '.heif']
    if any(archivo.filename.lower().endswith(ext) for ext in extensiones_imagen):
        return True
    if archivo.content_type and archivo.content_type.startswith('image/'):
        return True
    return False

def url_es_imagen(url: str) -> bool:
    ruta = url.split('?')[0]
    extensiones_imagen = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic', '.heif']
    return any(ruta.lower().endswith(ext) for ext in extensiones_imagen)

def obtener_top_antivirus(results):
    detectados = []
    for antivirus in ANTIVIRUS_CONOCIDOS:
        for key, value in results.items():
            if antivirus.lower() in key.lower() and value.get("category") == "malicious":
                detectados.append(key)
                break
        if len(detectados) >= 3:
            break
    return detectados

def barra_porcentaje(porcentaje, longitud=10):
    lleno = int(round(longitud * (porcentaje / 100)))
    vacio = longitud - lleno
    return "█" * lleno + "░" * vacio

# ========== VISTA DE BOTONES PARA LOGS ==========
class LogActionView(discord.ui.View):
    def __init__(self, bot, guild_id, user_id, elemento_id=None):
        super().__init__(timeout=None)
        self.bot = bot
        self.guild_id = guild_id
        self.user_id = user_id
        self.elemento_id = elemento_id
        if not elemento_id:
            self.remove_item(self.ignorar_btn)

    @discord.ui.button(label="Banear usuario", style=discord.ButtonStyle.danger, emoji=EMOJI_BAN)
    async def banear_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.ban_members:
            await interaction.response.send_message("No tienes permisos para banear.", ephemeral=True)
            return
        guild = interaction.guild
        user = guild.get_member(self.user_id)
        if user is None:
            await interaction.response.send_message("El usuario ya no está en el servidor.", ephemeral=True)
            return
        try:
            await guild.ban(user, reason="Amenaza detectada por Threat (acción desde log)")
            await interaction.response.send_message(f"{user.mention} ha sido baneado.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("No tengo permisos para banear a ese usuario.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Error inesperado: {e}", ephemeral=True)
        else:
            for child in self.children:
                child.disabled = True
            await interaction.message.edit(view=self)

    @discord.ui.button(label="Expulsar usuario", style=discord.ButtonStyle.danger, emoji=EMOJI_KICK)
    async def kick_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.kick_members:
            await interaction.response.send_message("No tienes permisos para expulsar.", ephemeral=True)
            return
        guild = interaction.guild
        user = guild.get_member(self.user_id)
        if user is None:
            await interaction.response.send_message("El usuario ya no está en el servidor.", ephemeral=True)
            return
        try:
            await guild.kick(user, reason="Amenaza detectada por Threat (acción desde log)")
            await interaction.response.send_message(f"{user.mention} ha sido expulsado.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("No tengo permisos para expulsar a ese usuario.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Error inesperado: {e}", ephemeral=True)
        else:
            for child in self.children:
                child.disabled = True
            await interaction.message.edit(view=self)

    @discord.ui.button(label="Ignorar (quitar infracción)", style=discord.ButtonStyle.secondary, emoji=EMOJI_CLEAN)
    async def ignorar_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("Solo administradores pueden ignorar infracciones.", ephemeral=True)
            return
        config = self.bot.obtener_config_guild(self.guild_id)
        uid = str(self.user_id)
        if self.elemento_id and uid in config.get("infracciones_registradas", {}):
            registradas = config["infracciones_registradas"][uid]
            if self.elemento_id in registradas:
                registradas.remove(self.elemento_id)
                if uid in config["infracciones"]:
                    config["infracciones"][uid] = max(0, config["infracciones"].get(uid, 1) - 1)
                asyncio.create_task(self.bot.guardar_datos())
                await interaction.response.send_message("Infracción eliminada.", ephemeral=True)
            else:
                await interaction.response.send_message("Esa infracción ya no existe.", ephemeral=True)
        else:
            await interaction.response.send_message("No se pudo identificar la infracción.", ephemeral=True)
        for child in self.children:
            child.disabled = True
        await interaction.message.edit(view=self)

# ========== ENVIAR LOG ==========
async def enviar_log_guild(guild_id, tipo, valor, detalles, usuario, url_vt=None, elemento_id=None):
    config = obtener_config_guild(guild_id)
    log_channel_id = config["log_channel_id"]
    if log_channel_id is None:
        return
    channel = bot.get_channel(log_channel_id)
    if channel is None:
        return
    embed = discord.Embed(
        title=f"{EMOJI_WARNING} Amenaza Detectada",
        description=f"**{tipo}** analizado resultó **malicioso**",
        color=discord.Color.red()
    )
    embed.add_field(name=f"{EMOJI_FINGERPRINT} Valor", value=f"`{valor}`", inline=False)
    embed.add_field(name=f"{EMOJI_GUARDIAN} Usuario", value=usuario.mention, inline=True)
    embed.add_field(name=f"{EMOJI_SHIELD} Detalles", value=detalles, inline=True)
    if url_vt:
        embed.add_field(name=f"{EMOJI_LINK} VirusTotal", value=f"[Ver informe]({url_vt})", inline=False)
    embed.set_footer(text=f"ID: {usuario.id} • {time.strftime('%Y-%m-%d %H:%M:%S')}")
    view = LogActionView(bot, guild_id, usuario.id, elemento_id=elemento_id)
    await channel.send(embed=embed, view=view)

# ========== UTILIDADES ==========
async def expandir_url(url):
    try:
        for _ in range(5):
            async with bot.session.head(url, allow_redirects=False) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location')
                    if location:
                        url = urllib.parse.urljoin(url, location)
                    else:
                        break
                else:
                    break
    except Exception as e:
        print(f"Error expandiendo URL {url}: {e}")
    return url

def tiene_doble_extension(filename):
    partes = filename.rsplit('.', 2)
    return len(partes) == 3 and partes[1].lower() in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'pdf', 'doc', 'xls']

# ========== ANÁLISIS VT ==========
async def analizar_url(url, guild_id=None, mensaje_original=None, guardar_cache=True):
    key = obtener_siguiente_key()
    if not key:
        embed = discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red())
        return "error", embed, 0
    headers = {"x-apikey": key}
    try:
        async with bot.session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}) as resp:
            if resp.status == 200:
                data = await resp.json()
                scan_id = data["data"]["id"]
                # Reintentos con verificación de estado
                for _ in range(3):
                    await asyncio.sleep(10)
                    async with bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers) as resp2:
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            status = analysis["data"]["attributes"]["status"]
                            if status == "completed":
                                stats_data = analysis["data"]["attributes"]["stats"]
                                mal = stats_data["malicious"]
                                encoded_url = urllib.parse.quote_plus(url)
                                vt_link = f"https://www.virustotal.com/gui/home/url?url={encoded_url}"
                                if mal > 0:
                                    if guild_id: update_stats_guild(guild_id, "malicioso")
                                    if mensaje_original and guild_id:
                                        registrar_infraccion(guild_id, mensaje_original.author.id, f"url:{url}")
                                    embed = discord.Embed(
                                        title=f"{EMOJI_WARNING} URL Maliciosa Detectada",
                                        description=f"Se encontraron **{mal}** detecciones",
                                        color=discord.Color.orange()
                                    )
                                    embed.add_field(name="URL", value=f"`{url}`", inline=False)
                                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                                    if mensaje_original and guild_id:
                                        await enviar_log_guild(guild_id, "URL", url, f"{mal} detecciones", mensaje_original.author, vt_link, elemento_id=f"url:{url}")
                                        config = obtener_config_guild(guild_id)
                                        if config["strict_mode"]:
                                            try: await mensaje_original.delete()
                                            except: pass
                                    if guardar_cache:
                                        clave = f"url:{url}"
                                        await guardar_analisis_db(clave, "url", "malicioso", embed)
                                        set_cache_mem(clave, "malicioso", embed)
                                    return "malicioso", embed, mal
                                else:
                                    if guild_id: update_stats_guild(guild_id, "seguro")
                                    embed = discord.Embed(
                                        title=f"{EMOJI_CORRECTO} URL Segura",
                                        description="No se detectaron amenazas",
                                        color=discord.Color.green()
                                    )
                                    embed.add_field(name="URL", value=f"`{url}`", inline=False)
                                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                                    if guardar_cache:
                                        clave = f"url:{url}"
                                        await guardar_analisis_db(clave, "url", "seguro", embed)
                                        set_cache_mem(clave, "seguro", embed)
                                    return "seguro", embed, 0
                            elif status == "queued":
                                continue  # reintentar
                # Si salimos del bucle sin éxito
                if guild_id: update_stats_guild(guild_id, "error")
                embed = discord.Embed(title="Error en análisis", description="El análisis no se completó a tiempo.", color=discord.Color.red())
                return "error", embed, 0
            else:
                if guild_id: update_stats_guild(guild_id, "error")
                embed = discord.Embed(title="Error al analizar URL", description="VirusTotal no procesó la solicitud", color=discord.Color.red())
                if guardar_cache:
                    clave = f"url:{url}"
                    await guardar_analisis_db(clave, "url", "error", embed)
                    set_cache_mem(clave, "error", embed)
                return "error", embed, 0
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_url: {e}")
        embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error de conexión", description="No se pudo contactar con VirusTotal", color=discord.Color.red())
        if guardar_cache:
            clave = f"url:{url}"
            await guardar_analisis_db(clave, "url", "error", embed)
            set_cache_mem(clave, "error", embed)
        return "error", embed, 0

async def analizar_hash(hash_valor, guild_id=None, mensaje_original=None, guardar_cache=True):
    key = obtener_siguiente_key()
    if not key:
        embed = discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red())
        return "error", embed, 0
    headers = {"x-apikey": key}
    try:
        async with bot.session.get(f"https://www.virustotal.com/api/v3/files/{hash_valor}", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats_data = data["data"]["attributes"]["last_analysis_stats"]
                mal = stats_data["malicious"]
                results = data["data"]["attributes"]["last_analysis_results"]
                vt_link = f"https://www.virustotal.com/gui/file/{hash_valor}"
                if mal > 0:
                    if guild_id: update_stats_guild(guild_id, "malicioso")
                    if mensaje_original and guild_id:
                        registrar_infraccion(guild_id, mensaje_original.author.id, f"hash:{hash_valor}")
                    top = obtener_top_antivirus(results)
                    top_text = ", ".join(top) if top else "Varios antivirus"
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Hash Malicioso Detectado", description=f"**{mal}** antivirus lo identificaron", color=discord.Color.orange())
                    embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                    embed.add_field(name="Detectado por", value=f"`{top_text}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if mensaje_original and guild_id:
                        await enviar_log_guild(guild_id, "Hash", hash_valor, f"{mal} detecciones (top: {top_text})", mensaje_original.author, vt_link, elemento_id=f"hash:{hash_valor}")
                        if (config := obtener_config_guild(guild_id))["strict_mode"]:
                            try: await mensaje_original.delete()
                            except: pass
                    if guardar_cache:
                        clave = f"hash:{hash_valor}"
                        await guardar_analisis_db(clave, "hash", "malicioso", embed)
                        set_cache_mem(clave, "malicioso", embed)
                    return "malicioso", embed, mal
                else:
                    if guild_id: update_stats_guild(guild_id, "seguro")
                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} Hash Seguro", description="No se encontraron amenazas", color=discord.Color.green())
                    embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        clave = f"hash:{hash_valor}"
                        await guardar_analisis_db(clave, "hash", "seguro", embed)
                        set_cache_mem(clave, "seguro", embed)
                    return "seguro", embed, 0
            else:
                if guild_id: update_stats_guild(guild_id, "error")
                embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Hash no encontrado", description="No existe en VirusTotal", color=discord.Color.red())
                if guardar_cache:
                    clave = f"hash:{hash_valor}"
                    await guardar_analisis_db(clave, "hash", "error", embed)
                    set_cache_mem(clave, "error", embed)
                return "error", embed, 0
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_hash: {e}")
        embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error", description="No se pudo consultar el hash", color=discord.Color.red())
        if guardar_cache:
            clave = f"hash:{hash_valor}"
            await guardar_analisis_db(clave, "hash", "error", embed)
            set_cache_mem(clave, "error", embed)
        return "error", embed, 0

async def analizar_ip(ip, guild_id=None, mensaje_original=None, guardar_cache=True):
    key = obtener_siguiente_key()
    if not key:
        embed = discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red())
        return "error", embed, 0
    headers = {"x-apikey": key}
    try:
        async with bot.session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                mal = stats["malicious"]
                vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
                if mal > 0:
                    if guild_id: update_stats_guild(guild_id, "malicioso")
                    if mensaje_original and guild_id:
                        registrar_infraccion(guild_id, mensaje_original.author.id, f"ip:{ip}")
                    embed = discord.Embed(title=f"{EMOJI_WARNING} IP Maliciosa Detectada", description=f"**{mal}** fuentes reportan actividad sospechosa", color=discord.Color.orange())
                    embed.add_field(name="IP", value=f"`{ip}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if mensaje_original and guild_id:
                        await enviar_log_guild(guild_id, "IP", ip, f"{mal} fuentes reportan", mensaje_original.author, vt_link, elemento_id=f"ip:{ip}")
                        if (config := obtener_config_guild(guild_id))["strict_mode"]:
                            try: await mensaje_original.delete()
                            except: pass
                    if guardar_cache:
                        clave = f"ip:{ip}"
                        await guardar_analisis_db(clave, "ip", "malicioso", embed)
                        set_cache_mem(clave, "malicioso", embed)
                    return "malicioso", embed, mal
                else:
                    if guild_id: update_stats_guild(guild_id, "seguro")
                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} IP Segura", description="No se encontraron reportes", color=discord.Color.green())
                    embed.add_field(name="IP", value=f"`{ip}`", inline=False)
                    embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                    if guardar_cache:
                        clave = f"ip:{ip}"
                        await guardar_analisis_db(clave, "ip", "seguro", embed)
                        set_cache_mem(clave, "seguro", embed)
                    return "seguro", embed, 0
            else:
                if guild_id: update_stats_guild(guild_id, "error")
                embed = discord.Embed(title=f"{EMOJI_INCORRECTO} IP no encontrada", description="No se pudo analizar la IP", color=discord.Color.red())
                return "error", embed, 0
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_ip: {e}")
        embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error", description="No se pudo contactar con VirusTotal", color=discord.Color.red())
        return "error", embed, 0

async def analizar_archivo(archivo, file_bytes=None, file_hash=None, guild_id=None, mensaje_original=None, guardar_cache=True):
    if file_bytes is None:
        try:
            async with bot.session.get(archivo.url, headers={"Authorization": f"Bot {TOKEN}"}) as resp:
                if resp.status != 200:
                    if guild_id: update_stats_guild(guild_id, "error")
                    embed = discord.Embed(title="Error al descargar archivo", description="No se pudo obtener el archivo", color=discord.Color.red())
                    return "error", embed, 0
                file_bytes = await resp.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
        except Exception as e:
            if guild_id: update_stats_guild(guild_id, "error")
            embed = discord.Embed(title="Error", description="Error al descargar el archivo", color=discord.Color.red())
            return "error", embed, 0

    if archivo.size > MAX_FILE_SIZE:
        if guild_id: update_stats_guild(guild_id, "error")
        embed = discord.Embed(title="Archivo demasiado grande", description=f"{EMOJI_FILE} `{archivo.filename}` excede 32 MB", color=discord.Color.red())
        return "error", embed, 0

    key = obtener_siguiente_key()
    if not key:
        embed = discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red())
        return "error", embed, 0
    headers = {"x-apikey": key}
    try:
        data = aiohttp.FormData()
        data.add_field('file', file_bytes, filename=archivo.filename)
        async with bot.session.post("https://www.virustotal.com/api/v3/files", headers=headers, data=data) as resp:
            if resp.status == 200:
                result_json = await resp.json()
                scan_id = result_json["data"]["id"]
                for _ in range(3):
                    await asyncio.sleep(15)
                    async with bot.session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers) as resp2:
                        if resp2.status == 200:
                            analysis = await resp2.json()
                            if analysis["data"]["attributes"]["status"] == "completed":
                                stats = analysis["data"]["attributes"]["stats"]
                                mal = stats["malicious"]
                                if mal > 0:
                                    if guild_id: update_stats_guild(guild_id, "malicioso")
                                    if mensaje_original and guild_id:
                                        registrar_infraccion(guild_id, mensaje_original.author.id, f"filehash:{file_hash}")
                                    embed = discord.Embed(
                                        title=f"{EMOJI_WARNING} Archivo Malicioso Detectado",
                                        description=f"**{mal}** antivirus detectaron {EMOJI_FILE} `{archivo.filename}`",
                                        color=discord.Color.orange()
                                    )
                                    if mensaje_original and guild_id:
                                        await enviar_log_guild(guild_id, "Archivo", archivo.filename, f"{mal} detecciones", mensaje_original.author, elemento_id=f"filehash:{file_hash}")
                                        if (config := obtener_config_guild(guild_id))["strict_mode"]:
                                            try: await mensaje_original.delete()
                                            except: pass
                                    if guardar_cache:
                                        clave = f"filehash:{file_hash}"
                                        await guardar_analisis_db(clave, "file", "malicioso", embed)
                                        set_cache_mem(clave, "malicioso", embed)
                                        clave_meta = f"file:{archivo.filename}:{archivo.size}"
                                        await guardar_metadatos_hash(clave_meta, file_hash)
                                    return "malicioso", embed, mal
                                else:
                                    if guild_id: update_stats_guild(guild_id, "seguro")
                                    embed = discord.Embed(
                                        title=f"{EMOJI_CORRECTO} Archivo Seguro",
                                        description=f"{EMOJI_FILE} `{archivo.filename}` parece limpio (0 detecciones)",
                                        color=discord.Color.green()
                                    )
                                    if guardar_cache:
                                        clave = f"filehash:{file_hash}"
                                        await guardar_analisis_db(clave, "file", "seguro", embed)
                                        set_cache_mem(clave, "seguro", embed)
                                        clave_meta = f"file:{archivo.filename}:{archivo.size}"
                                        await guardar_metadatos_hash(clave_meta, file_hash)
                                    return "seguro", embed, 0
                            elif analysis["data"]["attributes"]["status"] == "queued":
                                continue
                if guild_id: update_stats_guild(guild_id, "error")
                embed = discord.Embed(title="Error en análisis", description="El análisis no se completó a tiempo.", color=discord.Color.red())
                return "error", embed, 0
            else:
                if guild_id: update_stats_guild(guild_id, "error")
                embed = discord.Embed(title="Error al subir archivo", description="VirusTotal rechazó el archivo", color=discord.Color.red())
                return "error", embed, 0
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_archivo: {e}")
        embed = discord.Embed(title="Error", description="No se pudo analizar el archivo", color=discord.Color.red())
        return "error", embed, 0

# ========== ANÁLISIS NSFW MULTIMODELO ==========
async def analizar_imagen_multimodelo(image_content_hash, image_bytes):
    clave = f"nsfw:{image_content_hash}"
    tipo, details_json = get_from_cache_mem(clave)
    if details_json:
        try:
            details = json.loads(details_json)
            return details["is_nsfw"], details["max_confidence"], details["models"], True
        except:
            pass
    resultado_db, _ = await obtener_analisis_db(clave)
    if _:
        try:
            details = json.loads(resultado_db)
            set_cache_mem(clave, resultado_db, None)
            return details["is_nsfw"], details["max_confidence"], details["models"], True
        except:
            pass
    if not SE_API_KEYS_PAIRS:
        print("⚠️ Sightengine no configurado correctamente.")
        return False, 0.0, {}, False

    pair = obtener_siguiente_se_key()
    if not pair:
        print("⚠️ No hay pares de Sightengine disponibles.")
        return False, 0.0, {}, False
    api_user, api_key = pair

    try:
        data = aiohttp.FormData()
        data.add_field('media', image_bytes, filename='image.jpg')
        data.add_field('models', SIGHTENGINE_MODELS)
        data.add_field('api_user', api_user)
        data.add_field('api_secret', api_key)
        async with bot.session.post(SIGHTENGINE_API_URL, data=data) as resp:
            if resp.status == 200:
                registrar_uso_se(api_key)
                result = await resp.json()
                models = {}
                for model_name in SIGHTENGINE_MODELS.split(','):
                    model_data = result.get(model_name, {})
                    confidence = model_data.get('raw', 0.0)
                    models[model_name] = confidence
                is_nsfw = models.get('nudity', 0.0) >= 0.5 or models.get('weapon', 0.0) >= 0.5 or models.get('offensive', 0.0) >= 0.7
                max_confidence = max(models.values()) if models else 0.0
                cache_details = {"is_nsfw": is_nsfw, "max_confidence": max_confidence, "models": models}
                cache_json = json.dumps(cache_details)
                dummy_embed = discord.Embed(title="NSFW Cache")
                await guardar_analisis_db(clave, "nsfw", cache_json, dummy_embed)
                set_cache_mem(clave, cache_json, None)
                await guardar_datos()
                return is_nsfw, max_confidence, models, False
            else:
                if resp.status == 400:
                    error_details = {"is_nsfw": False, "max_confidence": 0.0, "models": {}, "error": "sightengine_400"}
                    error_json = json.dumps(error_details)
                    dummy_embed = discord.Embed(title="NSFW Error Cache")
                    await guardar_analisis_db(clave, "nsfw", error_json, dummy_embed)
                    set_cache_mem(clave, error_json, None)
                    return False, 0.0, {"error": "too_large"}, False
    except Exception as e:
        print(f"🔥 Excepción en análisis multimodelo: {e}")
    return False, 0.0, {}, False

# ========== FUNCIÓN UNIFICADA DE ANÁLISIS ==========
async def procesar_analisis(message, silent_mode, strict_mode, log_channel_id, whitelist):
    """Analiza URLs y adjuntos en un mensaje (nuevo o editado)."""
    guild_id = message.guild.id
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, message.content)

    if urls:
        todas_urls = []
        for url in urls:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            dominio = parsed.netloc.lower()
            if dominio.startswith("www."):
                dominio = dominio[4:]
            if not dominio_en_whitelist(dominio, whitelist):
                todas_urls.append(url)
            else:
                await safe_add_reaction(message, EMOJI_WHITELIST)

        if not todas_urls:
            if not silent_mode:
                await message.reply(f"{EMOJI_WHITELIST} **Dominio(s) en whitelist.** No se requiere análisis.", mention_author=False)
            return

        # Una sola URL
        if len(todas_urls) == 1:
            url = todas_urls[0]
            if url_es_imagen(url):
                await safe_add_reaction(message, EMOJI_LOADING)
                try:
                    async with bot.session.get(url, headers={"Authorization": f"Bot {TOKEN}"}) as resp:
                        if resp.status != 200:
                            await safe_remove_loading(message)
                            return
                        content_length = resp.headers.get('Content-Length')
                        if content_length and int(content_length) > MAX_IMAGE_SIZE:
                            await safe_remove_loading(message)
                            await safe_add_reaction(message, EMOJI_INCORRECTO)
                            if not silent_mode:
                                embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                                await message.channel.send(embed=embed, reference=message)
                            return
                        img_data = await resp.read()
                        if len(img_data) > MAX_IMAGE_SIZE:
                            await safe_remove_loading(message)
                            await safe_add_reaction(message, EMOJI_INCORRECTO)
                            if not silent_mode:
                                embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                                await message.channel.send(embed=embed, reference=message)
                            return
                        content_hash = hashlib.sha256(img_data).hexdigest()
                        is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                finally:
                    await safe_remove_loading(message)

                if models.get("error") == "too_large":
                    await safe_add_reaction(message, EMOJI_WARNING)
                    if not silent_mode:
                        embed = discord.Embed(title=f"{EMOJI_WARNING} Imagen no analizada", description="Supera el límite de Sightengine", color=discord.Color.orange())
                        await message.channel.send(embed=embed, reference=message)
                    return

                if is_nsfw:
                    if guild_id:
                        registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                    await safe_add_reaction(message, EMOJI_WARNING)
                    detectados = []
                    if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                    if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                    if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                    if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                    detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Contenido Inapropiado Detectado", description=f"{detalles_str}", color=discord.Color.orange())
                    embed.add_field(name="Resultados", value=f"{EMOJI_WARNING} Imagen NSFW\n{detalles_str}", inline=False)
                    await message.channel.send(embed=embed, reference=message)
                    if log_channel_id:
                        await enviar_log_guild(guild_id, "Imagen NSFW", url, detalles_str, message.author, elemento_id=f"nsfw:{content_hash}")
                    if strict_mode:
                        try: await message.delete()
                        except: pass
                else:
                    await safe_add_reaction(message, EMOJI_CORRECTO)
                    if not silent_mode:
                        embed = discord.Embed(title=f"{EMOJI_CORRECTO} Imagen Segura", description="No se detectó contenido inapropiado.", color=discord.Color.green())
                        embed.add_field(name="Resultados", value=f"{EMOJI_CORRECTO} Imagen segura", inline=False)
                        await message.channel.send(embed=embed, reference=message)
                return
            else:
                # URL no imagen
                url_original = url
                url = await expandir_url(url)
                clave = f"url:{url_original}"
                tipo, embed = get_from_cache_mem(clave)
                if embed is None:
                    tipo, embed = await obtener_analisis_db(clave)
                    if embed is not None:
                        set_cache_mem(clave, tipo, embed)

                if embed is not None:
                    if tipo == "malicioso":
                        registrar_infraccion(guild_id, message.author.id, f"url:{url}")
                        await message.channel.send(embed=embed, reference=message)
                        if log_channel_id:
                            await enviar_log_guild(guild_id, "URL", url, "Amenaza detectada (cache)", message.author, elemento_id=f"url:{url}")
                        if strict_mode:
                            try: await message.delete()
                            except: pass
                        await safe_add_reaction(message, EMOJI_WARNING)
                    elif tipo == "seguro":
                        if not silent_mode:
                            await message.channel.send(embed=embed, reference=message)
                        await safe_add_reaction(message, EMOJI_CORRECTO)
                    else:
                        if not silent_mode:
                            await message.channel.send(embed=embed, reference=message)
                        await safe_add_reaction(message, EMOJI_INCORRECTO)
                    return

                # Anti-spam
                ahora = time.time()
                user_id = message.author.id
                if user_id in bot.user_scan_history and len(bot.user_scan_history[user_id]) >= 30:
                    await safe_add_reaction(message, EMOJI_COOLDOWN)
                    return
                if user_id in bot.antispam_scan and ahora - bot.antispam_scan[user_id] < 10:
                    await safe_add_reaction(message, EMOJI_COOLDOWN)
                    return
                bot.antispam_scan[user_id] = ahora
                bot.user_scan_history.setdefault(user_id, []).append(ahora)

                await safe_add_reaction(message, EMOJI_LOADING)
                try:
                    tipo, embed, _ = await analizar_url(url, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                finally:
                    await safe_remove_loading(message)

                if tipo == "malicioso":
                    await message.channel.send(embed=embed, reference=message)
                    await safe_add_reaction(message, EMOJI_WARNING)
                elif tipo == "seguro":
                    if not silent_mode:
                        await message.channel.send(embed=embed, reference=message)
                    await safe_add_reaction(message, EMOJI_CORRECTO)
                else:
                    if not silent_mode:
                        await message.channel.send(embed=embed, reference=message)
                    await safe_add_reaction(message, EMOJI_INCORRECTO)
                return

        # Múltiples URLs
        await safe_add_reaction(message, EMOJI_LOADING)
        try:
            todas_urls = list(dict.fromkeys(todas_urls))[:5]
            resultados = []
            maliciosas = seguras = errores = 0
            for url in todas_urls:
                url_original = url
                url_exp = await expandir_url(url)
                clave = f"url:{url_original}"
                tipo, embed = get_from_cache_mem(clave)
                if embed is None:
                    tipo, embed = await obtener_analisis_db(clave)
                    if tipo is not None:
                        set_cache_mem(clave, tipo, embed)
                if embed is not None:
                    resultados.append((url_original, tipo, embed))
                    if tipo == "malicioso":
                        maliciosas += 1
                        registrar_infraccion(guild_id, message.author.id, f"url:{url_exp}")
                    elif tipo == "seguro": seguras += 1
                    else: errores += 1
                    continue
                await asyncio.sleep(1)
                tipo, embed, _ = await analizar_url(url_exp, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                resultados.append((url_original, tipo, embed))
                if tipo == "malicioso": maliciosas += 1
                elif tipo == "seguro": seguras += 1
                else: errores += 1

            color = discord.Color.orange() if maliciosas else (discord.Color.red() if errores else discord.Color.green())
            titulo = f"{EMOJI_WARNING} Amenazas detectadas" if maliciosas else (f"{EMOJI_WARNING} Errores en el análisis" if errores else f"{EMOJI_CORRECTO} Todos los enlaces son seguros")
            descripcion = f"Se analizaron **{len(todas_urls)}** enlace(s) en el mensaje de {message.author.mention}:\n" \
                          f"{EMOJI_CORRECTO} Seguros: **{seguras}**\n{EMOJI_WARNING} Maliciosos: **{maliciosas}**\n{EMOJI_INCORRECTO} Errores: **{errores}**"
            embed_resumen = discord.Embed(title=titulo, description=descripcion, color=color)
            valor_campo = ""
            for url_orig, tipo, _ in resultados:
                if tipo == "malicioso": valor_campo += f"{EMOJI_WARNING} `{url_orig}`\n"
                elif tipo == "seguro": valor_campo += f"{EMOJI_CORRECTO} `{url_orig}`\n"
                else: valor_campo += f"{EMOJI_INCORRECTO} `{url_orig}`\n"
            embed_resumen.add_field(name="Resultados", value=valor_campo[:1024], inline=False)
            if maliciosas:
                maliciosas_str = ""
                for url_orig, tipo, _ in resultados:
                    if tipo == "malicioso":
                        vt_link = f"https://www.virustotal.com/gui/home/url?url={urllib.parse.quote_plus(url_orig)}"
                        maliciosas_str += f"• `{url_orig}` {EMOJI_LINK} [Ver informe]({vt_link})\n"
                embed_resumen.add_field(name=f"{EMOJI_WARNING} Enlaces maliciosos", value=maliciosas_str[:1024], inline=False)
            if maliciosas and log_channel_id:
                for url_orig, tipo, _ in resultados:
                    if tipo == "malicioso":
                        await enviar_log_guild(guild_id, "URL (múltiples)", url_orig, "Detectado en análisis múltiple", message.author, elemento_id=f"url:{url_orig}")
            await message.channel.send(embed=embed_resumen, reference=message)
        finally:
            await safe_remove_loading(message)
        if maliciosas: await safe_add_reaction(message, EMOJI_WARNING)
        elif errores: await safe_add_reaction(message, EMOJI_WARNING)
        else: await safe_add_reaction(message, EMOJI_CORRECTO)
        if maliciosas and strict_mode:
            try: await message.delete()
            except: pass
        return

    # ========== ADJUNTOS ==========
    if message.attachments:
        adjuntos = message.attachments[:5]
        imagenes = [a for a in adjuntos if es_imagen(a)]
        otros = [a for a in adjuntos if not es_imagen(a)]

        resultados_img = []   # (filename, tipo, models, content_hash)
        resultados_arch = []  # (filename, tipo, mal, file_hash, wm)

        await safe_add_reaction(message, EMOJI_LOADING)
        try:
            # Imágenes (NSFW)
            for img in imagenes:
                if img.size > MAX_IMAGE_SIZE:
                    resultados_img.append((img.filename, "error", {"error": "too_large"}, ""))
                    continue
                clave_meta = f"nsfw_filename:{img.filename}:{img.size}"
                tipo_meta, embed_meta = get_from_cache_mem(clave_meta)
                content_hash = None
                if embed_meta is not None:
                    try: content_hash = json.loads(tipo_meta).get("hash")
                    except: pass
                if not content_hash:
                    content_hash = await obtener_hash_desde_metadatos(clave_meta)
                if content_hash:
                    is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, b"")
                    if from_cache:
                        resultados_img.append((img.filename, "nsfw" if is_nsfw else "seguro", models, content_hash))
                        continue
                # Descarga
                try:
                    async with bot.session.get(img.url, headers={"Authorization": f"Bot {TOKEN}"}) as resp:
                        if resp.status != 200:
                            resultados_img.append((img.filename, "error", {}, ""))
                            continue
                        img_data = await resp.read()
                        if len(img_data) > MAX_IMAGE_SIZE:
                            resultados_img.append((img.filename, "error", {"error": "too_large"}, ""))
                            continue
                        content_hash = hashlib.sha256(img_data).hexdigest()
                        is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                        if is_nsfw and guild_id:
                            registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                        resultados_img.append((img.filename, "nsfw" if is_nsfw else "seguro", models, content_hash))
                        dummy = discord.Embed(title="NSFW Meta")
                        set_cache_mem(clave_meta, json.dumps({"hash": content_hash}), dummy)
                        await guardar_metadatos_hash(clave_meta, content_hash)
                except:
                    resultados_img.append((img.filename, "error", {}, ""))

            # Archivos (VT)
            for archivo in otros:
                doble_ext = tiene_doble_extension(archivo.filename)
                wm = ""
                if doble_ext:
                    await safe_add_reaction(message, EMOJI_WARNING)
                if archivo.size > MAX_FILE_SIZE:
                    resultados_arch.append((archivo.filename, "error", 0, "", ""))
                    continue
                clave_meta = f"file:{archivo.filename}:{archivo.size}"
                tipo_meta, embed_meta = get_from_cache_mem(clave_meta)
                file_hash = None
                if embed_meta is not None:
                    try: file_hash = json.loads(tipo_meta).get("hash")
                    except: pass
                if not file_hash:
                    file_hash = await obtener_hash_desde_metadatos(clave_meta)
                if file_hash:
                    tipo, embed = get_from_cache_mem(f"filehash:{file_hash}")
                    if embed is None:
                        tipo, embed = await obtener_analisis_db(f"filehash:{file_hash}")
                        if embed is not None:
                            set_cache_mem(f"filehash:{file_hash}", tipo, embed)
                    if embed is not None:
                        if tipo == "malicioso":
                            registrar_infraccion(guild_id, message.author.id, f"filehash:{file_hash}")
                        resultados_arch.append((archivo.filename, tipo, 0, file_hash, wm))
                        continue
                # Descarga
                try:
                    async with bot.session.get(archivo.url, headers={"Authorization": f"Bot {TOKEN}"}) as resp:
                        if resp.status != 200:
                            resultados_arch.append((archivo.filename, "error", 0, "", ""))
                            continue
                        file_data = await resp.read()
                        file_hash = hashlib.sha256(file_data).hexdigest()
                        content_type = resp.headers.get('Content-Type', '')
                        if archivo.filename.endswith('.jpg') and content_type not in ('image/jpeg', 'image/jpg'):
                            wm = f"Extensión .jpg pero tipo real {content_type}"
                        elif archivo.filename.endswith('.png') and content_type != 'image/png':
                            wm = f"Extensión .png pero tipo real {content_type}"
                except:
                    resultados_arch.append((archivo.filename, "error", 0, "", ""))
                    continue
                tipo, embed = get_from_cache_mem(f"filehash:{file_hash}")
                if embed is None:
                    tipo, embed = await obtener_analisis_db(f"filehash:{file_hash}")
                    if embed is not None:
                        set_cache_mem(f"filehash:{file_hash}", tipo, embed)
                if embed is not None:
                    if tipo == "malicioso":
                        registrar_infraccion(guild_id, message.author.id, f"filehash:{file_hash}")
                    resultados_arch.append((archivo.filename, tipo, 0, file_hash, wm))
                else:
                    tipo, embed, mal = await analizar_archivo(archivo, file_bytes=file_data, file_hash=file_hash, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
                    resultados_arch.append((archivo.filename, tipo, mal, file_hash, wm))

        finally:
            await safe_remove_loading(message)

        total = len(resultados_img) + len(resultados_arch)
        if total == 0:
            return
        maliciosos = sum(1 for _, t, _, _ in resultados_img if t == "nsfw") + sum(1 for _, t, _, _, _ in resultados_arch if t == "malicioso")
        nsfw = sum(1 for _, t, _, _ in resultados_img if t == "nsfw")
        seguros = sum(1 for _, t, _, _ in resultados_img if t == "seguro") + sum(1 for _, t, _, _, _ in resultados_arch if t == "seguro")
        errores = total - maliciosos - nsfw - seguros
        has_doble_ext = any(tiene_doble_extension(a.filename) for a in adjuntos)

        if maliciosos or nsfw:
            color = discord.Color.orange()
            titulo = f"{EMOJI_WARNING} ¡Amenazas detectadas en archivos adjuntos!"
        elif errores:
            color = discord.Color.red()
            titulo = f"{EMOJI_WARNING} Análisis completado con errores"
        else:
            color = discord.Color.green()
            titulo = f"{EMOJI_CORRECTO} Todos los archivos son seguros"

        descripcion = f"**{total}** archivo(s) analizado(s) en el mensaje de {message.author.mention}:\n"
        descripcion += f"{EMOJI_CORRECTO} Seguros: **{seguros}**\n"
        descripcion += f"{EMOJI_WARNING} Maliciosos/NSFW: **{maliciosos}**\n"
        descripcion += f"{EMOJI_INCORRECTO} Errores: **{errores}**"
        embed_resumen = discord.Embed(title=titulo, description=descripcion, color=color)

        campo = ""
        for filename, tipo, models, _ in resultados_img:
            if tipo == "nsfw":
                detalles = []
                if models.get('nudity', 0.0) >= 0.5: detalles.append(f"Desnudez {models['nudity']*100:.0f}%")
                if models.get('weapon', 0.0) >= 0.5: detalles.append(f"Armas {models['weapon']*100:.0f}%")
                if models.get('offensive', 0.0) >= 0.7: detalles.append(f"Ofensivo {models['offensive']*100:.0f}%")
                if models.get('alcohol', 0.0) >= 0.7: detalles.append(f"Alcohol {models['alcohol']*100:.0f}%")
                detalle_str = ", ".join(detalles) if detalles else "Contenido inapropiado"
                campo += f"{EMOJI_WARNING} `{filename}` (NSFW: {detalle_str})\n"
            elif tipo == "seguro":
                campo += f"{EMOJI_CORRECTO} `{filename}` (imagen)\n"
            else:
                campo += f"{EMOJI_INCORRECTO} `{filename}` (error)\n"

        for filename, tipo, mal, file_hash, wm in resultados_arch:
            if tipo == "malicioso":
                campo += f"{EMOJI_WARNING} `{filename}` ({mal} detecciones)\n"
            elif tipo == "seguro":
                campo += f"{EMOJI_CORRECTO} `{filename}`\n"
            else:
                campo += f"{EMOJI_INCORRECTO} `{filename}`\n"

        embed_resumen.add_field(name="Resultados", value=campo[:1024], inline=False)

        # Logs
        if log_channel_id:
            for filename, tipo, models, content_hash in resultados_img:
                if tipo == "nsfw" and content_hash:
                    await enviar_log_guild(guild_id, "Imagen NSFW (múltiples)", filename, "Detectado en análisis múltiple", message.author, elemento_id=f"nsfw:{content_hash}")
            for filename, tipo, mal, file_hash, wm in resultados_arch:
                if tipo == "malicioso" and file_hash:
                    await enviar_log_guild(guild_id, "Archivo (múltiples)", filename, f"{mal} detecciones", message.author, elemento_id=f"filehash:{file_hash}")

        if maliciosos or nsfw or not silent_mode:
            try: await message.channel.send(embed=embed_resumen, reference=message)
            except discord.HTTPException: await message.channel.send(embed=embed_resumen)

        if maliciosos: await safe_add_reaction(message, EMOJI_WARNING)
        elif errores: await safe_add_reaction(message, EMOJI_WARNING)
        else: await safe_add_reaction(message, EMOJI_CORRECTO)

        if (maliciosos or has_doble_ext) and strict_mode:
            try: await message.delete()
            except: pass

# ========== EVENTOS ==========
@bot.event
async def on_message(message):
    if message.author == bot.user or not message.guild:
        return
    config = obtener_config_guild(message.guild.id)
    await procesar_analisis(message, config["silent_mode"], config["strict_mode"], config["log_channel_id"], config.get("whitelist", []))
    await bot.process_commands(message)

@bot.event
async def on_message_edit(before, after):
    if before.author == bot.user or not after.guild:
        return
    # Solo si cambió el contenido o se añadieron adjuntos
    if before.content == after.content and len(before.attachments) == len(after.attachments):
        return
    config = obtener_config_guild(after.guild.id)
    await procesar_analisis(after, config["silent_mode"], config["strict_mode"], config["log_channel_id"], config.get("whitelist", []))

@bot.event
async def on_ready():
    print(f"Bot conectado como {bot.user}")
    bot.session = aiohttp.ClientSession()
    await init_db()
    cargar_datos()
    asyncio.create_task(limpiar_db_expirados())
    await bot.change_presence(status=discord.Status.dnd, activity=None)
    await load_cogs()
    await bot.tree.sync()
    print("Comandos slash sincronizados correctamente")
    print("Bot Ready")

async def load_cogs():
    for archivo in os.listdir("./cogs"):
        if archivo.endswith(".py"):
            await bot.load_extension(f"cogs.{archivo[:-3]}")
            print(f"Cargado cog: {archivo}")

# ========== EXPORTACIONES A BOT ==========
bot.MAX_FILE_SIZE = MAX_FILE_SIZE
bot.CACHE_DURATION = CACHE_DURATION
bot.DATA_FILE = DATA_FILE
bot.DB_FILE = DB_FILE
bot.TOKEN = TOKEN
bot.guilds_data = guilds_data
bot.cache_mem = cache_mem
bot.obtener_siguiente_key = obtener_siguiente_key
bot.obtener_siguiente_se_key = obtener_siguiente_se_key
bot.registrar_uso_se = registrar_uso_se
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
bot.EMOJI_REPLY = EMOJI_REPLY
bot.EMOJI_KEY = EMOJI_KEY
bot.EMOJI_KICK = EMOJI_KICK
bot.EMOJI_BAN = EMOJI_BAN
bot.EMOJI_CLEAN = EMOJI_CLEAN
bot.analizar_url = analizar_url
bot.get_from_cache_mem = get_from_cache_mem
bot.set_cache_mem = set_cache_mem
bot.analizar_hash = analizar_hash
bot.analizar_ip = analizar_ip
bot.analizar_archivo = analizar_archivo
bot.analizar_imagen_nsfw = analizar_imagen_multimodelo
bot.obtener_analisis_db = obtener_analisis_db
bot.guardar_analisis_db = guardar_analisis_db
bot.guardar_datos = guardar_datos
bot.enviar_log_guild = enviar_log_guild
bot.obtener_config_guild = obtener_config_guild
bot.update_stats_guild = update_stats_guild
bot.obtener_stats_globales = obtener_stats_globales
bot.barra_porcentaje = barra_porcentaje
bot.expandir_url = expandir_url
bot.tiene_doble_extension = tiene_doble_extension
bot.dominio_en_whitelist = dominio_en_whitelist

if __name__ == "__main__":
    if not TOKEN or not VT_API_KEYS or not SE_API_KEYS_PAIRS:
        print("ERROR: Debes configurar DISCORD_TOKEN, al menos una VT_API_KEY y al menos un par válido de Sightengine en el .env")
    else:
        bot.run(TOKEN)