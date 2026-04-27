# Prueba denuevo.

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
import sqlite3
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

MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB
MAX_IMAGE_SIZE = 2 * 1024 * 1024  # 2 MB
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

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="-", intents=intents, allowed_mentions=discord.AllowedMentions.none())

# ========== FUNCIONES GLOBALES ==========
async def safe_remove_loading(msg):
    """Elimina de forma segura la reacción de carga, ignorando si el mensaje ya no existe."""
    try:
        await msg.remove_reaction(EMOJI_LOADING, bot.user)
    except discord.NotFound:
        pass

# ========== SEGUIMIENTO DE USO DE APIs ==========
# VirusTotal
bot.antispam_scan = {}
bot.user_scan_history = {}
bot.vt_key_index = 0
bot.vt_key_usage = {}
bot.vt_key_total_requests = {}
bot.vt_key_daily_usage = {}
bot.vt_key_count = len(VT_API_KEYS)

# Sightengine
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
    """Devuelve (api_user, api_key) del siguiente par, sin registrar uso."""
    if not SE_API_KEYS_PAIRS:
        return None
    pair = SE_API_KEYS_PAIRS[bot.se_key_index]
    bot.se_key_index = (bot.se_key_index + 1) % len(SE_API_KEYS_PAIRS)
    return pair

def registrar_uso_se(api_key):
    """Registra 4 operaciones por imagen (todos los modelos)."""
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
    guardar_datos()

# ========== LOGS DE SERVIDORES ==========
@bot.event
async def on_guild_join(guild):
    CHANNEL_ID = 758876871173079060
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        embed = discord.Embed(
            title=f"{EMOJI_CORRECTO} Nuevo servidor añadido",
            description=f"**Threat** ha sido añadido a un nuevo servidor.",
            color=discord.Color.green()
        )
        embed.add_field(name="Nombre", value=guild.name, inline=True)
        embed.add_field(name="ID", value=guild.id, inline=True)
        embed.add_field(name="Miembros", value=guild.member_count, inline=True)
        embed.add_field(name="Propietario", value=guild.owner.mention if guild.owner else "Desconocido", inline=True)
        embed.add_field(name="Creado", value=guild.created_at.strftime("%d/%m/%Y"), inline=True)
        embed.set_footer(text=f"Total de servidores: {len(bot.guilds)}")
        await channel.send(embed=embed)

@bot.event
async def on_guild_remove(guild):
    CHANNEL_ID = 758876871173079060
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        embed = discord.Embed(
            title=f"{EMOJI_WARNING} Servidor eliminado",
            description=f"**Threat** ha sido eliminado de un servidor.",
            color=discord.Color.red()
        )
        embed.add_field(name="Nombre", value=guild.name, inline=True)
        embed.add_field(name="ID", value=guild.id, inline=True)
        embed.add_field(name="Miembros (aprox.)", value=guild.member_count, inline=True)
        embed.set_footer(text=f"Total de servidores restantes: {len(bot.guilds)}")
        await channel.send(embed=embed)

# ========== BASE DE DATOS Y JSON ==========
guilds_data = {}
cache_mem = {}

ANTIVIRUS_CONOCIDOS = [
    "Kaspersky", "McAfee", "Avast", "Norton", "BitDefender", "ESET", "Symantec",
    "Sophos", "TrendMicro", "AVG", "Panda", "F-Secure", "Malwarebytes", "Windows Defender"
]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS analisis (clave TEXT PRIMARY KEY, tipo TEXT, resultado TEXT, embed_json TEXT, timestamp REAL, expira REAL)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_expira ON analisis(expira)')
    conn.commit()
    conn.close()

def guardar_analisis_db(clave, tipo_analisis, resultado, embed):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = time.time()
    expira = now + EXPIRACION.get(tipo_analisis, 7*24*3600)
    embed_dict = embed.to_dict() if embed else None
    embed_json = json.dumps(embed_dict) if embed_dict else None
    c.execute('''INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira) VALUES (?, ?, ?, ?, ?, ?)''', (clave, tipo_analisis, resultado, embed_json, now, expira))
    conn.commit()
    conn.close()

def obtener_analisis_db(clave):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = time.time()
    c.execute('SELECT resultado, embed_json, expira FROM analisis WHERE clave = ?', (clave,))
    row = c.fetchone()
    conn.close()
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

def limpiar_db_expirados():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM analisis WHERE expira < ?', (time.time(),))
    conn.commit()
    conn.close()

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

            # VT
            bot.vt_key_total_requests = api_usage.get("total_requests", {})
            bot.vt_key_daily_usage = api_usage.get("daily_usage", {})
            if not hasattr(bot, 'vt_key_usage') or not bot.vt_key_usage:
                bot.vt_key_usage = {}

            # Sightengine
            se_data = api_usage.get("sightengine", {})
            bot.se_key_total_requests = se_data.get("total_requests", {})
            bot.se_key_daily_usage = se_data.get("daily_usage", {})
            if not hasattr(bot, 'se_key_usage') or not bot.se_key_usage:
                bot.se_key_usage = {}
        except Exception as e:
            print(f"Error al cargar datos: {e}")
            guilds_data = {}

def guardar_datos():
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
        guardar_datos()
    return guilds_data[guild_id]

def obtener_stats_globales():
    if "__global__" not in guilds_data:
        guilds_data["__global__"] = {"total_analisis": 0, "seguros": 0, "maliciosos": 0, "errores": 0}
        guardar_datos()
    return guilds_data["__global__"]

def update_stats_global(tipo):
    stats = obtener_stats_globales()
    stats["total_analisis"] += 1
    if tipo == "seguro": stats["seguros"] += 1
    elif tipo == "malicioso": stats["maliciosos"] += 1
    else: stats["errores"] += 1
    guardar_datos()

def update_stats_guild(guild_id, tipo):
    config = obtener_config_guild(guild_id)
    stats = config["stats"]
    stats["total_analisis"] += 1
    if tipo == "seguro": stats["seguros"] += 1
    elif tipo == "malicioso": stats["maliciosos"] += 1
    else: stats["errores"] += 1
    update_stats_global(tipo)
    guardar_datos()

def registrar_infraccion(guild_id, user_id, elemento_id):
    """
    Registra una infracción para un usuario si no ha sido sancionado ya por ese elemento.
    elemento_id: cadena única que identifica el contenido (ej. 'url:http://...', 'filehash:abc123')
    """
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
    guardar_datos()
    return config["infracciones"][uid]

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

async def enviar_log_guild(guild_id, tipo, valor, detalles, usuario, url_vt=None):
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
    await channel.send(embed=embed)

# ========== UTILIDADES (expandir URL, doble extensión) ==========
async def expandir_url(url):
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for _ in range(5):
                async with session.head(url, allow_redirects=False) as resp:
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
        return "error", embed
    headers = {"x-apikey": key}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    scan_id = data["data"]["id"]
                    await asyncio.sleep(15)
                    async with session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers) as resp2:
                        if resp2.status == 200:
                            stats_data = (await resp2.json())["data"]["attributes"]["stats"]
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
                                    await enviar_log_guild(guild_id, "URL", url, f"{mal} detecciones", mensaje_original.author, vt_link)
                                    config = obtener_config_guild(guild_id)
                                    if config["strict_mode"]:
                                        try: await mensaje_original.delete()
                                        except: pass
                                if guardar_cache:
                                    clave = f"url:{url}"
                                    guardar_analisis_db(clave, "url", "malicioso", embed)
                                    set_cache_mem(clave, "malicioso", embed)
                                return "malicioso", embed
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
                                    guardar_analisis_db(clave, "url", "seguro", embed)
                                    set_cache_mem(clave, "seguro", embed)
                                return "seguro", embed
                        else:
                            if guild_id: update_stats_guild(guild_id, "error")
                            embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error en análisis", description="Error al obtener resultado del análisis", color=discord.Color.red())
                            if guardar_cache:
                                clave = f"url:{url}"
                                guardar_analisis_db(clave, "url", "error", embed)
                                set_cache_mem(clave, "error", embed)
                            return "error", embed
                else:
                    if guild_id: update_stats_guild(guild_id, "error")
                    embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error al analizar URL", description="VirusTotal no procesó la solicitud", color=discord.Color.red())
                    if guardar_cache:
                        clave = f"url:{url}"
                        guardar_analisis_db(clave, "url", "error", embed)
                        set_cache_mem(clave, "error", embed)
                    return "error", embed
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_url: {e}")
        embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error de conexión", description="No se pudo contactar con VirusTotal", color=discord.Color.red())
        if guardar_cache:
            clave = f"url:{url}"
            guardar_analisis_db(clave, "url", "error", embed)
            set_cache_mem(clave, "error", embed)
        return "error", embed

async def analizar_hash(hash_valor, guild_id=None, mensaje_original=None, guardar_cache=True):
    key = obtener_siguiente_key()
    if not key:
        embed = discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red())
        return "error", embed
    headers = {"x-apikey": key}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://www.virustotal.com/api/v3/files/{hash_valor}", headers=headers) as resp:
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
                        embed = discord.Embed(
                            title=f"{EMOJI_WARNING} Hash Malicioso Detectado",
                            description=f"**{mal}** antivirus lo identificaron",
                            color=discord.Color.orange()
                        )
                        embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                        embed.add_field(name="Detectado por", value=f"`{top_text}`", inline=False)
                        embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                        if mensaje_original and guild_id:
                            await enviar_log_guild(guild_id, "Hash", hash_valor, f"{mal} detecciones (top: {top_text})", mensaje_original.author, vt_link)
                            config = obtener_config_guild(guild_id)
                            if config["strict_mode"]:
                                try: await mensaje_original.delete()
                                except: pass
                        if guardar_cache:
                            clave = f"hash:{hash_valor}"
                            guardar_analisis_db(clave, "hash", "malicioso", embed)
                            set_cache_mem(clave, "malicioso", embed)
                        return "malicioso", embed
                    else:
                        if guild_id: update_stats_guild(guild_id, "seguro")
                        embed = discord.Embed(
                            title=f"{EMOJI_CORRECTO} Hash Seguro",
                            description="No se encontraron amenazas",
                            color=discord.Color.green()
                        )
                        embed.add_field(name="Hash", value=f"`{hash_valor}`", inline=False)
                        embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                        if guardar_cache:
                            clave = f"hash:{hash_valor}"
                            guardar_analisis_db(clave, "hash", "seguro", embed)
                            set_cache_mem(clave, "seguro", embed)
                        return "seguro", embed
                else:
                    if guild_id: update_stats_guild(guild_id, "error")
                    embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Hash no encontrado", description="No existe en VirusTotal", color=discord.Color.red())
                    if guardar_cache:
                        clave = f"hash:{hash_valor}"
                        guardar_analisis_db(clave, "hash", "error", embed)
                        set_cache_mem(clave, "error", embed)
                    return "error", embed
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_hash: {e}")
        embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error", description="No se pudo consultar el hash", color=discord.Color.red())
        if guardar_cache:
            clave = f"hash:{hash_valor}"
            guardar_analisis_db(clave, "hash", "error", embed)
            set_cache_mem(clave, "error", embed)
        return "error", embed

async def analizar_ip(ip, guild_id=None, mensaje_original=None, guardar_cache=True):
    key = obtener_siguiente_key()
    if not key:
        embed = discord.Embed(title="Error de configuración", description="No hay claves de VirusTotal disponibles.", color=discord.Color.red())
        return "error", embed
    headers = {"x-apikey": key}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats_data = data["data"]["attributes"]["last_analysis_stats"]
                    mal = stats_data["malicious"]
                    vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
                    if mal > 0:
                        if guild_id: update_stats_guild(guild_id, "malicioso")
                        if mensaje_original and guild_id:
                            registrar_infraccion(guild_id, mensaje_original.author.id, f"ip:{ip}")
                        embed = discord.Embed(
                            title=f"{EMOJI_WARNING} IP Maliciosa Detectada",
                            description=f"**{mal}** fuentes reportan actividad sospechosa",
                            color=discord.Color.orange()
                        )
                        embed.add_field(name="IP", value=f"`{ip}`", inline=False)
                        embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                        if mensaje_original and guild_id:
                            await enviar_log_guild(guild_id, "IP", ip, f"{mal} fuentes reportan", mensaje_original.author, vt_link)
                            config = obtener_config_guild(guild_id)
                            if config["strict_mode"]:
                                try: await mensaje_original.delete()
                                except: pass
                        if guardar_cache:
                            clave = f"ip:{ip}"
                            guardar_analisis_db(clave, "ip", "malicioso", embed)
                            set_cache_mem(clave, "malicioso", embed)
                        return "malicioso", embed
                    else:
                        if guild_id: update_stats_guild(guild_id, "seguro")
                        embed = discord.Embed(
                            title=f"{EMOJI_CORRECTO} IP Segura",
                            description="No se encontraron reportes",
                            color=discord.Color.green()
                        )
                        embed.add_field(name="IP", value=f"`{ip}`", inline=False)
                        embed.add_field(name="\u200b", value=f"{EMOJI_LINK} [Ver informe completo]({vt_link})", inline=False)
                        if guardar_cache:
                            clave = f"ip:{ip}"
                            guardar_analisis_db(clave, "ip", "seguro", embed)
                            set_cache_mem(clave, "seguro", embed)
                        return "seguro", embed
                else:
                    if guild_id: update_stats_guild(guild_id, "error")
                    embed = discord.Embed(title=f"{EMOJI_INCORRECTO} IP no encontrada", description="No se pudo analizar la IP", color=discord.Color.red())
                    if guardar_cache:
                        clave = f"ip:{ip}"
                        guardar_analisis_db(clave, "ip", "error", embed)
                        set_cache_mem(clave, "error", embed)
                    return "error", embed
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_ip: {e}")
        embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Error", description="No se pudo contactar con VirusTotal", color=discord.Color.red())
        if guardar_cache:
            clave = f"ip:{ip}"
            guardar_analisis_db(clave, "ip", "error", embed)
            set_cache_mem(clave, "error", embed)
        return "error", embed

async def analizar_archivo(archivo, file_bytes=None, file_hash=None, guild_id=None, mensaje_original=None, guardar_cache=True):
    if file_bytes is None:
        headers = {"Authorization": f"Bot {TOKEN}"}
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(archivo.url, headers=headers) as resp:
                    if resp.status != 200:
                        if guild_id: update_stats_guild(guild_id, "error")
                        embed = discord.Embed(
                            title=f"{EMOJI_INCORRECTO} Error al descargar archivo",
                            description="No se pudo obtener el archivo",
                            color=discord.Color.red()
                        )
                        return "error", embed
                    file_bytes = await resp.read()
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
        except Exception as e:
            if guild_id: update_stats_guild(guild_id, "error")
            print(f"Error descargando archivo: {e}")
            embed = discord.Embed(
                title=f"{EMOJI_INCORRECTO} Error",
                description="Error al descargar el archivo",
                color=discord.Color.red()
            )
            return "error", embed

    if archivo.size > MAX_FILE_SIZE:
        if guild_id: update_stats_guild(guild_id, "error")
        embed = discord.Embed(
            title=f"{EMOJI_INCORRECTO} Archivo demasiado grande",
            description=f"{EMOJI_FILE} `{archivo.filename}` excede 32 MB",
            color=discord.Color.red()
        )
        return "error", embed

    clave = f"filehash:{file_hash}"
    key = obtener_siguiente_key()
    if not key:
        embed = discord.Embed(
            title="Error de configuración",
            description="No hay claves de VirusTotal disponibles.",
            color=discord.Color.red()
        )
        return "error", embed
    headers = {"x-apikey": key}
    try:
        data = aiohttp.FormData()
        data.add_field('file', file_bytes, filename=archivo.filename)
        async with aiohttp.ClientSession() as session:
            async with session.post("https://www.virustotal.com/api/v3/files", headers=headers, data=data) as resp:
                if resp.status == 200:
                    result_json = await resp.json()
                    scan_id = result_json["data"]["id"]
                    await asyncio.sleep(30)
                    async with session.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers) as resp2:
                        if resp2.status == 200:
                            stats_data = (await resp2.json())["data"]["attributes"]["stats"]
                            mal = stats_data["malicious"]
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
                                    await enviar_log_guild(guild_id, "Archivo", archivo.filename, f"{mal} detecciones", mensaje_original.author)
                                    config = obtener_config_guild(guild_id)
                                    if config["strict_mode"]:
                                        try: await mensaje_original.delete()
                                        except: pass
                                if guardar_cache:
                                    guardar_analisis_db(clave, "file", "malicioso", embed)
                                    set_cache_mem(clave, "malicioso", embed)
                                    clave_nombre = f"file:{archivo.filename}:{archivo.size}"
                                    guardar_analisis_db(clave_nombre, "file", "malicioso", embed)
                                    set_cache_mem(clave_nombre, "malicioso", embed)
                                return "malicioso", embed
                            else:
                                if guild_id: update_stats_guild(guild_id, "seguro")
                                embed = discord.Embed(
                                    title=f"{EMOJI_CORRECTO} Archivo Seguro",
                                    description=f"{EMOJI_FILE} `{archivo.filename}` parece limpio (0 detecciones)",
                                    color=discord.Color.green()
                                )
                                if guardar_cache:
                                    guardar_analisis_db(clave, "file", "seguro", embed)
                                    set_cache_mem(clave, "seguro", embed)
                                    clave_nombre = f"file:{archivo.filename}:{archivo.size}"
                                    guardar_analisis_db(clave_nombre, "file", "seguro", embed)
                                    set_cache_mem(clave_nombre, "seguro", embed)
                                return "seguro", embed
                        else:
                            if guild_id: update_stats_guild(guild_id, "error")
                            embed = discord.Embed(
                                title=f"{EMOJI_INCORRECTO} Error en análisis",
                                description="No se pudo obtener resultado",
                                color=discord.Color.red()
                            )
                            if guardar_cache:
                                guardar_analisis_db(clave, "file", "error", embed)
                                set_cache_mem(clave, "error", embed)
                            return "error", embed
                else:
                    if guild_id: update_stats_guild(guild_id, "error")
                    embed = discord.Embed(
                        title=f"{EMOJI_INCORRECTO} Error al subir archivo",
                        description="VirusTotal rechazó el archivo",
                        color=discord.Color.red()
                    )
                    if guardar_cache:
                        guardar_analisis_db(clave, "file", "error", embed)
                        set_cache_mem(clave, "error", embed)
                    return "error", embed
    except Exception as e:
        if guild_id: update_stats_guild(guild_id, "error")
        print(f"Error en analizar_archivo: {e}")
        embed = discord.Embed(
            title=f"{EMOJI_INCORRECTO} Error",
            description="No se pudo analizar el archivo",
            color=discord.Color.red()
        )
        if guardar_cache:
            guardar_analisis_db(clave, "file", "error", embed)
            set_cache_mem(clave, "error", embed)
        return "error", embed

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
    resultado_db, embed_db = obtener_analisis_db(clave)
    if embed_db:
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
        async with aiohttp.ClientSession() as session:
            data = aiohttp.FormData()
            data.add_field('media', image_bytes, filename='image.jpg')
            data.add_field('models', SIGHTENGINE_MODELS)
            data.add_field('api_user', api_user)
            data.add_field('api_secret', api_key)
            async with session.post(SIGHTENGINE_API_URL, data=data) as resp:
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
                    guardar_analisis_db(clave, "nsfw", cache_json, dummy_embed)
                    set_cache_mem(clave, cache_json, None)
                    guardar_datos()
                    return is_nsfw, max_confidence, models, False
                else:
                    resp_text = await resp.text()
                    print(f"❌ Sightengine respondió con {resp.status}: {resp_text[:200]}")
                    if resp.status == 400:
                        error_details = {"is_nsfw": False, "max_confidence": 0.0, "models": {}, "error": "sightengine_400"}
                        error_json = json.dumps(error_details)
                        dummy_embed = discord.Embed(title="NSFW Error Cache")
                        guardar_analisis_db(clave, "nsfw", error_json, dummy_embed)
                        set_cache_mem(clave, error_json, None)
                        return False, 0.0, {"error": "too_large"}, False
    except Exception as e:
        print(f"🔥 Excepción en análisis multimodelo: {e}")
    return False, 0.0, {}, False

# ========== CARGA DE COGS ==========
async def load_cogs():
    for archivo in os.listdir("./cogs"):
        if archivo.endswith(".py"):
            await bot.load_extension(f"cogs.{archivo[:-3]}")
            print(f"Cargado cog: {archivo}")

@bot.event
async def on_ready():
    print(f"Bot conectado como {bot.user}")
    await bot.change_presence(status=discord.Status.dnd, activity=None)
    await load_cogs()
    await bot.tree.sync()
    print("Comandos slash sincronizados correctamente")
    print("Bot Ready")

# ========== EVENTO ON_MESSAGE (Caché prioritaria, avisos unificados) ==========
@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    if not message.guild:
        await bot.process_commands(message)
        return

    guild_id = message.guild.id
    config = obtener_config_guild(guild_id)
    silent_mode = config["silent_mode"]
    strict_mode = config["strict_mode"]
    log_channel_id = config["log_channel_id"]

    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, message.content)
    if urls:
        url = urls[0]
        from urllib.parse import urlparse
        parsed = urlparse(url)
        dominio = parsed.netloc.lower()
        if dominio.startswith("www."):
            dominio = dominio[4:]
        whitelist = config.get("whitelist", [])
        if dominio in whitelist:
            await message.add_reaction(EMOJI_WHITELIST)
            if not silent_mode:
                await message.reply(f"{EMOJI_WHITELIST} **Dominio en whitelist:** `{dominio}`. No se requiere análisis.", mention_author=False)
            await bot.process_commands(message)
            return

        if url_es_imagen(url):
            print(f"[DEBUG] URL detectada como imagen: {url}")
            await message.add_reaction(EMOJI_LOADING)
            headers = {"Authorization": f"Bot {TOKEN}"}
            try:
                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            content_length = resp.headers.get('Content-Length')
                            if content_length and int(content_length) > MAX_IMAGE_SIZE:
                                await safe_remove_loading(message)
                                await message.add_reaction(EMOJI_INCORRECTO)
                                if not silent_mode:
                                    embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                                    await message.channel.send(embed=embed, reference=message)
                                await bot.process_commands(message)
                                return
                            img_data = await resp.read()
                            if len(img_data) > MAX_IMAGE_SIZE:
                                await safe_remove_loading(message)
                                await message.add_reaction(EMOJI_INCORRECTO)
                                if not silent_mode:
                                    embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                                    await message.channel.send(embed=embed, reference=message)
                                await bot.process_commands(message)
                                return
                            content_hash = hashlib.sha256(img_data).hexdigest()
                            is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                            await safe_remove_loading(message)

                            if models.get("error") == "too_large":
                                await message.add_reaction(EMOJI_WARNING)
                                if not silent_mode:
                                    embed = discord.Embed(
                                        title=f"{EMOJI_WARNING} Imagen no analizada",
                                        description="La imagen supera el límite de 2 MB permitido por Sightengine.\nNo se pudo verificar el contenido.",
                                        color=discord.Color.orange()
                                    )
                                    await message.channel.send(embed=embed, reference=message)
                                await bot.process_commands(message)
                                return

                            if is_nsfw:
                                if guild_id:
                                    registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                                await message.add_reaction(EMOJI_WARNING)
                                detectados = []
                                if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                                if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                                if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                                if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                                detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                                embed = discord.Embed(title=f"{EMOJI_WARNING} Contenido Inapropiado Detectado (URL)", description=f"{detalles_str}", color=discord.Color.orange())
                                embed.add_field(name="Enlace", value=f"[Ver imagen]({url})", inline=False)
                                await message.channel.send(embed=embed, reference=message)
                                if log_channel_id:
                                    embed_log = discord.Embed(title=f"{EMOJI_WARNING} Contenido Inapropiado", description=f"{detalles_str} " + ("(cache)" if from_cache else ""), color=discord.Color.red())
                                    embed_log.add_field(name="Usuario", value=message.author.mention, inline=True)
                                    embed_log.add_field(name="Enlace", value=f"[Ver imagen]({url})", inline=True)
                                    embed_log.set_footer(text=f"ID: {message.author.id} • {time.strftime('%Y-%m-%d %H:%M:%S')}")
                                    channel = bot.get_channel(log_channel_id)
                                    if channel: await channel.send(embed=embed_log)
                                if strict_mode:
                                    try: await message.delete()
                                    except: pass
                            else:
                                await message.add_reaction(EMOJI_CORRECTO)
                                if not silent_mode:
                                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} Imagen Segura (URL)", description="No se detectó contenido inapropiado.", color=discord.Color.green())
                                    embed.add_field(name="Enlace", value=f"[Ver imagen]({url})", inline=False)
                                    await message.channel.send(embed=embed, reference=message)
                        else:
                            await safe_remove_loading(message)
            except asyncio.TimeoutError:
                await safe_remove_loading(message)
                await message.add_reaction(EMOJI_WARNING)
                if not silent_mode:
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Descarga lenta", description="La descarga de la imagen ha tardado demasiado.", color=discord.Color.orange())
                    await message.channel.send(embed=embed, reference=message)
            except Exception as e:
                print(f"[DEBUG] Excepción al procesar URL de imagen: {e}")
                await safe_remove_loading(message)
                await message.add_reaction(EMOJI_WARNING)
                if not silent_mode:
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Error de descarga", description="No se pudo descargar la imagen.", color=discord.Color.red())
                    await message.channel.send(embed=embed, reference=message)
            await bot.process_commands(message)
            return
        else:
            print(f"[DEBUG] URL no es imagen, analizando con VirusTotal: {url}")
            url_original = url
            url = await expandir_url(url)
            clave = f"url:{url_original}"
            tipo, embed = get_from_cache_mem(clave)
            if embed is None:
                tipo, embed = obtener_analisis_db(clave)
                if embed is not None:
                    set_cache_mem(clave, tipo, embed)

            if embed is not None:
                if tipo == "malicioso":
                    registrar_infraccion(guild_id, message.author.id, f"url:{url}")
                    await message.channel.send(embed=embed, reference=message)
                elif not silent_mode:
                    await message.channel.send(embed=embed, reference=message)

                if tipo == "malicioso":
                    await message.add_reaction(EMOJI_WARNING)
                    if log_channel_id:
                        await enviar_log_guild(guild_id, "URL", url, "Amenaza detectada (cache)", message.author)
                    if strict_mode:
                        try: await message.delete()
                        except: pass
                elif tipo == "seguro":
                    await message.add_reaction(EMOJI_CORRECTO)
                else:
                    await message.add_reaction(EMOJI_INCORRECTO)
                await bot.process_commands(message)
                return

            ahora = time.time()
            user_id = message.author.id
            if user_id not in bot.user_scan_history:
                bot.user_scan_history[user_id] = []
            bot.user_scan_history[user_id] = [t for t in bot.user_scan_history[user_id] if ahora - t < 3600]
            if len(bot.user_scan_history[user_id]) >= 30:
                await message.add_reaction(EMOJI_COOLDOWN)
                return
            if user_id in bot.antispam_scan:
                if ahora - bot.antispam_scan[user_id] < 10:
                    await message.add_reaction(EMOJI_COOLDOWN)
                    return
            bot.antispam_scan[user_id] = ahora
            bot.user_scan_history[user_id].append(ahora)

            await message.add_reaction(EMOJI_LOADING)
            tipo, embed = await analizar_url(url, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
            await safe_remove_loading(message)
            if url != url_original:
                embed.add_field(name=f"{EMOJI_REPLY} Redirección", value=f"Original: `{url_original}`\nExpandida: `{url}`", inline=False)

            if tipo == "malicioso":
                await message.channel.send(embed=embed, reference=message)
            elif not silent_mode:
                await message.channel.send(embed=embed, reference=message)

            try:
                if tipo == "seguro": await message.add_reaction(EMOJI_CORRECTO)
                elif tipo == "malicioso": await message.add_reaction(EMOJI_WARNING)
                else: await message.add_reaction(EMOJI_INCORRECTO)
            except discord.NotFound:
                pass
            await bot.process_commands(message)
            return

    if message.attachments:
        archivo = message.attachments[0]
        if es_imagen(archivo):
            if archivo.size > MAX_IMAGE_SIZE:
                await message.add_reaction(EMOJI_INCORRECTO)
                if not silent_mode:
                    embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                    await message.channel.send(embed=embed, reference=message)
                await bot.process_commands(message)
                return

            print(f"[DEBUG] Archivo adjunto es imagen: {archivo.filename}")
            await message.add_reaction(EMOJI_LOADING)
            headers = {"Authorization": f"Bot {TOKEN}"}
            try:
                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(archivo.url, headers=headers) as resp:
                        if resp.status == 200:
                            img_data = await resp.read()
                            if len(img_data) > MAX_IMAGE_SIZE:
                                await safe_remove_loading(message)
                                await message.add_reaction(EMOJI_INCORRECTO)
                                if not silent_mode:
                                    embed = discord.Embed(title=f"{EMOJI_INCORRECTO} Imagen demasiado grande", description="No se puede analizar (>2 MB)", color=discord.Color.red())
                                    await message.channel.send(embed=embed, reference=message)
                                await bot.process_commands(message)
                                return
                            content_hash = hashlib.sha256(img_data).hexdigest()
                            is_nsfw, confidence, models, from_cache = await analizar_imagen_multimodelo(content_hash, img_data)
                            await safe_remove_loading(message)

                            if models.get("error") == "too_large":
                                await message.add_reaction(EMOJI_WARNING)
                                if not silent_mode:
                                    embed = discord.Embed(
                                        title=f"{EMOJI_WARNING} Imagen no analizada",
                                        description="La imagen supera el límite de 2 MB permitido por Sightengine.\nNo se pudo verificar el contenido.",
                                        color=discord.Color.orange()
                                    )
                                    await message.channel.send(embed=embed, reference=message)
                                await bot.process_commands(message)
                                return

                            if is_nsfw:
                                if guild_id:
                                    registrar_infraccion(guild_id, message.author.id, f"nsfw:{content_hash}")
                                await message.add_reaction(EMOJI_WARNING)
                                detectados = []
                                if models.get('nudity', 0.0) >= 0.5: detectados.append(f"Desnudez {models['nudity']*100:.0f}%")
                                if models.get('weapon', 0.0) >= 0.5: detectados.append(f"Armas {models['weapon']*100:.0f}%")
                                if models.get('offensive', 0.0) >= 0.7: detectados.append(f"Ofensivo {models['offensive']*100:.0f}%")
                                if models.get('alcohol', 0.0) >= 0.7: detectados.append(f"Alcohol {models['alcohol']*100:.0f}%")
                                detalles_str = ", ".join(detectados) if detectados else "Contenido inapropiado"
                                embed = discord.Embed(title=f"{EMOJI_WARNING} Contenido Inapropiado Detectado", description=f"{detalles_str}", color=discord.Color.orange())
                                embed.add_field(name="Archivo", value=archivo.filename, inline=False)
                                await message.channel.send(embed=embed, reference=message)
                                if log_channel_id:
                                    embed_log = discord.Embed(title=f"{EMOJI_WARNING} Contenido Inapropiado", description=f"{detalles_str} " + ("(cache)" if from_cache else ""), color=discord.Color.red())
                                    embed_log.add_field(name="Usuario", value=message.author.mention, inline=True)
                                    embed_log.add_field(name="Archivo", value=archivo.filename, inline=True)
                                    embed_log.set_footer(text=f"ID: {message.author.id} • {time.strftime('%Y-%m-%d %H:%M:%S')}")
                                    channel = bot.get_channel(log_channel_id)
                                    if channel: await channel.send(embed=embed_log)
                                if strict_mode:
                                    try: await message.delete()
                                    except: pass
                            else:
                                await message.add_reaction(EMOJI_CORRECTO)
                                if not silent_mode:
                                    embed = discord.Embed(title=f"{EMOJI_CORRECTO} Imagen Segura", description="No se detectó contenido inapropiado.", color=discord.Color.green())
                                    embed.add_field(name="Archivo", value=archivo.filename, inline=False)
                                    await message.channel.send(embed=embed, reference=message)
                        else:
                            await safe_remove_loading(message)
            except asyncio.TimeoutError:
                await safe_remove_loading(message)
                await message.add_reaction(EMOJI_WARNING)
                if not silent_mode:
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Descarga lenta", description="La descarga de la imagen ha tardado demasiado.", color=discord.Color.orange())
                    await message.channel.send(embed=embed, reference=message)
            except Exception as e:
                print(f"[DEBUG] Excepción al procesar imagen adjunta: {e}")
                await safe_remove_loading(message)
                await message.add_reaction(EMOJI_WARNING)
                if not silent_mode:
                    embed = discord.Embed(title=f"{EMOJI_WARNING} Error de descarga", description="No se pudo descargar la imagen.", color=discord.Color.red())
                    await message.channel.send(embed=embed, reference=message)
            await bot.process_commands(message)
            return
        else:
            # Archivo no imagen – descargar primero y cachear por hash
            ahora = time.time()
            user_id = message.author.id
            if user_id not in bot.user_scan_history:
                bot.user_scan_history[user_id] = []
            bot.user_scan_history[user_id] = [t for t in bot.user_scan_history[user_id] if ahora - t < 3600]
            if len(bot.user_scan_history[user_id]) >= 30:
                await message.add_reaction(EMOJI_COOLDOWN)
                return
            if user_id in bot.antispam_scan:
                if ahora - bot.antispam_scan[user_id] < 10:
                    await message.add_reaction(EMOJI_COOLDOWN)
                    return
            bot.antispam_scan[user_id] = ahora
            bot.user_scan_history[user_id].append(ahora)

            print(f"[DEBUG] Archivo adjunto no es imagen: {archivo.filename}")

            doble_ext = tiene_doble_extension(archivo.filename)
            warning_mime = ""

            if doble_ext:
                await message.add_reaction(EMOJI_WARNING)

            # 1. Descargar el archivo para obtener el hash
            headers = {"Authorization": f"Bot {TOKEN}"}
            try:
                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(archivo.url, headers=headers) as resp:
                        if resp.status != 200:
                            error_embed = discord.Embed(
                                title=f"{EMOJI_INCORRECTO} Error",
                                description="No se pudo descargar el archivo.",
                                color=discord.Color.red()
                            )
                            if doble_ext:
                                error_embed.add_field(
                                    name=f"{EMOJI_WARNING} Doble extensión",
                                    value=f"`{archivo.filename}` podría ser peligroso.",
                                    inline=False
                                )
                            if not silent_mode or doble_ext:
                                await message.channel.send(embed=error_embed, reference=message)
                            await bot.process_commands(message)
                            return

                        file_data = await resp.read()
                        file_hash = hashlib.sha256(file_data).hexdigest()

                        content_type = resp.headers.get('Content-Type', '')
                        if archivo.filename.endswith('.jpg') and content_type not in ('image/jpeg', 'image/jpg'):
                            warning_mime = f"El archivo tiene extensión .jpg pero el tipo real es {content_type}."
                        elif archivo.filename.endswith('.png') and content_type != 'image/png':
                            warning_mime = f"El archivo tiene extensión .png pero el tipo real es {content_type}."

            except Exception as e:
                print(f"[DEBUG] Excepción al descargar archivo: {e}")
                error_embed = discord.Embed(
                    title=f"{EMOJI_INCORRECTO} Error",
                    description="Error al descargar el archivo.",
                    color=discord.Color.red()
                )
                if doble_ext:
                    error_embed.add_field(
                        name=f"{EMOJI_WARNING} Doble extensión",
                        value=f"`{archivo.filename}` podría ser peligroso.",
                        inline=False
                    )
                if not silent_mode or doble_ext:
                    await message.channel.send(embed=error_embed, reference=message)
                await bot.process_commands(message)
                return

            # 2. Mirar si ya tenemos el análisis por HASH en caché/DB
            clave_hash = f"filehash:{file_hash}"
            tipo, embed = get_from_cache_mem(clave_hash)
            if embed is None:
                tipo, embed = obtener_analisis_db(clave_hash)
                if embed is not None:
                    set_cache_mem(clave_hash, tipo, embed)

            if embed is not None:
                embed = embed.copy()
                if doble_ext and not any("Doble extensión" in field.name for field in embed.fields):
                    embed.add_field(
                        name=f"{EMOJI_WARNING} Doble extensión",
                        value=f"`{archivo.filename}` podría ser peligroso.",
                        inline=False
                    )
                if warning_mime and not any("Verificación MIME" in field.name for field in embed.fields):
                    embed.add_field(
                        name=f"{EMOJI_WARNING} Verificación MIME",
                        value=warning_mime,
                        inline=False
                    )

                if tipo == "malicioso" or doble_ext:
                    if tipo == "malicioso":
                        registrar_infraccion(guild_id, message.author.id, f"filehash:{file_hash}")
                    await message.channel.send(embed=embed, reference=message)
                elif not silent_mode:
                    await message.channel.send(embed=embed, reference=message)

                if tipo == "malicioso":
                    await message.add_reaction(EMOJI_WARNING)
                    if log_channel_id:
                        await enviar_log_guild(guild_id, "Archivo", archivo.filename, "Amenaza detectada (cache)", message.author)
                    if strict_mode:
                        try: await message.delete()
                        except: pass
                elif tipo == "seguro":
                    await message.add_reaction(EMOJI_CORRECTO)
                else:
                    await message.add_reaction(EMOJI_INCORRECTO)
                await bot.process_commands(message)
                return

            # 3. No está en caché → analizar con VT
            await message.add_reaction(EMOJI_LOADING)
            tipo, embed = await analizar_archivo(archivo, file_bytes=file_data, file_hash=file_hash, guild_id=guild_id, mensaje_original=message, guardar_cache=True)
            await safe_remove_loading(message)

            if doble_ext:
                embed.add_field(
                    name=f"{EMOJI_WARNING} Doble extensión",
                    value=f"`{archivo.filename}` podría ser peligroso.",
                    inline=False
                )
            if warning_mime:
                embed.add_field(
                    name=f"{EMOJI_WARNING} Verificación MIME",
                    value=warning_mime,
                    inline=False
                )

            if tipo == "malicioso" or doble_ext:
                await message.channel.send(embed=embed, reference=message)
            elif not silent_mode:
                await message.channel.send(embed=embed, reference=message)

            try:
                if tipo == "seguro": await message.add_reaction(EMOJI_CORRECTO)
                elif tipo == "malicioso": await message.add_reaction(EMOJI_WARNING)
                else: await message.add_reaction(EMOJI_INCORRECTO)
            except discord.NotFound:
                pass

            await bot.process_commands(message)
            return

    # Procesar comandos para mensajes sin URL ni archivo adjunto
    await bot.process_commands(message)

# ========== EVENTO ON_MESSAGE_EDIT ==========
@bot.event
async def on_message_edit(before, after):
    if before.author == bot.user:
        return
    if not after.guild:
        return

    guild_id = after.guild.id
    config = obtener_config_guild(guild_id)
    silent_mode = config["silent_mode"]
    strict_mode = config["strict_mode"]
    log_channel_id = config["log_channel_id"]

    # --- URLs añadidas en la edición ---
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, after.content)
    if urls and not re.findall(url_pattern, before.content):
        url = urls[0]
        from urllib.parse import urlparse
        parsed = urlparse(url)
        dominio = parsed.netloc.lower().removeprefix("www.")
        whitelist = config.get("whitelist", [])
        if dominio in whitelist:
            return

        if url_es_imagen(url):
            # Por ahora no analizamos imágenes en ediciones automáticamente
            return
        else:
            # --- URL no imagen (misma lógica que on_message) ---
            url_original = url
            url = await expandir_url(url)
            clave = f"url:{url_original}"
            tipo, embed = get_from_cache_mem(clave)
            if embed is None:
                tipo, embed = obtener_analisis_db(clave)
                if embed is not None:
                    set_cache_mem(clave, tipo, embed)

            if embed is not None:
                # Añadir campo de redirección si procede
                if url != url_original:
                    embed = embed.copy()
                    embed.add_field(name=f"{EMOJI_REPLY} Redirección", value=f"Original: `{url_original}`\nExpandida: `{url}`", inline=False)

                if tipo == "malicioso":
                    registrar_infraccion(guild_id, after.author.id, f"url:{url}")
                    await after.channel.send(embed=embed, reference=after)
                    if log_channel_id:
                        await enviar_log_guild(guild_id, "URL", url, "Detectado en edición", after.author)
                    if strict_mode:
                        try: await after.delete()
                        except: pass
                elif not silent_mode:
                    await after.channel.send(embed=embed, reference=after)
                return

            # Anti‑spam / cooldown
            ahora = time.time()
            if after.author.id in bot.antispam_scan and ahora - bot.antispam_scan[after.author.id] < 10:
                return
            bot.antispam_scan[after.author.id] = ahora

            # Análisis fresco
            await after.add_reaction(EMOJI_LOADING)
            tipo, embed = await analizar_url(url, guild_id=guild_id, mensaje_original=after, guardar_cache=True)
            await safe_remove_loading(after)

            if url != url_original:
                embed.add_field(name=f"{EMOJI_REPLY} Redirección", value=f"Original: `{url_original}`\nExpandida: `{url}`", inline=False)
            if tipo == "malicioso":
                await after.channel.send(embed=embed, reference=after)
                if log_channel_id:
                    await enviar_log_guild(guild_id, "URL", url, "Detectado en edición", after.author)
                if strict_mode:
                    try: await after.delete()
                    except: pass
            elif not silent_mode:
                await after.channel.send(embed=embed, reference=after)

    # --- Archivos añadidos en la edición (solo si no había adjuntos antes) ---
    if after.attachments and not before.attachments:
        archivo = after.attachments[0]
        if not es_imagen(archivo):
            # Anti‑spam / cooldown
            ahora = time.time()
            user_id = after.author.id
            if user_id not in bot.user_scan_history:
                bot.user_scan_history[user_id] = []
            bot.user_scan_history[user_id] = [t for t in bot.user_scan_history[user_id] if ahora - t < 3600]
            if len(bot.user_scan_history[user_id]) >= 30:
                await after.add_reaction(EMOJI_COOLDOWN)
                return
            if user_id in bot.antispam_scan and ahora - bot.antispam_scan[user_id] < 10:
                await after.add_reaction(EMOJI_COOLDOWN)
                return
            bot.antispam_scan[user_id] = ahora
            bot.user_scan_history[user_id].append(ahora)

            doble_ext = tiene_doble_extension(archivo.filename)
            warning_mime = ""

            if doble_ext:
                await after.add_reaction(EMOJI_WARNING)

            # 1. Descargar el archivo para obtener el hash y verificar MIME
            headers = {"Authorization": f"Bot {TOKEN}"}
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(archivo.url, headers=headers) as resp:
                        if resp.status != 200:
                            error_embed = discord.Embed(
                                title=f"{EMOJI_INCORRECTO} Error",
                                description="No se pudo descargar el archivo.",
                                color=discord.Color.red()
                            )
                            if doble_ext:
                                error_embed.add_field(name=f"{EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                            if not silent_mode or doble_ext:
                                await after.channel.send(embed=error_embed, reference=after)
                            return

                        file_data = await resp.read()
                        file_hash = hashlib.sha256(file_data).hexdigest()

                        content_type = resp.headers.get('Content-Type', '')
                        if archivo.filename.endswith('.jpg') and content_type not in ('image/jpeg', 'image/jpg'):
                            warning_mime = f"El archivo tiene extensión .jpg pero el tipo real es {content_type}."
                        elif archivo.filename.endswith('.png') and content_type != 'image/png':
                            warning_mime = f"El archivo tiene extensión .png pero el tipo real es {content_type}."

            except Exception as e:
                error_embed = discord.Embed(
                    title=f"{EMOJI_INCORRECTO} Error",
                    description="Error al descargar el archivo.",
                    color=discord.Color.red()
                )
                if doble_ext:
                    error_embed.add_field(name=f"{EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                if not silent_mode or doble_ext:
                    await after.channel.send(embed=error_embed, reference=after)
                return

            # 2. Caché / DB (por hash)
            clave_hash = f"filehash:{file_hash}"
            tipo, embed = get_from_cache_mem(clave_hash)
            if embed is None:
                tipo, embed = obtener_analisis_db(clave_hash)
                if embed is not None:
                    set_cache_mem(clave_hash, tipo, embed)

            if embed is not None:
                embed = embed.copy()
                if doble_ext and not any("Doble extensión" in field.name for field in embed.fields):
                    embed.add_field(name=f"{EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                if warning_mime and not any("Verificación MIME" in field.name for field in embed.fields):
                    embed.add_field(name=f"{EMOJI_WARNING} Verificación MIME", value=warning_mime, inline=False)

                if tipo == "malicioso" or doble_ext:
                    if tipo == "malicioso":
                        registrar_infraccion(guild_id, after.author.id, f"filehash:{file_hash}")
                    await after.channel.send(embed=embed, reference=after)
                elif not silent_mode:
                    await after.channel.send(embed=embed, reference=after)

                if tipo == "malicioso":
                    await after.add_reaction(EMOJI_WARNING)
                    if log_channel_id:
                        await enviar_log_guild(guild_id, "Archivo", archivo.filename, "Amenaza detectada en edición (cache)", after.author)
                    if strict_mode:
                        try: await after.delete()
                        except: pass
                elif tipo == "seguro":
                    await after.add_reaction(EMOJI_CORRECTO)
                else:
                    await after.add_reaction(EMOJI_INCORRECTO)
                return

            # 3. Análisis fresco con VT
            await after.add_reaction(EMOJI_LOADING)
            tipo, embed = await analizar_archivo(archivo, file_bytes=file_data, file_hash=file_hash, guild_id=guild_id, mensaje_original=after, guardar_cache=True)
            await safe_remove_loading(after)

            if doble_ext:
                embed.add_field(name=f"{EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
            if warning_mime:
                embed.add_field(name=f"{EMOJI_WARNING} Verificación MIME", value=warning_mime, inline=False)

            if tipo == "malicioso" or doble_ext:
                await after.channel.send(embed=embed, reference=after)
            elif not silent_mode:
                await after.channel.send(embed=embed, reference=after)

            try:
                if tipo == "seguro": await after.add_reaction(EMOJI_CORRECTO)
                elif tipo == "malicioso": await after.add_reaction(EMOJI_WARNING)
                else: await after.add_reaction(EMOJI_INCORRECTO)
            except discord.NotFound:
                pass

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

if __name__ == "__main__":
    if not TOKEN or not VT_API_KEYS or not SE_API_KEYS_PAIRS:
        print("ERROR: Debes configurar DISCORD_TOKEN, al menos una VT_API_KEY y al menos un par válido de Sightengine en el .env")
    else:
        cargar_datos()
        init_db()
        limpiar_db_expirados()
        bot.run(TOKEN)