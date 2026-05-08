import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")

VT_KEYS_RAW = [
    os.getenv("VT_API_KEY"),
    os.getenv("VT_API_KEY_2"),
    os.getenv("VT_API_KEY_3")
]
VT_API_KEYS = [k for k in VT_KEYS_RAW if k]

SE_VARS = [
    (os.getenv("SIGHTENGINE_API_USER"), os.getenv("SIGHTENGINE_API_KEY")),
    (os.getenv("SIGHTENGINE_API_USER_2"), os.getenv("SIGHTENGINE_API_KEY_2")),
    (os.getenv("SIGHTENGINE_API_USER_3"), os.getenv("SIGHTENGINE_API_KEY_3")),
]
SE_API_KEYS_PAIRS = [(u, k) for u, k in SE_VARS if u and k]

MAX_FILE_SIZE = 32 * 1024 * 1024
MAX_IMAGE_SIZE = 2 * 1024 * 1024
CACHE_DURATION = 3600
DATA_FILE = "data.json"
DB_FILE = "analisis.db"

EXPIRACION = {
    "url": 7 * 24 * 3600,
    "hash": 30 * 24 * 3600,
    "ip": 7 * 24 * 3600,
    "file": 30 * 24 * 3600,
    "nsfw": 30 * 24 * 3600,
}

SIGHTENGINE_API_URL = "https://api.sightengine.com/1.0/check.json"
SIGHTENGINE_MODELS = "nudity,weapon,alcohol,offensive"
NSFW_CONFIDENCE_THRESHOLD = 0.5

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

ANTIVIRUS_CONOCIDOS = [
    "Kaspersky", "McAfee", "Avast", "Norton", "BitDefender", "ESET", "Symantec",
    "Sophos", "TrendMicro", "AVG", "Panda", "F-Secure", "Malwarebytes", "Windows Defender",
]

DOMINIOS_PROTEGIDOS = [
    "youtube.com", "youtu.be", "google.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "reddit.com", "twitter.com",
    "x.com", "twitch.tv", "spotify.com", "microsoft.com",
    "apple.com", "amazon.com", "discord.com"
]

ANTISPAM_URLS_PER_HOUR = 30
ANTISPAM_COOLDOWN = 10

OWNER_ID = os.getenv("OWNER_ID")
