import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Base directory for resolving relative paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TOKEN: Optional[str] = os.getenv("DISCORD_TOKEN")

VT_KEYS_RAW: list[Optional[str]] = [
    os.getenv("VT_API_KEY"),
    os.getenv("VT_API_KEY_2"),
    os.getenv("VT_API_KEY_3")
]
VT_API_KEYS: list[str] = [k for k in VT_KEYS_RAW if k]

SE_VARS: list[tuple[Optional[str], Optional[str]]] = [
    (os.getenv("SIGHTENGINE_API_USER"), os.getenv("SIGHTENGINE_API_KEY")),
    (os.getenv("SIGHTENGINE_API_USER_2"), os.getenv("SIGHTENGINE_API_KEY_2")),
    (os.getenv("SIGHTENGINE_API_USER_3"), os.getenv("SIGHTENGINE_API_KEY_3")),
]
SE_API_KEYS_PAIRS: list[tuple[str, str]] = [(u, k) for u, k in SE_VARS if u and k]

MAX_FILE_SIZE: int = 32 * 1024 * 1024
MAX_IMAGE_SIZE: int = 2 * 1024 * 1024
CACHE_DURATION: int = 3600
DATA_FILE: str = os.path.join(BASE_DIR, "data.json")
DB_FILE: str = os.path.join(BASE_DIR, "analisis.db")

EXPIRACION: dict[str, int] = {
    "url": 7 * 24 * 3600,
    "hash": 30 * 24 * 3600,
    "ip": 7 * 24 * 3600,
    "file": 30 * 24 * 3600,
    "nsfw": 30 * 24 * 3600,
}

SIGHTENGINE_API_URL: str = "https://api.sightengine.com/1.0/check.json"
SIGHTENGINE_MODELS: str = "nudity,weapon,alcohol,offensive"
NSFW_CONFIDENCE_THRESHOLD: float = 0.5

EMOJI_CORRECTO: str = "<:SM_Correcto:1015080045410263051>"
EMOJI_INCORRECTO: str = "<:SM_Incorrecto:1015080005950259300>"
EMOJI_ERROR: str = "<:Error:1513757533008039956>"
EMOJI_WARNING: str = "<:SM_Warning:1016367428193767504>"
EMOJI_LINK: str = "<:SM_Link:1015452825834242088>"
EMOJI_LUPA: str = "<:SM_Lupa:1020191899258204160>"
EMOJI_LOADING: str = "<:LoadingError:1513758425115394048>"
EMOJI_FILE: str = "<:SM_File:1495493423728427028>"
EMOJI_SHIELD: str = "<:SM_Shield:1495494358646915172>"
EMOJI_FINGERPRINT: str = "<:SM_Fingerprint:1495496674833862726>"
EMOJI_GUARDIAN: str = "<:SM_Guardian:1495497006825603263>"
EMOJI_STATS: str = "<:SM_Stats:1495498539059646605>"
EMOJI_WHITELIST: str = "<:SM_Whitelist:1496963945943269498>"
EMOJI_COOLDOWN: str = "<:Hourglass:1513756176704339978>"
EMOJI_REPLY: str = "<:SM_Reply:1042590456892104835>"
EMOJI_KEY: str = "<:SM_Key:1497274741160149153>"
EMOJI_KICK: str = "<:SM_Kick:1498412609484099626>"
EMOJI_BAN: str = "<:SM_Ban:1498412610704375848>"
EMOJI_CLEAN: str = "<:SM_Clean:1498412609056014336>"
EMOJI_GITHUB: str = "<:Github:1512615005588160562>"
EMOJI_NSFW: str = "<:NSFW:1513756541931753544>"

ANTIVIRUS_CONOCIDOS: list[str] = [
    "Kaspersky", "McAfee", "Avast", "Norton", "BitDefender", "ESET", "Symantec",
    "Sophos", "TrendMicro", "AVG", "Panda", "F-Secure", "Malwarebytes", "Windows Defender",
]

DOMINIOS_PROTEGIDOS: list[str] = [
    "youtube.com", "youtu.be", "google.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "reddit.com", "twitter.com",
    "x.com", "twitch.tv", "spotify.com", "microsoft.com",
    "apple.com", "amazon.com", "discord.com"
]

ANTISPAM_ANALYSIS_PER_HOUR: int = 30
ANTISPAM_COOLDOWN: int = 10
VT_MAX_REQUESTS_PER_USER: int = 4

IMAGE_EXTENSIONS: list[str] = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic', '.heif']

OWNER_ID: Optional[str] = os.getenv("OWNER_ID")
