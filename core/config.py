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

# ===== Sistema visual =====
# Replican los tokens de landing/src/styles/global.css para que la marca sea la misma
# en la web y en Discord. La barra lateral del embed es lo primero que se lee, así que
# el color se reserva para la severidad y los embeds informativos van todos en gris.
COLOR_NEUTRAL: int = 0x36393F   # --color-surface-600: base de la UI oscura del sitio
COLOR_SEGURO: int = 0x4ADE80    # --color-secure
COLOR_MALICIOSO: int = 0xF59E0B  # --color-malicious: el objeto analizado es malo
COLOR_SOSPECHOSO: int = 0xE8C547 # --color-alert: engines que lo marcan, ninguno lo confirma
COLOR_ERROR: int = 0xDC2626     # --color-threat: requiere acción / algo falló
COLOR_NSFW: int = 0xDC2626      # --color-nsfw
COLOR_TOPGG: int = 0xFF3366     # --color-topgg: promoción puntual, nunca severidad

# Modelo de color:
#   ámbar  -> "esto es malo" (resultado de un análisis)
#   rojo   -> "esto está pasando en tu servidor, actúa" (log de amenaza) o error
#   alerta -> "algo no cuadra pero no está confirmado" (suspicious de VT)
SEVERIDAD_COLOR: dict[str, int] = {
    "seguro": COLOR_SEGURO,
    "sospechoso": COLOR_SOSPECHOSO,
    "malicioso": COLOR_MALICIOSO,
    "error": COLOR_ERROR,
    "nsfw": COLOR_NSFW,
}

EXPIRACION: dict[str, int] = {
    "url": 7 * 24 * 3600,
    "hash": 30 * 24 * 3600,
    "ip": 7 * 24 * 3600,
    "file": 30 * 24 * 3600,
    "nsfw": 30 * 24 * 3600,
    # "VirusTotal todavía no ha visto este archivo". Caducidad corta a propósito: el
    # resultado es determinista mientras nadie suba el archivo, así que cachearlo evita
    # gastar una request de la cuota gratuita en cada reaparición de la misma imagen.
    # En cuanto alguien lo suba, ya hay algo que mirar, así que no se guarda 30 días como
    # un veredicto: el compromiso es una request por imagen y día, a cambio de poder
    # retrasar como mucho un día la detección de un archivo que suba otra persona.
    "imgmal_desconocido": 24 * 3600,
}

SIGHTENGINE_API_URL: str = "https://api.sightengine.com/1.0/check.json"
# `nudity` v1.0 está deprecated en favor de `nudity-2.1`, y se añade `gore-2.0` porque
# la sangre/gore es contenido que de verdad aparece en un servidor y antes no se miraba.
# Suman 5 operaciones por llamada, y ese número lo gasta SE_OPS_PER_CALL.
SIGHTENGINE_MODELS: str = "nudity-2.1,weapon,alcohol,gore-2.0,offensive"
NSFW_CONFIDENCE_THRESHOLD: float = 0.5

# Umbrales por categoría. Se pueden sobrescribir por servidor desde /settings; estos son
# los valores por defecto.
#
# `nudity_partial` va aparte de `nudity_raw` a propósito: `raw` es material explícito
# tipo X y `partial` es bikini, lencería o escote. Antes solo se leía `raw`, que es justo
# lo que menos aparece, así que el detector marcaba muy poco.
UMBRALES_CONTENIDO: dict[str, float] = {
    "nudity_raw": 0.5,
    "nudity_partial": 0.45,
    "gore": 0.5,
    "offensive": 0.7,
    # `restringido` son señales discutibles: avisan y se registran, pero no borran.
    "alcohol": 0.7,
    "weapon": 0.6,
}

EMOJI_CORRECTO: str = "<:SM_Correcto:1015080045410263051>"
EMOJI_INCORRECTO: str = "<:SM_Incorrecto:1015080005950259300>"
EMOJI_ERROR: str = "<:Error:1513757533008039956>"
EMOJI_WARNING: str = "<:SM_Warning:1016367428193767504>"
EMOJI_LINK: str = "<:SM_Link:1015452825834242088>"
EMOJI_LUPA: str = "<:SM_Lupa:1020191899258204160>"
EMOJI_LOADING: str = "<:Loading:1514474322721378304>"
EMOJI_LOADING_ERROR: str = "<:LoadingError:1513758425115394048>"
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
# Veredictos añadidos con la separación nsfw/restringido y el detector anti-phishing.
# `Flag` es una bandera con el signo rojo: "prohibido", que es el vocabulario que
# Discord usa para el contenido restringido por edad (alcohol, armas).
EMOJI_RESTRINGIDO: str = "<:Flag:1555092175547801670>"
EMOJI_PHISHING: str = "<:Phishing:1555091633865760808>"
# "El nombre del archivo no cuadra con su contenido": doble extensión, o extensión que
# no corresponde a los bytes. NO es el de malware (`EMOJI_WARNING`): aquí no hay ninguna
# detección, solo un nombre que no dice lo que es.
#
# Antes usaba `EMOJI_REPLY`, que es una flecha de "responder" y no significa nada en
# este contexto. La huella encaja mejor: el archivo declara una identidad y es otra.
# Cámbiala por un emoji propio cuando quieras, igual que Flag y Phishing.
EMOJI_NOMBRE_SOSPECHOSO: str = EMOJI_FINGERPRINT

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
ANTISPAM_WINDOW: int = 3600

# Cuotas de las APIs externas. Fuente única de verdad: la consumen api/virustotal.py
# para aplicar los límites y cogs/stats.py para mostrarlos.
#
# Valores del plan gratuito, que es el que usa este bot. Si algún día se paga, los
# límites cambian y hay que tocar aquí.
#
# VirusTotal Public API: 4 req/min, 500 req/día por key (reset 00:00 UTC). Una sola
# URL puede costar hasta 5 requests (GET, POST, 2 sondeos y verificación final), así
# que el techo realisticamente son ~100 enlaces nuevos al día, no 500.
VT_MAX_ANALYSES_PER_MINUTE: int = 4
VT_MAX_ANALYSES_PER_DAY: int = 500
# Coste máximo de un análisis de URL, para poder razonar sobre la cuota sin surprises.
VT_REQUESTS_POR_URL_MAX: int = 5

# SightEngine Free: 2.000 operaciones/mes con tope duro de 500/día, 1 req/s. Cada
# modelo pedido en una misma llamada cuenta como una operación, así que una imagen
# consume SE_OPS_PER_CALL unidades.
#
# OJO con el orden de magnitud: el tope que manda es el MENSUAL, no el diario. Con 5
# modelos salen 2.000/5 = 400 imágenes al mes, unas 13 al día. Con los 4 modelos de
# antes eran 500 al mes. El cambio a 5 modelos cuesta un 20% de capacidad a cambio de
# detectar gore, que antes no se miraba.
SE_MAX_OPS_PER_MONTH: int = 2000
SE_MAX_OPS_PER_DAY: int = 500
SE_MAX_REQUESTS_PER_SECOND: int = 1
# Derivado de la lista real de modelos: cada uno pedido en la misma llamada cuenta como
# una operación. Con `nudity-2.1,weapon,alcohol,gore-2.0,offensive` son 5, así que el
# plan gratuito da 500/5 = 100 imágenes al día, no 125.
SE_OPS_PER_CALL: int = len(SIGHTENGINE_MODELS.split(","))
SE_MAX_REQUESTS_PER_MINUTE: int = 4

IMAGE_EXTENSIONS: list[str] = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic', '.heif']

OWNER_ID: Optional[str] = os.getenv("OWNER_ID")
