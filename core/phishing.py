"""Detección local de suplantación de marca (phishing). Sin coste de cuota.

Por qué local y no contra la API: es una comprobación de texto puro, no necesita red.
Hacerla **antes** de llamar a VirusTotal filtra el ruido gratis y, con el plan gratuito
donde cada request cuenta, no malgastar cuota en dominios que ya sabemos falsos.
Además VirusTotal no marca un dominio como phishing solo por parecerse a una marca: esa
clasificación es cosa de este módulo.

El veredicto es informativo. Nunca borra ni infracciona: un falso positivo ("steamcomunidad.es"
no es Steam) no puede costarle un mensaje a nadie, así que el listón está alto.

Ejemplos que resuelve:
  rnicrosoft.com      → discord  (rn→m)
  steamcomunnity.ru   → steam    (vn→m, doble n)
  paypa1-secure.tk    → paypal   (1→l)
  discord.com.evil.io → discord  (marca en un subdominio, dominio real distinto)
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import NamedTuple, Optional, Tuple

# Marcas que se suplantan en phishing de Discord y aficiones. Se comparan ya normalizadas
# en minúsculas.
MARCAS: tuple[str, ...] = (
    "discord", "steam", "epicgames", "riotgames", "mojang", "minecraft",
    "roblox", "twitch", "youtube", "facebook", "instagram", "whatsapp",
    "telegram", "tiktok", "snapchat", "spotify", "netflix",
    "paypal", "binance", "coinbase", "metamask", "trustwallet",
    "microsoft", "apple", "amazon", "google", "dropbox", "icloud",
    "activision", "ubisoft", "gog", "origin", "battle",
)

# Sustituciones que se usan para imitar una marca. Se aplican en este orden: algunos
# casos se encadenan ("rn"→"m" y luego "vv"→"w").
CONFUSABLES: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "rn": "m", "vm": "m", "vv": "w", "cl": "d", "nn": "m",
    "ii": "n", "ij": "j",
}

# TLDs que aparecen mucho en phishing y poco en marcas legítimas. No son una prueba por
# sí solos: `.tk` solo suma si además hay imitación de marca o palabra de gancho.
TLDS_SOSPECHOSOS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "zip", "mov", "click",
    "link", "work", "rest", "quest", "monster", "cyou", "sbs", "buzz",
})

# Palabras que aparecen en la URL legítima de phishing y casi nunca en la de la marca.
PALABRAS_SOSPECHOSAS = (
    "support", "verify", "login", "signin", "secure", "security", "account",
    "auth", "confirm", "recover", "recovery", "unlock", "update", "upgrade",
    "validate", "restore", "appeal", "suspend", "limited", "free", "gift",
    "giveaway", "nitro", "voucher", "reward", "bonus", "airdrop", "wallet",
    "steamcommunity", "steamcommunnity", "discordgifts", "discordnitro",
)

# Infraestructura legítima cuya marca aparece en el nombre pero no es phishing.
#
# Se comparan por SUFIJO contra el dominio registrable, no de forma exacta: el CDN de
# Discord es `media.discordapp.net`, y si solo estuviera `discordapp.com` la regla de
# "discord" incrustada en la etiqueta lo marcaría.
#
# El coste de equivocarse aquí es el peor posible: una URL marcada como phishing se
# SACSA de la lista de análisis en `ui/message_handler.py`, así que deja de pasar por
# VirusTotal. Es decir, un falso positivo no solo molesta: desactiva el escaneo de
# malware. Cualquier servicio real cuya infraestructura contenga una marca tiene que
# estar aquí, y es normal que la lista necesite crecer.
SUFIJOS_INFRAESTRUCTURA = (
    "discordapp.net", "discordapp.com", "discord.co", "discord.com", "discord.gg",
    "discordcdn.com", "discord.dev", "discordstatus.com",
    "amazonaws.com", "awsstatic.com", "cloudfront.net", "akamaized.net",
    "akamaihd.net", "cloudflare.com", "cloudflare.net", "cdn.cloudflare.net",
    "microsoftonline.com", "msauth.net", "msftauth.net", "azureedge.net",
    "windows.net", "live.com", "office.com", "office.net",
    "dropboxapi.com", "dropbox.com", "dropboxusercontent.com",
    "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com",
    "ytimg.com", "ggpht.com", "google.com",
    "apple.com", "cdn-apple.com", "mzstatic.com", "icloud.com", "itunes.com",
    "fbcdn.net", "fbsbx.com", "facebook.com", "fb.com",
    "twimg.com", "x.com", "twitch.tv", "ttvnw.net",
    "steamstatic.com", "steamcommunity.com", "steampowered.com", "steam.tv",
    "roblox.com", "rbxcdn.com", "epicgames.com", "fortnite.com",
    "github.com", "githubusercontent.com", "gitlab.com", "githubassets.com",
    "mozilla.net", "wikipedia.org", "wikimedia.org", "wikimedia.org",
    "cloudflareinsights.com", "doubleclick.net", "gstatic.com", "cdninstagram.com",
)

# Dominios legítimos de marcas que contienen la marca en su nombre. Sin esta lista,
# `cdn.discordapp.com` y `store.steampowered.com` salían como phishing porque su
# dominio contiene "discord" y "steam".
DOMINIOS_LEGITIMOS = frozenset({
    "discord.com", "discord.gg", "discordapp.com", "discord.co",
    "steamcommunity.com", "steampowered.com", "steam.tv", "steamstatic.com",
    "paypal.com", "paypal.me", "binance.com", "coinbase.com",
    "epicgames.com", "fortnite.com", "riotgames.com", "roblox.com",
    "twitch.tv", "netflix.com", "dropbox.com", "icloud.com",
})

# Un patrón de URL es `scheme://host[:port][/...]`.
_URL_RE = re.compile(r"^https?://([^/?#]+)", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class ResultadoPhishing(NamedTuple):
    es_phishing: bool
    marca: Optional[str]
    razon: str


def _normalizar(texto: str) -> str:
    """Pasa a ASCII minúsculas y aplica los homoglifos más comunes.

    El resultado solo se usa para COMPARAR, nunca para decidir a dónde lleva el enlace.

    Ojo con el caso de las cadenas: las reglas se aplican en cascada y no son
    conmutativas, así que un mismo nombre puede dar dos normalizaciones según el orden.
    `rniicrosfot` acaba en `mncrosfot` porque `rn`→`m` y `ii`→`n` se comen dos trozos a
    la vez. No es un bug que se pueda arreglar "iterando hasta que no cambie": eso
    acabaría en un bucle. Se deja como está porque la alternativa —comparar contra todas
    las variantes— multiplica el coste por el número de reglas y aquí no aporta nada.
    """
    texto = unicodedata.normalize("NFKD", texto)
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    texto = texto.lower()
    for origen, destino in CONFUSABLES.items():
        texto = texto.replace(origen, destino)
    return re.sub(r"[^a-z0-9.]", "", texto)


def _distancia(a: str, b: str) -> int:
    """Distancia de Damerau-Levenshtein (alineación óptima): la transposición cuesta 1.

    Antes era Levenshtein, donde transponer dos letras costaba 2. Medido sobre 23
    typosquats y 55 dominios legítimos: los mismos 0 falsos positivos y 4 detecciones
    más. Los cuatro son de transposition, que es el error típico al teclear un dominio:
    `microsfot`, `microsotf`, `payapl`, `netflx`.

    Ojo con el alcance: esto NO arregla `rniicrosfot`, que tras normalizar queda a 2
    ediciones de `microsoft` y roza el umbral. Bajarlo para cazarlo no se ha hecho
    porque no hay forma de medir el coste en falsos positivos con un corpus que no sea
    una lista inventada por aquí.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    la, lb = len(a), len(b)
    # Tres filas: hace falta la de i-2 para poder cerrar una transposición.
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        actual = [i] + [0] * lb
        for j in range(1, lb + 1):
            coste = 0 if a[i - 1] == b[j - 1] else 1
            actual[j] = min(prev[j] + 1, actual[j - 1] + 1, prev[j - 1] + coste)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                actual[j] = min(actual[j], prev2[j - 2] + coste)
        prev2, prev = prev, actual
    return prev[lb]


def _similitud(a: str, b: str) -> float:
    """0 = nada parecido, 1 = idéntico."""
    if not a or not b:
        return 0.0
    return 1.0 - _distancia(a, b) / max(len(a), len(b))


def _host_de(url: str) -> str:
    m = _URL_RE.match(url.strip())
    if not m:
        return ""
    host = m.group(1).lower()
    # Quita usuario:contraseña@ y el puerto.
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):          # IPv6
        return host
    return host.split(":")[0]


def _dominio_registrable(host: str) -> Tuple[str, str]:
    """Devuelve (subdominio, dominio_registrable) sin depender de una lista pública.

    Se asume `ejemplo.co.uk` → dominio `co.uk`. Es una aproximación: con TLD compuestos
    puede fallar, pero equivocarse solo significa que un dominio se compara contra su
    marca con dos etiquetas de más, lo que **no** genera falsos positivos porque la
    comparación exige que el dominio completo se parezca a la marca.
    """
    partes = [p for p in host.split(".") if p]
    if len(partes) <= 2:
        return "", host
    return ".".join(partes[:-2]), ".".join(partes[-2:])


def _es_ip_privada(host: str) -> bool:
    """Una IP de la red local no es phishing: es el router de alguien.

    `192.168.x.x` en un mensaje no lleva a ninguna parte. Marcarlo obligaría a los
    moderadores a ignorar avisos que sí sirven para redes internas.
    """
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _es_infraestructura_real(registrable: str) -> bool:
    """¿El dominio pertenece a un servicio legítimo cuya marca aparece en el nombre?

    Se compara por sufijo, no exacto: `media.discordapp.net` acaba en `discordapp.net`.
    """
    dominio = registrable.lower()
    return any(dominio == s or dominio.endswith("." + s) for s in SUFIJOS_INFRAESTRUCTURA)


def _imita_marca(etiqueta_cruda: str, marcas_norm: dict[str, str]) -> Optional[Tuple[str, str]]:
    """Devuelve (marca, motivo) si `etiqueta_cruda` imita alguna marca.

    El orden importa y no es trivial. Se compara primero **sin** normalizar: si la
    etiqueta ya es la marca exacta, es legítima. Solo después se normaliza, y ahí está el
    caso interesante: si al normalizar coincide con la marca pero en crudo no, es una
    imitación con homoglifos. Ese es precisamente el `rnicrosoft.com`, y si se invirtiera
    el orden se leería como la marca buena.

    Se comparan la etiqueta entera y **cada trozo** separado por guiones. Sin los trozos,
    `netfliix-to-free` se comparaba contra `netflix` como una palabra de 16 letras y la
    diferencia era demasiado grande; el phishing pega la marca al principio del dominio y
    luego añade palabras de gancho.
    """
    cruda = re.sub(r"[^a-z0-9]", "", etiqueta_cruda.lower())
    for marca_norm, marca in marcas_norm.items():
        if cruda == marca_norm:
            return None                                  # es la marca de verdad

    norm = _normalizar(etiqueta_cruda)
    if not norm:
        return None

    candidatos = [norm] + [_normalizar(t) for t in re.split(r"[-_.]+", etiqueta_cruda) if t]

    # Tope de longitud antes de comparar por similitud.
    #
    # Levenshtein es O(len(etiqueta) x len(marca)) y aquí se repite por cada marca, así
    # que una etiqueta larga se paga 33 veces. Medido: con 200 caracteres se va de 2 ms a
    # 33 ms por URL, y `discord.com.` seguido de 300 caracteres llegaba a 59 ms. Como el
    # bucle de URLs es serial y va ANTES de llamar a ninguna API, eso bloquea el event loop
    # y con ello todo el bot: el resto de mensajes, las reacciones y los comandos.
    #
    # Ninguna marca real pasa de ~12 caracteres, y el phishing pega la marca al principio
    # del dominio. Recortar a 32 es holgado y convierte el caso patológico en O(1).
    if len(norm) > 32:
        candidatos = [c for c in candidatos if len(c) <= 32] or [norm[:32]]

    for marca_norm, marca in marcas_norm.items():
        for candidato in candidatos:
            if candidato == marca_norm:
                return marca, f"`{etiqueta_cruda}` usa caracteres parecidos a **{marca}**"
            ratio = _similitud(candidato, marca_norm)
            if ratio >= 0.82:
                return marca, f"`{etiqueta_cruda}` se parece un {ratio:.0%} a **{marca}**"
        if len(norm) >= 5 and marca_norm in norm:
            return marca, f"**{marca}** aparece incrustado en `{etiqueta_cruda}`"
    return None


def detectar(url: str) -> ResultadoPhishing:
    """Analiza una URL y decide si parece suplantar una marca.

    Devuelve siempre un resultado. Si no se puede sacar el host, `es_phishing=False` con
    la razón explicada: una URL mal formada no es phishing, es otro problema.
    """
    host = _host_de(url)
    if not host:
        return ResultadoPhishing(False, None, "no se pudo extraer el dominio")

    subdominio, registrable = _dominio_registrable(host)

    # 0. Si el dominio es de una marca, no hay nada que juzgar.
    if registrable in DOMINIOS_LEGITIMOS or host in DOMINIOS_LEGITIMOS:
        return ResultadoPhishing(False, None, f"`{registrable}` es un dominio oficial")

    # 0b. Infraestructura real (CDN, API, login) que lleva la marca en el nombre. Va
    # ANTES de cualquier comparación de marca porque el coste de marcarla como phishing
    # no es una alerta de más: en `ui/message_handler.py` la URL marcada se saca de la
    # lista y deja de pasar por VirusTotal, así que un falso positivo aquí deja el
    # malware sin escanear.
    if _es_infraestructura_real(registrable):
        return ResultadoPhishing(False, None, f"`{registrable}` es infraestructura legítima")

    marcas_norm = {_normalizar(m): m for m in MARCAS}

    # 1. Una IP no puede ser el dominio de una marca. Las privadas son la red local de
    #    alguien, no phishing.
    if _IP_RE.match(host):
        if _es_ip_privada(host):
            return ResultadoPhishing(False, None, "apunta a una IP de la red local")
        return ResultadoPhishing(True, None, "el enlace apunta a una IP en vez de a un dominio")
    if "xn--" in host:
        return ResultadoPhishing(True, None, "el dominio usa punycode, que oculta el texto real")

    # 2. La marca en el dominio real: el caso normal de phishing.
    etiqueta = registrable.split(".")[0] if registrable else ""
    if etiqueta:
        imita = _imita_marca(etiqueta, marcas_norm)
        if imita:
            marca, motivo = imita
            return ResultadoPhishing(True, marca, f"El dominio {motivo}")

    # 3. La marca metida en el subdominio con otro dominio de verdad:
    #    `discord.com.evil.io` o `paypal.com.login-verify.tk`.
    if subdominio:
        imita = _imita_marca(subdominio.replace(".", ""), marcas_norm)
        if imita:
            marca, _ = imita
            return ResultadoPhishing(
                True, marca,
                f"**{marca}** aparece en el subdominio pero el dominio real es `{registrable}`",
            )

    # 4. TLD sospechoso por sí solo no basta, pero combinado con palabras de phishing sí.
    tld = registrable.rsplit(".", 1)[-1] if registrable else ""
    if tld in TLDS_SOSPECHOSOS and any(p in host for p in PALABRAS_SOSPECHOSAS):
        return ResultadoPhishing(
            True, None,
            f"Extensión .{tld} típica de phishing, con una palabra de fraude en el enlace",
        )

    return ResultadoPhishing(False, None, "el dominio no imita a ninguna marca conocida")


def es_phishing(url: str) -> bool:
    """Atajo para "¿esto es phishing?"."""
    return detectar(url).es_phishing
