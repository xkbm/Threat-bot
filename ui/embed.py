"""Constructor único de embeds de Threat.

Reglas del sistema:
  - Todos los embeds llevan el escudo (EMOJI_SHIELD, emoji personalizado del bot) en
    el título. Los emojis personalizados solo renderizan donde Threat está presente, así
    que un embed suyo es reconocible al instante: no se usa ningún emoji unicode.
  - Todos llevan pie: "Threat · <contexto> · <fecha UTC>".
  - El color solo codifica severidad. Los embeds informativos van todos en COLOR_NEUTRAL.
  - Los títulos van en sentence case y el vocabulario de errores está cerrado en tres.
  - Los nombres de campo salen de un vocabulario fijo, sin excepciones por embeds.

Este módulo solo importa `discord` y `core.config` a propósito: la capa de caché
(core/database.py, core/cache.py) lo usa para renderizar al leer, así que cualquier
dependencia de core.utils o de api/ crearía un ciclo de imports.

`resultado()` debe permanecer PURA: mismos `datos` -> mismo embed, sin I/O ni estado global.
"""

import time
from typing import Optional

import discord

from core.config import (
    COLOR_NEUTRAL, COLOR_SEGURO, COLOR_MALICIOSO, COLOR_SOSPECHOSO, COLOR_ERROR, COLOR_NSFW, COLOR_TOPGG,
    SEVERIDAD_COLOR,
    EMOJI_SHIELD, EMOJI_FILE, EMOJI_FINGERPRINT, EMOJI_GUARDIAN, EMOJI_LINK, EMOJI_NSFW,
)

MARCA = "Threat"

# ============================================================================
# Vocabulario de títulos. Los valores de la izquierda están PROHIBIDOS: un test
# parametrizado los busca en el código y falla si alguno reaparece.
#
# Sentence case: se capitaliza la primera palabra y los ACRÓNIMOS (URL, IP, NSFW,
# API). El resto en minúscula. "Hash" y "archivo" son palabras comunes, no nombres
# propios, así que solo la inicial de "Hash" se capitaliza por ser la primera.
# ============================================================================
TITULOS: dict[str, str] = {
    # resultados
    "url_maliciosa": "URL maliciosa detectada",
    "url_sospechosa": "URL sospechosa",
    "url_segura": "URL segura",
    "hash_malicioso": "Hash malicioso detectado",
    "hash_sospechoso": "Hash sospechoso",
    "hash_seguro": "Hash seguro",
    "ip_maliciosa": "IP maliciosa detectada",
    "ip_sospechosa": "IP sospechosa",
    "ip_segura": "IP segura",
    "archivo_malicioso": "Archivo malicioso detectado",
    "archivo_sospechoso": "Archivo sospechoso",
    "archivo_seguro": "Archivo seguro",
    # errores (los tres únicos permitidos)
    "error_analisis": "Error de análisis",
    "error_conexion": "Error de conexión",
    "error_cuota": "Límite de API alcanzado",
    # avisos
    "nsfw": "Contenido NSFW detectado",
    "amenaza": "Amenaza detectada",
}

# Siglas que sí van en mayúscula dentro de los títulos.
ACRONIMOS: frozenset[str] = frozenset({"URL", "IP", "NSFW", "API", "AGPL"})

# Estos son los títulos antiguos que el rediseño elimina. El test de guardia falla si
# alguno vuelve a aparecer en un título de embed.
TITULOS_PROHIBIDOS: tuple[str, ...] = (
    "URL Maliciosa Detectada",
    "URL Segura",
    "Hash Malicioso Detectado",
    "Hash Seguro",
    "IP Maliciosa Detectada",
    "IP Segura",
    "Archivo Malicioso Detectado",
    "Archivo Seguro",
    "Amenaza Detectada",
    "Contenido NSFW Detectado",
    "Sin cuota de API",
    "Hash no encontrado",
    "IP no encontrada",
    "Archivo demasiado grande",
)

# ============================================================================
# Pie y marca
# ============================================================================

def _truncar(texto: str, limite: int = 60) -> str:
    texto = " ".join(str(texto).split())
    return texto if len(texto) <= limite else texto[: limite - 1] + "…"


def pie(embed: discord.Embed, contexto: str, avatar_url: Optional[str] = None) -> discord.Embed:
    """Añade el pie de marca. Siempre es el último paso al construir un embed."""
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    partes = [MARCA]
    if contexto:
        partes.append(_truncar(contexto))
    partes.append(stamp)
    embed.set_footer(text=" · ".join(partes))
    if avatar_url:
        embed.set_thumbnail(url=avatar_url)
    return embed


def titulo(texto: str) -> str:
    """Prefija el título con la marca. Todo título de Threat pasa por aquí."""
    return f"{EMOJI_SHIELD} {texto}"


ETIQUETA_INFORME = "Informe"


def enlace_informe(url: Optional[str], con_emoji: bool = True) -> str:
    """Enlace al informe de VirusTotal, siempre con la misma etiqueta.

    Antes el mismo enlace se etiquetaba de cuatro formas distintas ("Ver informe
    completo", "Ver informe", "VT" y el nombre del campo "VirusTotal"), lo que
    obligaba a leerlo cuatro veces para saber que era lo mismo. Ahora hay una sola,
    y quien lo lea tiene una referencia constante.
    """
    if not url:
        return ""
    icono = f"{EMOJI_LINK} " if con_emoji else ""
    return f"{icono}[{ETIQUETA_INFORME}]({url})"


def _nuevo(texto_titulo: str, color: int, descripcion: str = "") -> discord.Embed:
    return discord.Embed(title=titulo(texto_titulo), description=descripcion or None, color=discord.Color(color))


# ============================================================================
# Resultados de análisis. Se renderizan al leer desde la caché, así que es pura.
# ============================================================================

_ETIQUETA_ELEMENTO = {"url": "URL", "hash": "Hash", "ip": "IP", "file": "Archivo"}

_TITULO_RESULTADO = {
    ("url", "malicioso"): TITULOS["url_maliciosa"],
    ("url", "sospechoso"): TITULOS["url_sospechosa"],
    ("url", "seguro"): TITULOS["url_segura"],
    ("hash", "malicioso"): TITULOS["hash_malicioso"],
    ("hash", "sospechoso"): TITULOS["hash_sospechoso"],
    ("hash", "seguro"): TITULOS["hash_seguro"],
    ("ip", "malicioso"): TITULOS["ip_maliciosa"],
    ("ip", "sospechoso"): TITULOS["ip_sospechosa"],
    ("ip", "seguro"): TITULOS["ip_segura"],
    ("file", "malicioso"): TITULOS["archivo_malicioso"],
    ("file", "sospechoso"): TITULOS["archivo_sospechoso"],
    ("file", "seguro"): TITULOS["archivo_seguro"],
}


def _veredicto_de(datos: dict, mal: int) -> str:
    """Veredicto del análisis, tal y como se guarda en caché.

    Se lee de `datos` y no se deduce solo de `mal` porque un elemento con 0 detecciones
    maliciosas y varias sospechosa sigue sin estar limpio, y ese matiz se pierde si solo
    guardamos el número. Viaja dentro de `datos` —que es lo que se persiste y se
    re-renderiza al leer— para que una entrada cacheada siga mostrando su veredicto
    aunque el diseño cambie dentro de seis meses.

    El `mal > 0` es el respaldo para las filas antiguas de SQLite, que se guardaron sin
    `veredicto`, y para las entradas que nunca se han reanalizado.

    Lo que NO se hace es inventar. Antes, un veredicto que esta función no conocía
    (los nuevos: `restringido`, `phishing`, `ignorado`) caía en
    `"malicioso" if mal > 0 else "seguro"`. Eso producía dos自主品牌 bugs:
    una imagen con alcohol marcada como malware, y un `error` (que es "no se pudo
    comprobar") pintado de verde como "Sin detecciones". Es exactamente el fallo que
    `core.veredictos` declara el peor posible.
    """
    # Se valida contra el enum: un valor corrupto en la fila no puede colarse hasta el
    # título del embed ni romper el render.
    from core.veredictos import Veredicto

    guardado = datos.get("veredicto")
    if guardado:
        try:
            return Veredicto(str(guardado)).value
        except ValueError:
            pass          # valor desconocido: al respaldo de abajo
    if "error" in datos:
        return "error"
    return "malicioso" if mal > 0 else "seguro"


def resultado(tipo: str, datos: dict, mal: int) -> discord.Embed:
    """Embed de resultado de análisis.

    `tipo` es "url" | "hash" | "ip" | "file". `datos` lleva lo mínimo para poder
    re-renderizar sin volver a llamar a la API:
        valor     -> el elemento analizado (URL, hash, IP o nombre de archivo)
        vt_link   -> enlace al informe de VirusTotal (opcional)
        top_text  -> antivirus que lo detectaron, ya formateado (opcional)
        veredicto -> "malicioso" | "sospechoso" | "seguro" (opcional, ver arriba)
        susp      -> cuántos engines lo marcan como sospechoso (opcional)
    """
    veredicto = _veredicto_de(datos, mal)
    texto = _TITULO_RESULTADO.get((tipo, veredicto), "Resultado del análisis")
    embed = _nuevo(texto, SEVERIDAD_COLOR.get(veredicto, COLOR_NEUTRAL))
    if veredicto == "malicioso":
        embed.description = f"**{mal}** detecciones"
    elif veredicto == "sospechoso":
        embed.description = f"**{datos.get('susp', 0)}** engines lo marcan como sospechoso"
    else:
        embed.description = "Sin detecciones"

    valor = str(datos.get("valor", ""))
    etiqueta = _ETIQUETA_ELEMENTO.get(tipo, "Elemento")
    icono_elemento = EMOJI_FILE if tipo == "file" else EMOJI_FINGERPRINT
    embed.add_field(name=f"{icono_elemento} {etiqueta}", value=f"`{valor}`", inline=False)

    if datos.get("top_text"):
        embed.add_field(name=f"{EMOJI_GUARDIAN} Detectado por", value=f"`{datos['top_text']}`", inline=False)

    if datos.get("vt_link"):
        # El nombre del campo ya dice de dónde viene; el valor solo lleva la acción.
        embed.add_field(name=f"{EMOJI_LINK} VirusTotal", value=enlace_informe(datos["vt_link"], con_emoji=False), inline=False)

    return pie(embed, f"{etiqueta} · {veredicto}")


# ============================================================================
# Errores. Vocabulario cerrado de tres.
# ============================================================================

def error(texto: str, descripcion: str, detalle: Optional[str] = None, icono: str = EMOJI_SHIELD) -> discord.Embed:
    """Error con el vocabulario cerrado. El icono por defecto es el escudo de marca:
    la severidad ya la comunica el color rojo y el texto, así que el icono del título
    se reserva para la identidad. `icono` existe para los casos que síQuieres otra cosa."""
    embed = discord.Embed(
        title=f"{icono} {texto}",
        description=descripcion,
        color=discord.Color(COLOR_ERROR),
    )
    if detalle:
        embed.add_field(name="Detalle", value=_truncar(detalle, 200), inline=False)
    return pie(embed, texto)


def error_analisis(descripcion: str, detalle: Optional[str] = None) -> discord.Embed:
    return error(TITULOS["error_analisis"], descripcion, detalle)


def error_conexion(descripcion: str, detalle: Optional[str] = None) -> discord.Embed:
    return error(TITULOS["error_conexion"], descripcion, detalle)


def error_cuota(espera: Optional[int] = None) -> discord.Embed:
    detalle = None
    if espera:
        minutos, segs = divmod(max(0, int(espera)), 60)
        detalle = f"Disponible en {minutos}m {segs}s" if minutos else f"Disponible en {segs}s"
    return error(
        TITULOS["error_cuota"],
        "Se alcanzó el límite de peticiones de la API de análisis.",
        detalle,
    )


# ============================================================================
# Avisos e información. Siempre en gris: sin veredicto, sin color de severidad.
# ============================================================================

def aviso(texto: str, descripcion: str = "", campos: Optional[list[tuple[str, str, bool]]] = None,
          color: int = COLOR_NEUTRAL, icono: str = EMOJI_SHIELD, con_pie: bool = True,
          avatar_url: Optional[str] = None, pie_texto: Optional[str] = None) -> discord.Embed:
    """Embed informativo. `campos` es una lista de (nombre, valor, inline).

    `con_pie=False` se usa cuando el embed se completa más abajo y el pie se añade
    al final, con un contexto que ya incluye los contadores.

    `pie_texto` sustituye el pie por defecto. Lo usa el panel de ajustes, cuyo mensaje
    es efímero y no se actualiza al reiniciar el bot: sin una marca de tiempo no hay forma
    de distinguir un panel viejo de uno actual.
    """
    embed = discord.Embed(
        title=f"{icono} {texto}",
        description=descripcion or None,
        color=discord.Color(color),
    )
    for nombre, valor, inline in (campos or []):
        embed.add_field(name=nombre, value=valor, inline=inline)
    if pie_texto is not None:
        return pie(embed, pie_texto, avatar_url)
    return pie(embed, texto, avatar_url) if con_pie else embed


def enlace_mensaje(guild_id: Optional[int], channel_id: Optional[int],
                   message_id: Optional[int]) -> str:
    """Enlace al mensaje original, o "" si no hay mensaje al que ir.

    No es un adorno: el log de amenaza es un registro, y un registro sin el mensaje al
    que se refiere obliga a buscarlo a mano. Se usa la misma etiqueta fija que el informe
    de VirusTotal para que quien lee los dos enlaces no tenga que descifrar dos formatos.

    Se devuelve "" cuando falta cualquier parte del identificador, sobre todo cuando el
    mensaje fue borrado: un enlace a un mensaje que ya no existe no ayuda a nadie, y
    manda al moderador a una pantalla de "mensaje no encontrado".
    """
    if not guild_id or not channel_id or not message_id:
        return ""
    return (f"{EMOJI_LINK} "
            f"[Mensaje](https://discord.com/channels/{guild_id}/{channel_id}/{message_id})")


def nsfw(tipo: str, valor: str, detalles: str, usuario: discord.abc.User,
         mensaje: str = "") -> discord.Embed:
    """Log de contenido NSFW o restringido.

    El usuario es obligatorio a propósito: es el canal donde se decide si se banea o
    expulsa a alguien, y antes este embed salía sin él. Los botones de Ban/Kick ya
    apuntaban al autor correcto, así que el moderador tenía botones para banear a alguien
    que el propio log no nombraba. Sin eso no se puede ni leer ni copiar el ID.

    Va en la misma forma que `amenaza` a propósito: un moderador que lee los dos no tiene
    que aprender dos formatos.
    """
    embed = _nuevo(TITULOS["nsfw"], COLOR_NSFW, f"**{tipo}** con contenido NSFW")
    embed.add_field(name=f"{EMOJI_NSFW} Elemento", value=f"```{valor}```", inline=False)
    embed.add_field(name=f"{EMOJI_GUARDIAN} Usuario", value=usuario.mention, inline=True)
    if detalles:
        embed.add_field(name=f"{EMOJI_SHIELD} Detectado por", value=detalles, inline=True)
    # El ID explícito se perdería al mover el pie al formato de marca, y quien modera lo
    # necesita para herramientas de moderación y para comprobar si es la misma persona.
    embed.add_field(name="ID", value=f"`{usuario.id}`", inline=True)
    if mensaje:
        embed.add_field(name="Origen", value=mensaje, inline=False)
    return pie(embed, f"NSFW · {tipo}")


# Cómo se describe cada veredicto en el log de amenaza. Antes `emb.amenaza` escribía
# "resultó malicioso" en el texto y lo clavaba para TODO lo que no fuera NSFW, así que una
# foto con una cerveza salía como "CONTENIDO RESTRINGIDO resultó malicioso" con un botón
# de banear. Un moderador que se fiara del texto podía banear a alguien por una cerveza.
#
# El veredicto es la verdad y el texto tiene que salir de él, no al revés.
_HEADLINE = {
    "malicioso": "resultó **malicioso**",
    "restringido": "es contenido **restringido**",
    "sospechoso": "resultó **sospechoso**",
}
_COLOR_POR_VEREDICTO = {
    "malicioso": COLOR_ERROR,
    "restringido": COLOR_MALICIOSO,
    "sospechoso": COLOR_SOSPECHOSO,
}


def amenaza(tipo: str, valor: str, detalles: str, usuario: discord.abc.User,
            vt_link: Optional[str] = None, veredicto: str = "malicioso",
            mensaje: str = "") -> discord.Embed:
    """Log de amenaza enviado al canal del servidor. Es el embed más crítico:
    aquí se toman acciones de moderación, así que el valor va en un code block
    para que un atacante no pueda inyectar markdown ni romper la maquetación."""
    headline = _HEADLINE.get(veredicto, _HEADLINE["malicioso"])
    color = _COLOR_POR_VEREDICTO.get(veredicto, COLOR_ERROR)
    embed = _nuevo(TITULOS["amenaza"], color, f"**{tipo.upper()}** {headline}")
    embed.add_field(name=f"{EMOJI_FINGERPRINT} Valor", value=f"```{valor}```", inline=False)
    embed.add_field(name=f"{EMOJI_GUARDIAN} Usuario", value=usuario.mention, inline=True)
    embed.add_field(name=f"{EMOJI_SHIELD} Detalles", value=detalles, inline=True)
    # El ID explícito se perdería al mover el pie al formato de marca, y quien modera
    # lo necesita para copiar y pegar en herramientas de moderación.
    embed.add_field(name="ID", value=f"`{usuario.id}`", inline=True)
    if vt_link:
        embed.add_field(name=f"{EMOJI_LINK} VirusTotal", value=enlace_informe(vt_link, con_emoji=False), inline=False)
    if mensaje:
        embed.add_field(name="Origen", value=mensaje, inline=False)
    return pie(embed, f"Amenaza · {tipo}")


def topgg(mensaje: str) -> discord.Embed:
    return aviso("Eres parte de la comunidad", mensaje, color=COLOR_TOPGG)


def resultado_barra(porcentaje: float, total: int, limite: int) -> str:
    """Barra de progreso compartida entre /stats y los avisos de cuota."""
    largo = 10
    llenos = int(largo * min(100.0, max(0.0, porcentaje)) / 100)
    return f"{'█' * llenos}{'░' * (largo - llenos)} **{porcentaje:.0f}%** ({total}/{limite})"


__all__ = [
    "MARCA", "TITULOS", "TITULOS_PROHIBIDOS", "ACRONIMOS", "ETIQUETA_INFORME",
    "pie", "titulo", "resultado", "error", "error_analisis", "error_conexion",
    "error_cuota", "aviso", "nsfw", "amenaza", "topgg", "resultado_barra", "enlace_informe",
    "COLOR_NEUTRAL", "COLOR_SEGURO", "COLOR_MALICIOSO", "COLOR_SOSPECHOSO", "COLOR_ERROR", "COLOR_NSFW",
    "COLOR_TOPGG", "SEVERIDAD_COLOR",
]
