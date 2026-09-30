"""Constructor único de embeds de Threat.

Reglas del sistema:
  - Todos los embeds llevan el prefijo de marca 🛡️ en el título.
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
    COLOR_NEUTRAL, COLOR_SEGURO, COLOR_MALICIOSO, COLOR_ERROR, COLOR_NSFW, COLOR_TOPGG,
    SEVERIDAD_COLOR,
    EMOJI_SHIELD, EMOJI_FILE, EMOJI_FINGERPRINT, EMOJI_GUARDIAN, EMOJI_LINK, EMOJI_NSFW,
    EMOJI_KEY, EMOJI_CORRECTO, EMOJI_WARNING, EMOJI_INCORRECTO,
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
    "url_segura": "URL segura",
    "hash_malicioso": "Hash malicioso detectado",
    "hash_seguro": "Hash seguro",
    "ip_maliciosa": "IP maliciosa detectada",
    "ip_segura": "IP segura",
    "archivo_malicioso": "Archivo malicioso detectado",
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


def _nuevo(texto_titulo: str, color: int, descripcion: str = "") -> discord.Embed:
    return discord.Embed(title=titulo(texto_titulo), description=descripcion or None, color=discord.Color(color))


# ============================================================================
# Resultados de análisis. Se renderizan al leer desde la caché, así que es pura.
# ============================================================================

_ETIQUETA_ELEMENTO = {"url": "URL", "hash": "Hash", "ip": "IP", "file": "Archivo"}

_TITULO_RESULTADO = {
    ("url", "malicioso"): TITULOS["url_maliciosa"],
    ("url", "seguro"): TITULOS["url_segura"],
    ("hash", "malicioso"): TITULOS["hash_malicioso"],
    ("hash", "seguro"): TITULOS["hash_seguro"],
    ("ip", "malicioso"): TITULOS["ip_maliciosa"],
    ("ip", "seguro"): TITULOS["ip_segura"],
    ("file", "malicioso"): TITULOS["archivo_malicioso"],
    ("file", "seguro"): TITULOS["archivo_seguro"],
}


def resultado(tipo: str, datos: dict, mal: int) -> discord.Embed:
    """Embed de resultado de análisis.

    `tipo` es "url" | "hash" | "ip" | "file". `datos` lleva lo mínimo para poder
    re-renderizar sin volver a llamar a la API:
        valor    -> el elemento analizado (URL, hash, IP o nombre de archivo)
        vt_link  -> enlace al informe de VirusTotal (opcional)
        top_text -> antivirus que lo detectaron, ya formateado (opcional)
    """
    veredicto = "malicioso" if mal > 0 else "seguro"
    texto = _TITULO_RESULTADO.get((tipo, veredicto), "Resultado del análisis")
    embed = _nuevo(texto, SEVERIDAD_COLOR.get(veredicto, COLOR_NEUTRAL))
    embed.description = f"**{mal}** detecciones" if veredicto == "malicioso" else "Sin detecciones"

    valor = str(datos.get("valor", ""))
    etiqueta = _ETIQUETA_ELEMENTO.get(tipo, "Elemento")
    icono_elemento = EMOJI_FILE if tipo == "file" else EMOJI_FINGERPRINT
    embed.add_field(name=f"{icono_elemento} {etiqueta}", value=f"`{valor}`", inline=False)

    if datos.get("top_text"):
        embed.add_field(name=f"{EMOJI_GUARDIAN} Detectado por", value=f"`{datos['top_text']}`", inline=False)

    if datos.get("vt_link"):
        embed.add_field(name=f"{EMOJI_LINK} VirusTotal", value=f"[Ver informe completo]({datos['vt_link']})", inline=False)

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
          avatar_url: Optional[str] = None) -> discord.Embed:
    """Embed informativo. `campos` es una lista de (nombre, valor, inline).

    `con_pie=False` se usa cuando el embed se completa más abajo y el pie se añade
    al final, con un contexto que ya incluye los contadores.
    """
    embed = discord.Embed(
        title=f"{icono} {texto}",
        description=descripcion or None,
        color=discord.Color(color),
    )
    for nombre, valor, inline in (campos or []):
        embed.add_field(name=nombre, value=valor, inline=inline)
    return pie(embed, texto, avatar_url) if con_pie else embed


def nsfw(tipo: str, valor: str, detalles: str) -> discord.Embed:
    embed = _nuevo(TITULOS["nsfw"], COLOR_NSFW, f"**{tipo}** con contenido NSFW")
    embed.add_field(name=f"{EMOJI_NSFW} Elemento", value=f"`{valor}`", inline=False)
    if detalles:
        embed.add_field(name=f"{EMOJI_GUARDIAN} Detectado por", value=detalles, inline=False)
    return pie(embed, f"NSFW · {tipo}")


def amenaza(tipo: str, valor: str, detalles: str, usuario: discord.abc.User,
            vt_link: Optional[str] = None) -> discord.Embed:
    """Log de amenaza enviado al canal del servidor. Es el embed más crítico:
    aquí se toman acciones de moderación, así que el valor va en un code block
    para que un atacante no pueda inyectar markdown ni romper la maquetación."""
    embed = _nuevo(TITULOS["amenaza"], COLOR_ERROR, f"**{tipo.upper()}** resultó **malicioso**")
    embed.add_field(name=f"{EMOJI_FINGERPRINT} Valor", value=f"```{valor}```", inline=False)
    embed.add_field(name=f"{EMOJI_GUARDIAN} Usuario", value=usuario.mention, inline=True)
    embed.add_field(name=f"{EMOJI_SHIELD} Detalles", value=detalles, inline=True)
    # El ID explícito se perdreía al mover el pie al formato de marca, y quien modera
    # lo necesita para copiar y pegar en herramientas de moderación.
    embed.add_field(name="ID", value=f"`{usuario.id}`", inline=True)
    if vt_link:
        embed.add_field(name=f"{EMOJI_LINK} VirusTotal", value=f"[Ver informe]({vt_link})", inline=False)
    return pie(embed, f"Amenaza · {tipo}")


def topgg(mensaje: str) -> discord.Embed:
    return aviso("Eres parte de la comunidad", mensaje, color=COLOR_TOPGG)


def resultado_barra(porcentaje: float, total: int, limite: int) -> str:
    """Barra de progreso compartida entre /stats y los avisos de cuota."""
    largo = 10
    llenos = int(largo * min(100.0, max(0.0, porcentaje)) / 100)
    return f"{'█' * llenos}{'░' * (largo - llenos)} **{porcentaje:.0f}%** ({total}/{limite})"


__all__ = [
    "MARCA", "TITULOS", "TITULOS_PROHIBIDOS",
    "pie", "titulo", "resultado", "error", "error_analisis", "error_conexion",
    "error_cuota", "aviso", "nsfw", "amenaza", "topgg", "resultado_barra",
    "COLOR_NEUTRAL", "COLOR_SEGURO", "COLOR_MALICIOSO", "COLOR_ERROR", "COLOR_NSFW", "COLOR_TOPGG",
    "SEVERIDAD_COLOR",
    "EMOJI_CORRECTO", "EMOJI_WARNING", "EMOJI_NSFW", "EMOJI_FILE", "EMOJI_LINK",
]
