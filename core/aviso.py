"""Decide si un mensaje merece un embed en el canal.

Un dial por categoría, y nada más. Antes eran tres interruptores (limpios, sospechosos,
errores) más una lista aparte para los motivos de fallo, lo que dejaba cosas imposibles
de expresar: callar "se acabó la cuota" sin callar también "había demasiados adjuntos", o
callar el NSFW sin callar el malware. Con un dial por categoría, quien configura decide
qué le importa en su servidor, que es lo único que no se puede suponer.

Hay dos niveles, a propósito:

- `silent_mode` es el interruptor general, para silenciar el bot de golpe sin tocar
  quince diales. Es un botón de emergencia, no la mecánica de uso normal.
- `notificar` es la lista de categorías activas. Todo apagado es un estado legítimo: hay
  quien prefiere mirar el panel en silencio y usar solo la reacción.

Los valores por defecto de los interruptores antiguos NO se derivan aquí: si una guild
tiene claves viejas en su configuración, estas se ignoran y manda la lista. Es
deliberado, porque mantener dos vocabularios de interruptores sería peor.
"""

from __future__ import annotations

from typing import Any, Mapping, Set

from core.senales import Senales

# Claves que se leen de la configuración. `silent_mode` y `reacciones` no son categorías:
# son interruptores aparte.
CONFIG_AVISO: tuple[str, ...] = (
    "silent_mode",
    "notificar",
    "reacciones",
)


def config_aviso_por_defecto(silent_mode: bool) -> dict[str, Any]:
    """Defaults de aviso, para una guild que no tenga nada configurado.

    Se mantiene por compatibilidad con `core.guild_config`, que lo usa al derivar los
    valores de una configuración antigua. `notificar` sale del catálogo: los interruptores
    antiguos no se traducen a una lista porque no hay forma honesta de saber qué quería
    quien los dejó puestos.
    """
    from core.config_schema import CATEGORIAS_POR_DEFECTO

    return {
        "silent_mode": bool(silent_mode),
        "notificar": list(CATEGORIAS_POR_DEFECTO),
        "reacciones": True,
    }


def categorias_aviso(config: Mapping[str, Any]) -> Set[str]:
    """Las categorías que este servidor tiene activadas.

    Una lista vacía significa "nada", no "sin configurar": quien la vació a propósito
    quiere silencio, y confundirlo con "aún no se ha tocado" es lo que hace que un filtro
    mal entendido termine callando lo que sí importa.
    """
    from core.config_schema import CATEGORIAS_POR_DEFECTO

    valor = config.get("notificar")
    if valor is None:
        # Sin la clave (config anterior a esta): los defaults del catálogo, no vacío.
        return set(CATEGORIAS_POR_DEFECTO)
    return set(valor)


def debe_enviar_embed(senales: Senales, config: Mapping[str, Any]) -> bool:
    """¿Va este mensaje al canal como embed?

    Es una intersección: si el mensaje tiene alguna categoría y esa categoría está
    activa, se avisa. No hay jerarquías ni casos especiales: lo que se ha encontrado y lo
    que se ha pedido ver.
    """
    if not config.get("silent_mode", True):
        # El interruptor general manda sobre todo, sin mirar qué hay activo.
        return False
    return bool(senales.categorias & categorias_aviso(config))


def reacciones_activas(config: Mapping[str, Any]) -> bool:
    """Si este servidor quiere el emoji sobre el mensaje.

    Va aparte de los avisos a propósito: la reacción es retroalimentación de que el bot
    ha mirado el mensaje, no una notificación. Quien la silencia sigue viendo el embed.
    """
    return bool(config.get("reacciones", True))


def razon_para_embeder(senales: Senales, config: Mapping[str, Any]) -> str:
    """Qué decidió mandar (o no mandar) el embed. Para logs y tests."""
    if not config.get("silent_mode", True):
        return "interruptor general apagado"
    pedidas = senales.categorias & categorias_aviso(config)
    if pedidas:
        return ", ".join(sorted(pedidas))
    if senales.categorias:
        return f"todo silenciado ({len(senales.categorias)} categoría(s))"
    return "nada que avisar"
