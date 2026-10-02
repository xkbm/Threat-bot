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

# Claves que se leen de la configuración. `avisar_todo` y `reacciones` no son categorías:
# son interruptores aparte.
CONFIG_AVISO: tuple[str, ...] = (
    "avisar_todo",
    "notificar",
    "reacciones",
)

# Clave antigua y su traducción.
#
# El nombre mentía y el comportamiento no: con `silent_mode` en True, `debe_enviar_embed`
# hacía `if not silent_mode: return False` — o sea, no cortaba ahí y por lo tanto
# avisaba. El valor guardado True significaba "avisa" desde el principio, aunque dijera
# "silent". Por eso la traducción es identidad y no negación: un servidor con
# `silent_mode: True` guardado (que es el default de todos) tiene que seguir recibiendo
# avisos, y con una negación se quedaría mudo.
#
# La clave nueva se llama `avisar_todo` para que el nombre ya no admita lectura
# ambigua: True = avisa, False = calla, y el botón lo dice igual.
CLAVE_LEGADA = "silent_mode"


def config_aviso_por_defecto(avisar: bool = True) -> dict[str, Any]:
    """Defaults de aviso, para una guild que no tenga nada configurado.

    `avisar=True` es el default **porque es lo que tenía la gente**, no porque "avisar"
    suene a default de un bot de seguridad. Para lo contrario, `avisar=False`.
    """
    from core.config_schema import CATEGORIAS_POR_DEFECTO

    return {
        "avisar_todo": bool(avisar),
        "notificar": list(CATEGORIAS_POR_DEFECTO),
        "reacciones": True,
    }


def migrar_aviso(config: dict) -> dict:
    """Traduce `silent_mode` a `avisar_todo` una sola vez, al leer.

    Identidad, no negación: el código leía `silent_mode=True` como "avisa", y hay que
    conservar ese comportamiento. Un servidor con la clave antigua se quedaría si no con
    `avisar_todo` en su default y su interruptor se movería solo, así que la traducción
    es explícita y el registro viejo se borra para que no queden dos interruptores con
    el mismo nombre y sentidos distintos circulando por la configuración.
    """
    if CLAVE_LEGADA in config and "avisar_todo" not in config:
        config["avisar_todo"] = bool(config.pop(CLAVE_LEGADA))
    return config


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
    if not config.get("avisar_todo", True):
        # El botón de emergencia calla TODO, amenazas incluidas. Es a propósito: para
        # callar una sola cosa está la lista de categorías, y para eso no hace falta
        # apagar el bot entero.
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
    if not config.get("avisar_todo", True):
        return "avisar_todo apagado: no sale nada"
    pedidas = senales.categorias & categorias_aviso(config)
    if pedidas:
        return ", ".join(sorted(pedidas))
    if senales.categorias:
        return f"todo silenciado ({len(senales.categorias)} categoría(s))"
    return "nada que avisar"
