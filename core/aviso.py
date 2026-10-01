"""Decide si un mensaje merece un embed en el canal.

`silent_mode` mezclaba dos preguntas distintas: "¿no me digas nada de lo que está
limpio?" y "¿no me digas nada de lo que falló?". Un servidor que solo quiere castigar
amenazas tampoco podía callar los errores de cuota, y uno que callaba los errores se
veía obligado a ver cada imagen limpia.

Aquí se separan. `silent_mode` sigue siendo el master retrocompatible ("solo avisa si
hay algo que mirar") y por debajo hay tres interruptores que el usuario controla. Los
valores por defecto reproducen exactamente el comportamiento anterior, así que al
actualizar ningún servidor ve un cambio.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from core.senales import Senales

# Claves de aviso. `silent_mode` es el master y se conserva por compatibilidad.
CONFIG_AVISO: tuple[str, ...] = (
    "silent_mode",
    "avisar_limpios",
    "avisar_sospechosos",
    "avisar_errores",
    "reacciones",
)


def config_aviso_por_defecto(silent_mode: bool) -> Dict[str, bool]:
    """Deriva los interruptores a partir del `silent_mode` antiguo.

    Es lo que se usa en la primera carga de una guild que aún no tiene las claves
    nuevas, para que un servidor que llevaba meses con `silent_mode=True` siga
    recibiendo exactamente los mismos mensajes.
    """
    return {
        "silent_mode": bool(silent_mode),
        # Con el modo silencioso activo no se ve lo limpio; si está desactivado, sí.
        "avisar_limpios": not silent_mode,
        "avisar_sospechosos": True,
        "avisar_errores": True,
        "reacciones": True,
    }


def debe_enviar_embed(senales: Senales, config: Mapping[str, Any]) -> bool:
    """¿Va este mensaje al canal como embed?

    El orden importa: primero el master, luego lo que nunca se calla, después lo que
    sí se puede apagar.

    - Las amenazas (malicioso, NSFW) avisan siempre. Un modo estricto que se puede
      silenciar no es un modo estricto.
    - Los errores van detrás de su interruptor. Un corte de cuota no debería tapar el
      resto del análisis.
    - `omitidos` y `cooldown` cuentan como errores: ambos significan "no miré todo".
    - Lo limpio solo se ve si `avisar_limpios` está activo.
    """
    if not config.get("silent_mode", True):
        return True
    if senales.hay_amenaza:
        return True
    if config.get("avisar_sospechosos", True) and senales.hay_hallazgo:
        return True
    if senales.whitelist_omitidos > 0:
        # El bot ha ignorado enlaces a propósito. Es información que el usuario pidió
        # él mismo, no ruido: si tiene la whitelist activa, quiere saber que se aplicó.
        return True
    if senales.error or senales.cooldown or senales.omitidos > 0:
        # Hay un fallo que contar. Solo se enseña si el usuario quiere ver errores; el
        # interruptor de limpios no lo activa: "muéstrame lo limpio" no significa
        # "muéstrame también lo que no pude comprobar".
        return bool(config.get("avisar_errores", True))
    # No hay hallazgos ni fallos: es un mensaje limpio de verdad.
    return bool(config.get("avisar_limpios", False))


def reacciones_activas(config: Mapping[str, Any]) -> bool:
    """Si el usuario ha pedido silenciar también las reacciones.

    Los interruptores de aviso solo gobiernan el embed: la reacción es feedback visual
    inmediato y no hace ruido en el canal. Este es el interruptor separado para quien
    no quiera ni eso.
    """
    return bool(config.get("reacciones", True))


def razon_para_embeder(senales: Senales, config: Mapping[str, Any]) -> str:
    """Qué regla decidió mandar (o no mandar) el embed. Para logs y tests.

    El orden tiene que calcar el de `debe_enviar_embed`, o el log explaina una cosa y el
    embed hace otra. Por eso la whitelist va antes del bloque de errores: decide siempre,
    sin depender de ningún interruptor.
    """
    if not config.get("silent_mode", True):
        return "master desactivado"
    if senales.hay_amenaza:
        return "amenaza confirmada"
    if config.get("avisar_sospechosos", True) and senales.hay_hallazgo:
        return "hallazgo"
    if senales.whitelist_omitidos > 0:
        return "enlaces en whitelist"
    if config.get("avisar_errores", True):
        if senales.error:
            return "error de análisis"
        if senales.cooldown:
            return "cooldown de antispam"
        if senales.omitidos > 0:
            return "adjuntos omitidos"
    elif senales.error or senales.cooldown or senales.omitidos > 0:
        return "fallo silenciado"
    if config.get("avisar_limpios", False):
        return "mensaje limpio"
    return "silenciado"