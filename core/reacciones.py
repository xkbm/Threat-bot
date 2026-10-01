"""Una sola reacción de Threat por mensaje.

El problema que resuelve: las reacciones se añadían en cinco sitios distintos
(`ui/message_handler.py:321, 472, 506, 789-800`) y solo se retiraba `EMOJI_LOADING`.
Nada más se quitaba nunca, así que un mensaje con un enlace en whitelist, un
`.pdf.exe` y una imagen NSFW acababa con tres reacciones a la vez. Peor: el emoji de
whitelist se ponía *antes* de conocer el resultado, de modo que un mensaje con
whitelist y un link malicioso salía marcado con los dos, que se lee contradictorio.

Aquí hay dos piezas:

- `resolver_reaccion()` es pura y decide cuál poner, de peor a mejor.
- `ReactionController` es el dueño del mensaje y garantiza el invariante: como mucho
  una reacción de veredicto. Antes de poner una nueva quita la anterior.

`EMOJI_LOADING` tiene su propia ranura porque no es un veredicto, es progreso. Puede
convivir con un veredicto (el análisis sigue) pero nunca hay dos veredictos.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core import config
from core.senales import Senales
from core.veredictos import Veredicto

log = logging.getLogger("reacciones")

EMOJI_VEREDICTOS = frozenset({
    config.EMOJI_CORRECTO,
    config.EMOJI_INCORRECTO,
    config.EMOJI_ERROR,
    config.EMOJI_WARNING,
    config.EMOJI_NSFW,
    config.EMOJI_GUARDIAN,
    config.EMOJI_WHITELIST,
    config.EMOJI_COOLDOWN,
    config.EMOJI_RESTRINGIDO,
    config.EMOJI_PHISHING,
})


def resolver_reaccion(senales: Senales) -> str:
    """Devuelve el único emoji que corresponde a este mensaje.

    La tabla de prioridad es la definición de "peor". Un mensaje con whitelist y un link
    malicioso sale solo con el de malicioso, y el embed dice cuántos enlaces hubo exentos
    en lugar de marcarse con dos emojis contradictorios.

    Excepción: si lo **único** que pasó fue la whitelist, esa es la respuesta. Marcarlo
    con el check verde diría "analizado y limpio", que es falso: no se miró nada. Y sin
    reacción, un mensaje con enlaces exentos queda indistinguible de uno que el bot pasó
    por alto.
    """
    if senales.malicious:
        return config.EMOJI_WARNING
    if senales.nsfw:
        return config.EMOJI_NSFW
    if senales.restringido:
        return config.EMOJI_RESTRINGIDO
    if senales.phishing:
        return config.EMOJI_PHISHING
    if senales.cooldown:
        return config.EMOJI_COOLDOWN
    if senales.error:
        return config.EMOJI_ERROR
    if senales.hay_senal_de_nombre:
        return config.EMOJI_WARNING
    if senales.suspicious:
        return config.EMOJI_GUARDIAN
    # La whitelist es lo último: solo decide cuando no hay nada más que contar. Con
    # elementos de por medio, manda su veredicto y la whitelist va al embed.
    if senales.whitelist_omitidos:
        return config.EMOJI_WHITELIST
    return config.EMOJI_CORRECTO


class ReactionController:
    """Dueño de las reacciones de un mensaje. Garantiza un solo veredicto.

    Se guarda por `message.id` en el bot y no como variable local, porque
    `on_message` y `on_message_edit` pueden procesar el mismo mensaje a la vez y dos
    instancias compitiendo se quitarían y pondrían emojis sin coordinarse.
    """

    def __init__(self, message: Any) -> None:
        self.message = message
        self.veredicto_actual: Optional[str] = None
        self.loading_actual: bool = False

    async def set(self, emoji: str) -> None:
        """Pone `emoji` como veredicto, retirando antes el que hubiera.

        Poner dos veces el mismo emoji no es un no-op: en el camino rápido solo
        détection de nombre no hay nada que quitar, y en el resto evita el trabajo de
        quitar y volver a poner si el veredicto no ha cambiado.
        """
        if emoji == self.veredicto_actual:
            return
        if not self.message:
            return

        # Si el veredicto definitive ya no hay nada que esperar, el loading sobra.
        await self._quitar_loading()

        anterior = self.veredicto_actual
        if anterior and anterior != emoji:
            try:
                await self.message.remove_reaction(anterior, self.message.author.bot)
            except Exception:
                # El emoji puede no estar puesto o el bot no tener permiso; en ambos
                # casos se sigue adelante: es cosmético y no debe tumbar el análisis.
                log.debug(f"No se pudo quitar {anterior} de {self.message.id}")

        try:
            await self.message.add_reaction(emoji)
        except Exception as e:
            log.debug(f"No se pudo poner {emoji} en {self.message.id}: {e}")
            return
        self.veredicto_actual = emoji

    async def loading(self) -> None:
        """Marca progreso. Nunca sustituye a un veredicto, solo se añade."""
        if self.loading_actual or not self.message:
            return
        try:
            await self.message.add_reaction(config.EMOJI_LOADING)
            self.loading_actual = True
        except Exception as e:
            log.debug(f"No se pudo poner loading en {self.message.id}: {e}")

    async def _quitar_loading(self) -> None:
        if not self.loading_actual or not self.message:
            return
        try:
            await self.message.remove_reaction(config.EMOJI_LOADING, self.message.author.bot)
        except Exception:
            pass
        self.loading_actual = False

    async def limpiar(self) -> None:
        """Retira loading. El veredicto se queda: es el resumen del análisis."""
        await self._quitar_loading()


# Mapa emoji → veredicto. Explícito para que quien lo lea no tenga que deducirlo de
# la tabla de `resolver_reaccion`.
MAPA_EMOJI_VEREDICTO: Dict[str, Veredicto] = {
    config.EMOJI_WARNING: Veredicto.MALICIOSO,
    config.EMOJI_NSFW: Veredicto.NSFW,
    config.EMOJI_RESTRINGIDO: Veredicto.RESTRINGIDO,
    config.EMOJI_PHISHING: Veredicto.PHISHING,
    config.EMOJI_COOLDOWN: Veredicto.ERROR,
    config.EMOJI_ERROR: Veredicto.ERROR,
    config.EMOJI_GUARDIAN: Veredicto.SOSPECHOSO,
    config.EMOJI_CORRECTO: Veredicto.SEGURO,
}