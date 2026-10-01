"""Conjunto cerrado de veredictos: fuente única de verdad.

Antes estos literales ("malicioso", "sospechoso", "seguro", "nsfw", "error") vivían
sueltos en cinco ficheros y cada uno repetía su propia lógica de título, color y
acción. Aquí se declaran una vez.

Los dos veredictos nuevos separan lo que antes iba mezclado:

- `restringido` es contenido sensible pero discutible (alcohol, armas). **No borra por
  defecto**: avisa y queda registrado. Antes compartía veredicto y borrado con `nsfw`,
  y una foto de una cerveza con prob 0.75 acababa borrada en modo estricto.
- `phishing` es una suplantación de marca detectada localmente, sin llamar a
  VirusTotal. Informativo: nunca borra ni infracciona.

Regla que atraviesa todo el módulo: **un elemento que no se pudo comprobar es `error`,
nunca `seguro`**. Un análisis que falla se reportaba antes como seguro, y eso es el
peor fallo posible: el bot afirma estar limpio de algo que nunca miró.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Optional

from core import config


class Veredicto(Enum):
    """Cada veredicto sabe cómo se pinta y qué hacer con él."""

    SEGURO = "seguro"
    SOSPECHOSO = "sospechoso"
    MALICIOSO = "malicioso"
    NSFW = "nsfw"
    RESTRINGIDO = "restringido"
    PHISHING = "phishing"
    ERROR = "error"

    @property
    def es_amenaza(self) -> bool:
        """Amenaza confirmada:borra y avisa pase lo que pase el resto de ajustes."""
        return self in (Veredicto.MALICIOSO, Veredicto.NSFW)

    @property
    def es_hallazgo(self) -> bool:
        """Algo que un moderador debería mirar aunque no haya amenaza confirmada."""
        return self in (
            Veredicto.SOSPECHOSO,
            Veredicto.RESTRINGIDO,
            Veredicto.PHISHING,
            Veredicto.MALICIOSO,
            Veredicto.NSFW,
        )

    @property
    def color(self) -> int:
        return _COLORES[self]

    @property
    def emoji(self) -> str:
        return _EMOJIS[self]

    @property
    def titulo(self) -> str:
        """Titular del mensaje cuando este veredicto es el más grave."""
        return _TITULOS[self]

    @property
    def contador(self) -> str:
        """Sustantivo para la línea de recuento del embed.

        Distinto de `titulo` a propósito: `titulo` es una frase para encabezar un
        mensaje ("Amenazas detectadas") y `contador` un sustantivo para contar
        ("Maliciosos: **2**"). Con un único campo los contadores salían como
        "Todos los elementos son seguros: **3**".
        """
        return _CONTADORES[self]

    @property
    def borra_en_modo_estricto(self) -> bool:
        """Solo el malware confirmado y la pornografía borran solas.

        `restringido`, `phishing` y `sospechoso` son señales que el moderador decide
        por sí mismo; borrarlas automáticamente genera falsos positivos que hacen que
        el modo estricto se desactive a la primera.
        """
        return self in (Veredicto.MALICIOSO, Veredicto.NSFW)

    @classmethod
    def desde(cls, valor: Optional[str]) -> "Veredicto":
        """Convierte un literal antiguo en Veredicto. Desconocido -> ERROR.

        Tolera `None` y valores inventados: es el único punto donde entra texto de
        fuera, y ante la duda el elemento se marca como error, no como seguro.
        """
        if isinstance(valor, cls):
            return valor
        if not valor:
            return cls.ERROR
        for veredicto in cls:
            if veredicto.value == str(valor).lower():
                return veredicto
        return cls.ERROR


_COLORES: Dict[Veredicto, int] = {
    Veredicto.SEGURO: config.COLOR_SEGURO,
    Veredicto.SOSPECHOSO: config.COLOR_SOSPECHOSO,
    Veredicto.MALICIOSO: config.COLOR_MALICIOSO,
    Veredicto.NSFW: config.COLOR_NSFW,
    Veredicto.RESTRINGIDO: config.COLOR_SOSPECHOSO,
    Veredicto.PHISHING: config.COLOR_SOSPECHOSO,
    Veredicto.ERROR: config.COLOR_ERROR,
}

_EMOJIS: Dict[Veredicto, str] = {
    Veredicto.SEGURO: config.EMOJI_CORRECTO,
    Veredicto.SOSPECHOSO: config.EMOJI_GUARDIAN,
    Veredicto.MALICIOSO: config.EMOJI_WARNING,
    Veredicto.NSFW: config.EMOJI_NSFW,
    Veredicto.RESTRINGIDO: config.EMOJI_RESTRINGIDO,
    Veredicto.PHISHING: config.EMOJI_PHISHING,
    Veredicto.ERROR: config.EMOJI_ERROR,
}

_TITULOS: Dict[Veredicto, str] = {
    Veredicto.SEGURO: "Todos los elementos son seguros",
    Veredicto.SOSPECHOSO: "Elementos sospechosos",
    Veredicto.MALICIOSO: "Amenazas detectadas",
    Veredicto.NSFW: "Contenido NSFW detectado",
    Veredicto.RESTRINGIDO: "Contenido restringido detectado",
    Veredicto.PHISHING: "Posible suplantación de marca",
    Veredicto.ERROR: "Análisis completado con errores",
}

_CONTADORES: Dict[Veredicto, str] = {
    Veredicto.SEGURO: "Seguros",
    Veredicto.SOSPECHOSO: "Sospechosos",
    Veredicto.MALICIOSO: "Maliciosos",
    Veredicto.NSFW: "NSFW",
    Veredicto.RESTRINGIDO: "Restringidos",
    Veredicto.PHISHING: "Suplantaciones",
    Veredicto.ERROR: "Errores",
}

# Orden en que se muestran los contadores en el embed. Distinto de PRECEDENCIA: aquí va
# de menos a más grave, porque es una lista de recuento y se lee como un resumen.
#
# Debe contener TODOS los veredictos: si uno falta, su contador no sale y la suma de las
# líneas deja de cuadrar con el total. Pasó con `phishing`, que se añadió al enumerado y
# se olvidó en esta tupla, así que un mensaje solo de suplantación mostraba "Seguros: 0"
# y ningún recuento de lo encontrado.
ORDEN_CONTADORES = (
    Veredicto.SEGURO,
    Veredicto.SOSPECHOSO,
    Veredicto.RESTRINGIDO,
    Veredicto.PHISHING,
    Veredicto.NSFW,
    Veredicto.MALICIOSO,
    Veredicto.ERROR,
)

# De peor a mejor. Cuando hay varios elementos en un mensaje manda el primero de la
# lista. El orden es la definición de "peor", así que no debe cambiar por whim: si un
# veredicto nuevo aparece, hay que decidir deliberadamente dónde se coloca.
#
# `SOSPECHOSO` va antes que `ERROR` a propósito. Un hallazgo confirmado es accionable;
# un error es "no se pudo comprobar". Si un mensaje trae un sospechoso y además un
# elemento que falló, lo que el moderador necesita ver primero es el sospechoso: el
# error se sigue contando en el embed, pero no tapa el hallazgo. Al revés, el mensaje
# entero se pone en rojo porque algo no se pudo comprobar, y eso es peor que mostrar
# ámbar con el recuento de lo que no se pudo comprobar.
PRECEDENCIA = (
    Veredicto.MALICIOSO,
    Veredicto.NSFW,
    Veredicto.RESTRINGIDO,
    Veredicto.PHISHING,
    Veredicto.SOSPECHOSO,
    Veredicto.ERROR,
    Veredicto.SEGURO,
)


def peor(veredictos) -> Veredicto:
    """Devuelve el veredicto más grave de la colección.

    Una lista vacía es SEGURO, no ERROR: no hay nada malo *y* nada que falló. El
    error se propaga por separado, que es justamente el punto de no colar un fallo
    como si fuera una ausencia de hallazgos.
    """
    presentes = set(veredictos)
    for candidato in PRECEDENCIA:
        if candidato in presentes:
            return candidato
    return Veredicto.SEGURO