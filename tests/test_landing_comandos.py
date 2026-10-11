"""La landing no puede anunciar un comando que no exista.

`test_interacciones.py` ya comprueba que `/help` no anuncie comandos muertos, pero con
**lista negra**: solo salta lo que alguien se acordó de añadir. Aquí es al revés —
cualquier `/palabra` de las páginas tiene que existir en el árbol de comandos— y así se
mantiene solo la próxima vez que se elimine uno.

No es hipotético. `/thanks` pedía `/setlogchannel` y `/strictmode`, que no existen desde
hace tiempo, y es la primera pantalla que ve el owner después de invitar. Le decía que
escribiera un comando que Discord iba a rechazar.

El JSON-LD de `index.astro` va más lejos: ese texto es el que Google muestra bajo el
resultado de búsqueda, así que el error salía del buscador.
"""

import os
import pathlib
import re

import pytest

RAIZ = pathlib.Path(__file__).resolve().parent.parent
PAGINAS = ["index", "thanks", "terminos", "privacidad", "404"]

# Rutas de la propia landing. No son comandos, y por eso están aquí. Cada excepción
# necesita su motivo: una lista sin explicaciones se va llenando sola y acaba
# dejando pasar justo lo que tenía que atrapar.
NO_COMANDOS = {
    "thanks",      # /thanks, la landing a la que redirige la invitación de OAuth
    "404",
    "terminos",
    "privacidad",
}

# El grupo acepta `-` para que `/emoji-whitelist.png` se lea entero y se descarte por la
# extensión, en vez de quedarse con `emoji` y dar un falso positivo. Y `\.[a-z0-9]{1,4}`
# con su `\b` deja pasar `/strictmode.` a final de frase, que sí queremos detectar.
#
# El `.` va también en el lookbehind para que los imports de Astro
# (`from '../components/Icon.astro'`) no salten: ahí `/components` es una ruta, no un
# comando.
MENCION = re.compile(r"(?<![\w./])/([a-z][a-z0-9_-]{1,40})(?![-\w]|\.[a-z0-9]{1,4}\b)")

COMANDOS_MUERTOS_CONOCIDOS = {
    "setlogchannel", "strictmode", "silentmode", "autoscan",
    "whitelist", "disablelogchannel",
}


def _mencionados(pagina: str) -> set[str]:
    texto = (RAIZ / "landing" / "src" / "pages" / f"{pagina}.astro").read_text("utf-8")
    texto = re.sub(r"https?://\S+", " ", texto)          # URLs: el enlace de invitación
    texto = re.sub(r"</?[a-zA-Z][\w-]*", " ", texto)      # etiquetas: `</div>` no es un comando
    return {m for m in MENCION.findall(texto)} - NO_COMANDOS


def _bot():
    """El bot de `bot.py` con los cogs cargados, que es lo que puebla el árbol.

    Los cogs se leen del directorio en vez de usar la lista de `test_arranque.py`: esa
    lista es manual, y un guard que depende de que alguien recuerde actualizar una
    lista deja de comprobar el comando nuevo, que es justo lo que tiene que comprobar.
    """
    import sys

    from tests import test_arranque

    cargar = getattr(test_arranque._bot_cargado, "__wrapped__", test_arranque._bot_cargado)
    bot = cargar()
    return bot


async def _comandos_existentes() -> set[str]:
    bot = _bot()
    for archivo in sorted(os.listdir(RAIZ / "cogs")):
        if archivo.endswith(".py") and not archivo.startswith("_"):
            nombre = f"cogs.{archivo[:-3]}"
            if nombre not in bot.extensions:
                await bot.load_extension(nombre)
    return {c.name for c in bot.tree.get_commands()}


@pytest.mark.parametrize("pagina", PAGINAS)
@pytest.mark.asyncio
async def test_la_pagina_no_anuncia_comandos_muertos(pagina):
    existen = await _comandos_existentes()

    for nombre in sorted(_mencionados(pagina)):
        assert nombre in existen, (
            f"{pagina}.astro anuncia /{nombre}, que ya no existe. "
            f"Comandos reales: {sorted(existen)}. "
            f"Si es una ruta de la landing, va en NO_COMANDOS con su motivo."
        )


def test_el_guard_encuentra_de_verdad():
    """Un guard que no encuentra nada no es un guard.

    Si el regex se rompe y deja de detectar menciones, el test de arriba pasa en verde
    sin comprobar nada. Este falla cuando la extracción se queda vacía.
    """
    assert _mencionados("thanks"), "el regex dejó de encontrar comandos"


def test_los_comandos_muertos_conocidos_siguen_muertos():
    """Que la lista de comandos muertos documentada siga siendo cierta.

    Los atajos de un paso se borraron a propósito. Si alguno vuelve, este test salta
    aunque la landing todavía no lo anuncie.
    """
    texto = (RAIZ / "cogs" / "help.py").read_text("utf-8")
    for muerto in COMANDOS_MUERTOS_CONOCIDOS:
        assert f"/{muerto}" not in texto, f"/help volvió a anunciar /{muerto}"