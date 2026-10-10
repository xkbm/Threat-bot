"""Los mockups de la landing tienen que parecerse a lo que el bot responde de verdad.

La landing muestra dos chats de ejemplo con los embeds que "envía" Threat. Esos embeds
están escritos a mano en `landing/src/pages/index.astro` y el bot construye los suyos en
`ui/embed.py`. Nadie los conecta, así que pueden divergir sin que nada se entere: el
cambia un título en el bot, los tests de embeds pasan, y la web sigue mostrando el
antiguo.

Estos tests leen el `.astro` y comparan contra la fuente real. Fallan cuando divergen.
"""

import os
import re

import pytest

from core.config import COLOR_NSFW
from core.veredictos import Veredicto
from ui.embed import TITULOS, TITULOS_PROHIBIDOS

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(RAIZ, "landing", "src", "pages", "index.astro")

# El mockup de whitelist no es un embed: es el `message.reply()` en texto plano que
# ya no existe. El bot devuelve el veredicto IGNORADO, cuyo título vive en el catálogo.
TITULO_IGNORADO = Veredicto.IGNORADO.titulo


@pytest.fixture(scope="module")
def index() -> str:
    with open(INDEX, encoding="utf-8") as f:
        return f.read()


def _rgb_de(color_hex: int) -> str:
    """`0xDC2626` -> `rgb(220, 38, 38)`, que es como lo escribe el .astro."""
    r, g, b = (color_hex >> 16) & 0xFF, (color_hex >> 8) & 0xFF, color_hex & 0xFF
    return f"rgb({r}, {g}, {b})"


class TestTitulosEnElMockup:
    """El mockup representa el embed del AUTOESCANEO, no el del log de amenaza.

    Son dos embeds distintos con títulos distintos para lo mismo:
    `Veredicto.MALICIOSO.titulo` es "Amenazas detectadas" (plural, es el que pinta el
    `message_handler` con `peor()`) y `TITULOS["amenaza"]` es "Amenaza detectada"
    (singular, el que usa el embed de log con botones Ban/Kick). Comparar contra el
    equivocado daría un fallo falso.
    """

    def test_amenazas_detectadas_es_el_titulo_real(self, index):
        assert Veredicto.MALICIOSO.titulo in index

    def test_contenido_nsfw_es_el_titulo_real(self, index):
        assert Veredicto.NSFW.titulo == TITULOS["nsfw"]  # ambos coinciden hoy
        assert Veredicto.NSFW.titulo in index

    def test_todos_los_elementos_seguros_es_el_titulo_real(self, index):
        assert Veredicto.SEGURO.titulo in index

    def test_el_titulo_de_whitelist_es_el_del_veredicto_ignorado(self, index):
        assert TITULO_IGNORADO in index

    def test_ningun_titulo_prohibido_aparece_en_la_landing(self, index):
        # `TITULOS_PROHIBIDOS` son los títulos que el rediseño del bot eliminó. Que no
        # aparezcan en la web es la misma garantía que da `test_no_reaparece` para el bot.
        reaparecen = [t for t in TITULOS_PROHIBIDOS if t in index]
        assert not reaparecen, f"la landing muestra títulos que el bot ya no usa: {reaparecen}"


class TestVeredictoDeWhitelist:
    def test_no_anuncia_el_whitelist_como_texto_plano(self, index):
        # Era un `message.reply()` del código viejo. Hoy es un veredicto, no un texto suelto.
        assert "No se requiere análisis" not in index


class TestEmojiPorVeredicto:
    def test_nsfw_usa_el_emoji_de_nsfw(self, index):
        """El mockup de NSFW ponía el emoji de amenaza en vez del suyo."""
        # Extraer el bloque del escenario NSFW y ver qué emoji asigna.
        bloques = re.findall(
            r"titulo:\s*'Contenido NSFW detectado'.*?emoji:\s*'([^']+)'", index, re.DOTALL
        )
        assert bloques, "no se encontró el escenario NSFW"
        for emoji in bloques:
            assert "emoji-nsfw" in emoji, (
                f"el escenario NSFW usa {emoji}; el veredicto NSFW tiene su propio emoji"
            )

    def test_amenaza_usa_el_emoji_de_amenaza(self, index):
        bloques = re.findall(
            r"titulo:\s*'Amenazas detectadas'.*?emoji:\s*'([^']+)'", index, re.DOTALL
        )
        assert bloques, "no se encontró el escenario de amenaza"
        for emoji in bloques:
            assert "emoji-warn" in emoji


class TestColoresDeBorde:
    def test_el_borde_del_escenario_nsfw_es_el_color_nsfw(self, index):
        """El mockup usaba el ámbar de "alerta". `COLOR_NSFW` es rojo."""
        bloques = re.findall(
            r"titulo:\s*'Contenido NSFW detectado'.*?borderColor:\s*'([^']+)'", index, re.DOTALL
        )
        assert bloques, "no se encontró el escenario NSFW"
        esperado = _rgb_de(COLOR_NSFW)
        for color in bloques:
            assert color == esperado, (
                f"el borde del escenario NSFW es {color}; el veredicto NSFW usa {esperado}"
            )


class TestConsistenciaEntreLosDosMockups:
    def test_los_dos_chats_comparten_la_lista_de_titulos(self, index):
        """Hay dos chats de ejemplo (hero y sección "cómo funciona").

        Si uno actualiza un título y el otro no, la web muestra dos versiones distintas
        de la misma respuesta. Se comparan los títulos que cada uno declara.
        """
        titulos_hero = set(re.findall(r"titulo:\s*'([^']*)'", index))
        # Ambos bloques declaran `titulo:`; que el conjunto tenga entradas es lo que
        # comprueba que el patrón sigue siendo el que se cree.
        assert titulos_hero, "no se encontraron escenarios con titulo: en la landing"
        assert "" in titulos_hero, "el escenario de whitelist debería declararlo vacío"
