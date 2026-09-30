"""Sistema unificado de embeds: contrato de estilo, paleta y render-on-read."""

import os
import re

import discord
import pytest

from core.config import (
    COLOR_NEUTRAL, COLOR_SEGURO, COLOR_MALICIOSO, COLOR_ERROR, COLOR_NSFW, COLOR_TOPGG,
    EMOJI_SHIELD, EMOJI_LINK, EMOJI_GUARDIAN, EMOJI_FILE, EMOJI_FINGERPRINT,
    EMOJI_INCORRECTO,
)
from ui import embed as emb
from ui.embed import MARCA, TITULOS, TITULOS_PROHIBIDOS

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATOS_URL = {"valor": "https://ejemplo.com/ruta", "vt_link": "https://vt/gui/x", "top_text": "Kaspersky, ESET"}
DATOS_HASH = {"valor": "a" * 64, "vt_link": "https://vt/gui/h", "top_text": "Kaspersky"}
DATOS_IP = {"valor": "8.8.8.8", "vt_link": "https://vt/gui/i", "top_text": None}
DATOS_FILE = {"valor": "documento.pdf", "vt_link": None, "top_text": None}


def texto_pie(embed) -> str:
    return (embed.footer.text or "") if embed.footer else ""


def nombres_campos(embed):
    return [f.name for f in embed.fields]


class TestPieDeMarca:
    """El pie es lo que hace identificable al bot. Debe estar en todos."""

    @pytest.mark.parametrize("construir", [
        lambda: emb.resultado("url", DATOS_URL, 3),
        lambda: emb.resultado("url", DATOS_URL, 0),
        lambda: emb.resultado("hash", DATOS_HASH, 1),
        lambda: emb.resultado("ip", DATOS_IP, 0),
        lambda: emb.resultado("file", DATOS_FILE, 7),
        lambda: emb.error_analisis("algo falló"),
        lambda: emb.error_conexion("sin red"),
        lambda: emb.error_cuota(65),
        lambda: emb.aviso("título", "desc"),
        lambda: emb.topgg("deja una reseña"),
    ])
    def test_siempre_presente(self, construir):
        pie = texto_pie(construir())
        assert pie, "el embed no tiene pie"
        assert pie.startswith(MARCA), f"el pie no empieza por la marca: {pie!r}"

    @pytest.mark.parametrize("construir", [
        lambda: emb.resultado("url", DATOS_URL, 3),
        lambda: emb.error_analisis("algo falló"),
        lambda: emb.aviso("título", "desc"),
    ])
    def test_formato_con_fecha_utc(self, construir):
        pie = texto_pie(construir())
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", pie), pie

    def test_contexto_se_incluye(self):
        pie = texto_pie(emb.aviso("Configuración", "x"))
        assert "Configuración" in pie

    def test_contexto_se_trunca(self):
        pie = texto_pie(emb.aviso("t", "d"))
        largo = texto_pie(emb.aviso("x" * 300, "d"))
        assert "…" in largo
        assert len(largo) < len("Threat · " + "x" * 300 + " · fecha")

    def test_avatar_si_se_pasa(self):
        e = emb.aviso("t", "d", avatar_url="https://cdn/x.png")
        assert e.thumbnail.url == "https://cdn/x.png"

    def test_sin_avatar_no_thumbnail(self):
        assert emb.aviso("t", "d").thumbnail.url is None


class TestPrefijoDeMarca:
    @pytest.mark.parametrize("construir", [
        lambda: emb.resultado("url", DATOS_URL, 3),
        lambda: emb.error_analisis("fallo"),
        lambda: emb.aviso("título", "desc"),
    ])
    def test_escudo_en_el_titulo(self, construir):
        assert construir().title.startswith(EMOJI_SHIELD), construir().title


class TestPaletaPorSeveridad:
    def test_malicioso_es_ambar(self):
        assert emb.resultado("url", DATOS_URL, 3).color == discord.Color(COLOR_MALICIOSO)

    def test_seguro_es_verde(self):
        assert emb.resultado("url", DATOS_URL, 0).color == discord.Color(COLOR_SEGURO)

    @pytest.mark.parametrize("tipo", ["url", "hash", "ip", "file"])
    def test_malicioso_ambar_en_todos_los_tipos(self, tipo):
        datos = {"url": DATOS_URL, "hash": DATOS_HASH, "ip": DATOS_IP, "file": DATOS_FILE}[tipo]
        assert emb.resultado(tipo, datos, 4).color == discord.Color(COLOR_MALICIOSO)
        assert emb.resultado(tipo, datos, 0).color == discord.Color(COLOR_SEGURO)

    @pytest.mark.parametrize("construir", [
        lambda: emb.error_analisis("x"),
        lambda: emb.error_conexion("x"),
        lambda: emb.error_cuota(),
    ])
    def test_errores_en_rojo(self, construir):
        assert construir().color == discord.Color(COLOR_ERROR)

    def test_aviso_neutro_es_gris(self):
        assert emb.aviso("t", "d").color == discord.Color(COLOR_NEUTRAL)

    def test_nsfw_rojo(self):
        e = emb.nsfw("Imagen", "http://x.png", "Desnudez 90%")
        assert e.color == discord.Color(COLOR_NSFW)

    def test_amenaza_roja(self):
        u = type("U", (), {"mention": "<@1>", "id": 1})()
        assert emb.amenaza("URL", "http://x", "3 detecciones", u).color == discord.Color(COLOR_ERROR)

    def test_topgg_rosa(self):
        assert emb.topgg("reseña").color == discord.Color(COLOR_TOPGG)

    def test_severidad_abierta(self):
        e = emb.aviso("t", "d", color=emb.COLOR_MALICIOSO)
        assert e.color == discord.Color(COLOR_MALICIOSO)


class TestTitulos:
    @pytest.mark.parametrize("tipo,datos,mal,esperado", [
        ("url", DATOS_URL, 3, TITULOS["url_maliciosa"]),
        ("url", DATOS_URL, 0, TITULOS["url_segura"]),
        ("hash", DATOS_HASH, 1, TITULOS["hash_malicioso"]),
        ("hash", DATOS_HASH, 0, TITULOS["hash_seguro"]),
        ("ip", DATOS_IP, 2, TITULOS["ip_maliciosa"]),
        ("ip", DATOS_IP, 0, TITULOS["ip_segura"]),
        ("file", DATOS_FILE, 5, TITULOS["archivo_malicioso"]),
        ("file", DATOS_FILE, 0, TITULOS["archivo_seguro"]),
    ])
    def test_titulo_correcto(self, tipo, datos, mal, esperado):
        assert emb.resultado(tipo, datos, mal).title == f"{EMOJI_SHIELD} {esperado}"

    def test_vocabulario_de_errores_cerrado(self):
        assert emb.error_analisis("x").title.endswith(TITULOS["error_analisis"])
        assert emb.error_conexion("x").title.endswith(TITULOS["error_conexion"])
        assert emb.error_cuota().title.endswith(TITULOS["error_cuota"])

    def test_los_tres_errores_llevan_el_mismo_icono(self):
        titulos = {
            emb.error_analisis("x").title,
            emb.error_conexion("x").title,
            emb.error_cuota().title,
        }
        prefijos = {t.split(" ", 1)[0] for t in titulos}
        assert prefijos == {EMOJI_INCORRECTO}, f"iconos inconsistentes: {titulos}"

    def test_sentence_case_en_titulos(self):
        """Solo los nombres propios llevan mayúscula."""
        for clave, texto in TITULOS.items():
            if clave in ("error_analisis", "error_conexion", "error_cuota"):
                continue
            primera = texto[0]
            assert primera.islower(), f"{clave}: {texto!r} empieza en mayúscula"

    def test_titulos_unicos(self):
        assert len(set(TITULOS.values())) == len(TITULOS)


class TestGuardiaDeTitulosViejos:
    """Si un título viejo reaparece en el código, el rediseño se ha deshecho."""

    FICHEROS = ["api", "ui", "cogs", "core", "bot.py"]

    def _fuente(self):
        for base in self.FICHEROS:
            ruta = os.path.join(RAIZ, base)
            rutas = [ruta] if os.path.isfile(ruta) else [
                os.path.join(ruta, f) for f in sorted(os.listdir(ruta)) if f.endswith(".py")
            ]
            for r in rutas:
                if r.endswith("embed.py"):
                    continue
                with open(r, encoding="utf-8") as fh:
                    yield r, fh.read()

    @pytest.mark.parametrize("prohibido", TITULOS_PROHIBIDOS)
    def test_no_reaparece(self, prohibido):
        for ruta, texto in self._fuente():
            assert prohibido not in texto, f"'{prohibido}' reaparece en {ruta}"

    def test_ningun_embed_construido_a_mano(self):
        """ui/embed.py debe ser el único que llama a discord.Embed()."""
        for ruta, texto in self._fuente():
            assert "discord.Embed(" not in texto, f"discord.Embed() fuera de ui/embed.py en {ruta}"

    def test_ningun_color_literal_de_discord(self):
        for ruta, texto in self._fuente():
            for patron in ("Color.gold(", "Color.blue(", "Color.dark_blue(",
                           "Color.orange(", "Color.green(", "Color.red("):
                assert patron not in texto, f"{patron} en {ruta}: usar los tokens de core.config"

    def test_sin_el_truco_de_espacio_cero(self):
        for ruta, texto in self._fuente():
            assert "\\u200b" not in texto, f"el truco \\u200b sigue en {ruta}"


class TestCampos:
    def test_vocabulario_cerrado_de_campos(self):
        permitidos = {"URL", "Hash", "IP", "Archivo", "Detectado por", "VirusTotal", "Detalle"}
        for e in (emb.resultado("url", DATOS_URL, 3), emb.resultado("hash", DATOS_HASH, 1),
                  emb.resultado("ip", DATOS_IP, 0), emb.resultado("file", DATOS_FILE, 0),
                  emb.error_analisis("x", detalle="d")):
            for n in nombres_campos(e):
                limpio = re.sub(r"^\W*\s*", "", n)
                assert any(limpio.endswith(p) or limpio == p for p in permitidos), f"campo inesperado: {n!r}"

    def test_campos_valor_que_ya_ordena(self):
        esperado = [f"{EMOJI_LINK} URL", f"{EMOJI_GUARDIAN} Detectado por", f"{EMOJI_LINK} VirusTotal"]
        assert nombres_campos(emb.resultado("url", DATOS_URL, 3)) == esperado

    def test_sin_detectado_por_si_no_hay_datos(self):
        assert "Detectado por" not in nombres_campos(emb.resultado("url", DATOS_IP, 3))

    def test_sin_vt_link_no_hay_campo_vt(self):
        assert "VirusTotal" not in nombres_campos(emb.resultado("file", DATOS_FILE, 5))

    def test_vt_link_solo_si_existe(self):
        assert "VirusTotal" in nombres_campos(emb.resultado("url", DATOS_URL, 3))

    def test_error_con_detalle(self):
        e = emb.error_analisis("desc", detalle="porque sí")
        assert "Detalle" in nombres_campos(e)
        assert "porque sí" in e.fields[0].value

    def test_error_sin_detalle_no_crea_campo(self):
        assert "Detalle" not in nombres_campos(emb.error_analisis("desc"))

    def test_amenaza_lleva_id_explicito(self):
        u = type("U", (), {"mention": "<@1>", "id": 12345})()
        e = emb.amenaza("URL", "http://x", "3 detecciones", u)
        nombres = nombres_campos(e)
        assert "ID" in nombres
        assert "12345" in [f.value for f in e.fields if f.name == "ID"][0]

    def test_amenaza_escapa_el_valor_en_code_block(self):
        """El valor viene de un mensaje de usuario: si no va en code block podría
        inyectar markdown y romper la maquetación del embed de moderación."""
        malicioso = "http://x\n**inyectado**"
        u = type("U", (), {"mention": "<@1>", "id": 1})()
        e = emb.amenaza("URL", malicioso, "d", u)
        campo = next(f for f in e.fields if f.name.endswith("Valor"))
        assert campo.value.startswith("```") and campo.value.endswith("```")


class TestRenderOnRead:
    def test_resultado_es_puro(self):
        """Mismos datos -> mismo embed. Es lo que hace seguro el render-on-read."""
        a = emb.resultado("url", DATOS_URL, 3)
        b = emb.resultado("url", DATOS_URL, 3)
        assert a.to_dict() == b.to_dict()

    def test_puro_entre_llamadas_con_otros_tipos_mezclados(self):
        emb.resultado("hash", DATOS_HASH, 1)
        emb.resultado("file", DATOS_FILE, 9)
        a = emb.resultado("url", DATOS_URL, 3)
        b = emb.resultado("url", DATOS_URL, 3)
        assert a.to_dict() == b.to_dict()

    def test_no_depende_del_estado_global(self):
        primero = emb.resultado("ip", DATOS_IP, 2).to_dict()
        emb.aviso("otro", "cosa", color=emb.COLOR_TOPGG)
        assert emb.resultado("ip", DATOS_IP, 2).to_dict() == primero

    def test_descripcion_consistente_entre_tipos(self):
        mal = emb.resultado("url", DATOS_URL, 3)
        ok = emb.resultado("url", DATOS_URL, 0)
        assert "3" in mal.description and "detecciones" in mal.description
        assert ok.description == "Sin detecciones"

    def test_serializable(self):
        """El embed tiene que poder ir a to_dict/from_dict: es lo que se guarda en caché."""
        e = emb.resultado("url", DATOS_URL, 3)
        hidratado = discord.Embed.from_dict(e.to_dict())
        assert hidratado.title == e.title
        assert hidratado.color == e.color
        assert [f.name for f in hidratado.fields] == [f.name for f in e.fields]


class TestBarra:
    def test_barra_rellena(self):
        assert emb.resultado_barra(100.0, 10, 10).startswith("█" * 10)

    def test_barra_vacia(self):
        assert "░" in emb.resultado_barra(0, 0, 10)

    def test_barra_texto(self):
        s = emb.resultado_barra(50, 5, 10)
        assert "50%" in s and "5/10" in s

    def test_barra_acota_por_encima_de_100(self):
        assert emb.resultado_barra(150, 15, 10).count("░") == 0
