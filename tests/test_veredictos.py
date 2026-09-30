"""Veredicto `sospechoso` (F3).

VirusTotal separa `suspicious` de `malicious` en su esquema y el bot solo leía
`malicious`, así que un enlace con tres engines que lo marcan como sospechoso y
ninguno que lo confirme salía con el veredicto "seguro" —el error más frecuente que
puede cometer un antivirus: decirte que algo está bien cuando no está comprobado.
"""

import discord
import pytest

from ui import embed as emb
from core import config


DATOS_URL = {"valor": "https://ejemplo.com", "vt_link": "https://vt/x", "top_text": None}


def color(valor: int) -> discord.Color:
    return discord.Color(valor)


def stats(mal=0, susp=0, harmless=0, undetected=0):
    return {"malicious": mal, "suspicious": susp, "harmless": harmless, "undetected": undetected}


class TestPrecedenciaDeVeredictos:
    @pytest.mark.parametrize("mal,susp,esperado", [
        (3, 5, "malicioso"),   # manda malicioso
        (1, 0, "malicioso"),
        (0, 3, "sospechoso"),   # solo sospechoso
        (0, 0, "seguro"),
    ])
    def test_orden_de_precedencia(self, mal, susp, esperado):
        from api.virustotal import _veredicto
        assert _veredicto(stats(mal=mal, susp=susp)) == esperado

    def test_sin_claves_suspicious_no_rompe(self):
        """VT omite `suspicious` en algunos responses. Leerlo con .get y no con []."""
        from api.virustotal import _veredicto
        assert _veredicto({"malicious": 0}) == "seguro"
        assert _veredicto({"malicious": 2}) == "malicioso"


class TestTitulosYColor:
    @pytest.mark.parametrize("clave", ["url_sospechosa", "hash_sospechoso", "ip_sospechosa", "archivo_sospechoso"])
    def test_el_titulo_existe(self, clave):
        assert clave in emb.TITULOS
        assert emb.TITULOS[clave].startswith(emb.TITULOS[clave][0].upper())

    @pytest.mark.parametrize("tipo", ["url", "hash", "ip", "file"])
    def test_todas_las_tablas_tienen_sospechoso(self, tipo):
        assert (tipo, "sospechoso") in emb._TITULO_RESULTADO

    def test_sospechoso_tiene_color_propio(self):
        assert config.COLOR_SOSPECHOSO not in (config.COLOR_SEGURO, config.COLOR_MALICIOSO, config.COLOR_ERROR)
        assert config.SEVERIDAD_COLOR["sospechoso"] == config.COLOR_SOSPECHOSO

    def test_el_titulo_manda_en_sentence_case(self):
        """`test_sentence_case_en_titulos` recorre TITULOS, pero conviene comprobar
        aquí que el título nuevo no se cuela en Title Case."""
        for clave in ("url_sospechosa", "hash_sospechoso", "ip_sospechosa", "archivo_sospechoso"):
            for palabra in emb.TITULOS[clave].split()[1:]:
                limpia = palabra.strip(".:,()")
                assert not limpia.isupper() or limpia in emb.ACRONIMOS


class TestRender:
    def test_embed_sospechoso(self):
        e = emb.resultado("url", {**DATOS_URL, "veredicto": "sospechoso", "susp": 3}, 0)
        assert emb.TITULOS["url_sospechosa"] in e.title
        assert e.color == color(config.COLOR_SOSPECHOSO)
        assert "3" in e.description

    def test_embed_malicioso_no_cambia(self):
        e = emb.resultado("url", {**DATOS_URL, "veredicto": "malicioso", "susp": 0}, 7)
        assert emb.TITULOS["url_maliciosa"] in e.title
        assert e.color == color(config.COLOR_MALICIOSO)
        assert "7" in e.description

    def test_embed_seguro_no_cambia(self):
        e = emb.resultado("url", {**DATOS_URL, "veredicto": "seguro", "susp": 0}, 0)
        assert emb.TITULOS["url_segura"] in e.title
        assert e.color == color(config.COLOR_SEGURO)


class TestRenderOnRead:
    """El veredicto viaja dentro de `datos`, que es lo que se persiste. Si no, una
    entrada cacheada con veredicto sospechoso se re-renderizaría como segura."""

    def test_datos_con_veredicto(self):
        e = emb.resultado("url", {**DATOS_URL, "veredicto": "sospechoso", "susp": 2}, 0)
        assert "sospechosa" in e.title

    def test_datos_sin_veredicto_cae_a_la_regla_antigua(self):
        """Filas de SQLite anteriores a este cambio no tienen `veredicto`. Tienen que
        seguir renderizando como antes, no romperse ni salir como seguras."""
        e = emb.resultado("url", DATOS_URL, 4)
        assert emb.TITULOS["url_maliciosa"] in e.title

    def test_datos_sin_veredicto_y_sin_detecciones(self):
        e = emb.resultado("url", DATOS_URL, 0)
        assert emb.TITULOS["url_segura"] in e.title

    def test_veredicto_inventado_cae_al_respaldo(self):
        """Un `veredicto` corrupto en la fila no puede romper el render."""
        e = emb.resultado("url", {**DATOS_URL, "veredicto": "inventado"}, 0)
        assert emb.TITULOS["url_segura"] in e.title

    def test_es_puro(self):
        """`resultado()` tiene que seguir siendo pura: mismos datos, mismo embed."""
        datos = {**DATOS_URL, "veredicto": "sospechoso", "susp": 3}
        a = emb.resultado("url", datos, 0)
        b = emb.resultado("file", {"valor": "x", "veredicto": "seguro"}, 0)
        c = emb.resultado("url", datos, 0)
        assert a.to_dict() == c.to_dict()
        assert a.to_dict() != b.to_dict()
