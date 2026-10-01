"""Tests del embed unificado y de la deduplicación de mensajes (F2 y F8)."""

import types

import discord
import pytest

from ui import embed as emb
from core.senales import desde_tuplas
from ui.message_handler import (
    ImgUrlResult,
    UrlResult,
    _construir_embed_unificado,
    _huella_mensaje,
    _marcar_procesado,
    _procesados,
    debe_borrar,
    limpiar_cache_procesados,
)


def fake_message(content="hola", attachments=None, author_name="Ana", message_id=1):
    return types.SimpleNamespace(
        id=message_id,
        content=content,
        attachments=attachments or [],
        author=types.SimpleNamespace(mention=f"<@{author_name}>"),
    )


@pytest.fixture(autouse=True)
def limpiar_huellas():
    _procesados.clear()
    yield
    _procesados.clear()


class TestHuellaDeMensaje:
    def test_mismo_contenido_misma_huella(self):
        a = _huella_mensaje(fake_message("https://ejemplo.com"))
        b = _huella_mensaje(fake_message("https://ejemplo.com"))
        assert a == b

    def test_contenido_distinto_huella_distinta(self):
        a = _huella_mensaje(fake_message("uno"))
        b = _huella_mensaje(fake_message("dos"))
        assert a != b

    def test_adjuntos_cuentan(self):
        adj = types.SimpleNamespace(id=7, size=100, filename="a.png")
        a = _huella_mensaje(fake_message("x"))
        b = _huella_mensaje(fake_message("x", attachments=[adj]))
        assert a != b

    def test_orden_de_adjuntos_irrelevante(self):
        a1 = types.SimpleNamespace(id=1, size=10, filename="a")
        a2 = types.SimpleNamespace(id=2, size=20, filename="b")
        x = _huella_mensaje(fake_message("x", attachments=[a1, a2]))
        y = _huella_mensaje(fake_message("x", attachments=[a2, a1]))
        assert x == y


class TestMarcarProcesado:
    def test_primera_vez_se_procesa(self):
        assert _marcar_procesado(fake_message("hola")) is True

    def test_mismo_id_mismo_contenido_se_omite(self):
        """Regresión de F8: editar sin cambios reprocesaba y recalentaba /stats."""
        m = fake_message("hola")
        assert _marcar_procesado(m) is True
        assert _marcar_procesado(m) is False
        assert _marcar_procesado(m) is False

    def test_contenido_cambiado_se_procesa(self):
        assert _marcar_procesado(fake_message("seguro")) is True
        assert _marcar_procesado(fake_message("malicioso")) is True

    def test_ids_distintos_se_procesan(self):
        assert _marcar_procesado(fake_message("x", message_id=1)) is True
        assert _marcar_procesado(fake_message("x", message_id=2)) is True

    def test_huella_expirada_se_procesa(self, monkeypatch):
        import ui.message_handler as mh
        reloj = {"t": 1_000_000.0}
        monkeypatch.setattr(mh.time, "time", lambda: reloj["t"])
        m = fake_message("x")
        assert _marcar_procesado(m) is True
        assert _marcar_procesado(m) is False
        reloj["t"] += mh._HUELLA_TTL + 1
        assert _marcar_procesado(m) is True

    def test_tiene_tope_de_entradas(self, monkeypatch):
        import ui.message_handler as mh
        for i in range(mh._HUELLA_MAX + 50):
            _marcar_procesado(fake_message(f"m{i}", message_id=i))
        assert len(_procesados) <= mh._HUELLA_MAX

    def test_purga_expired(self, monkeypatch):
        import ui.message_handler as mh
        reloj = {"t": 1_000_000.0}
        monkeypatch.setattr(mh.time, "time", lambda: reloj["t"])
        _marcar_procesado(fake_message("x", message_id=1))
        assert limpiar_cache_procesados() == 0
        reloj["t"] += mh._HUELLA_TTL + 1
        assert limpiar_cache_procesados() == 1
        assert _procesados == {}


class TestRedireccion:
    """La redirección se deduce de UrlResult.redireccion, no de parámetros sueltos.
    Antes solo se rellenaba en la rama de URL única, así que con varias URLs se perdía."""

    @pytest.mark.asyncio
    async def test_sin_redireccion_no_hay_campo(self):
        e = await construir(urls=[UrlResult("https://x.com", "seguro", 0, None, "u", False, None)])
        assert not any("Redirecci" in f.name for f in e.fields)

    @pytest.mark.asyncio
    async def test_una_redireccion_en_singular(self):
        e = await construir(urls=[
            UrlResult("https://bit.ly/a", "seguro", 0, None, "u1", False, "https://destino.example/promo"),
        ])
        campo = next(f for f in e.fields if "Redirecci" in f.name)
        assert campo.name.endswith("Redirección"), campo.name
        assert "bit.ly/a" in campo.value and "destino.example/promo" in campo.value

    @pytest.mark.asyncio
    async def test_varias_redirecciones_en_plural(self):
        e = await construir(urls=[
            UrlResult("https://bit.ly/a", "malicioso", 4, "http://vt/a", "u1", False, "https://evil.com/falsa"),
            UrlResult("https://github.com/x", "seguro", 0, None, "u2", True, None),
            UrlResult("https://tinyurl.com/z", "error", 0, None, "u3", False, "https://destino.example/promo"),
        ])
        campo = next(f for f in e.fields if "Redirecci" in f.name)
        assert campo.name.endswith("Redirecciones"), campo.name
        assert "https://evil.com/falsa" in campo.value
        assert "https://destino.example/promo" in campo.value
        # La que no redirige no debe aparecer.
        assert "github.com" not in campo.value


class TestUrlResult:
    def test_es_una_tupla_named(self):
        r = UrlResult("http://a", "malicioso", 3, "http://vt", "url:http://a", True)
        assert r.url == "http://a"
        assert r.tipo == "malicioso"
        assert r.mal == 3
        assert r.vt_link == "http://vt"
        assert r.elemento_id == "url:http://a"
        assert r.ya_logueado is True

    def test_redireccion_opcional(self):
        assert UrlResult("http://a", "seguro", 0, None, "u", False).redireccion is None
        assert UrlResult("http://a", "seguro", 0, None, "u", False).es_redireccion is False

    def test_es_redireccion(self):
        r = UrlResult("http://a", "seguro", 0, None, "u", False, "http://b")
        assert r.redireccion == "http://b"
        assert r.es_redireccion is True


class TestImgUrlResult:
    def test_campos(self):
        r = ImgUrlResult("http://i.png", "nsfw", "Desnudez 80%", "nsfw:abc")
        assert r.url == "http://i.png"
        assert r.tipo == "nsfw"
        assert r.detalles == "Desnudez 80%"
        assert r.elemento_id == "nsfw:abc"

    def test_elemento_id_opcional(self):
        assert ImgUrlResult("http://i.png", "seguro", "").elemento_id == ""


def construir(urls=(), imgs_url=(), imgs=(), archs=(), omitidos=0, **kw):
    """Adapta las tuplas de siempre a `Senales` y llama al embed.

    El embed recibe `Senales` (una sola fuente de verdad para veredicto, título, color e
    icono) en vez de las cuatro listas de tuplas. El helper traduce para que los tests
    sigan describiendo el caso con la forma que ya usaban.
    """
    senales = desde_tuplas(list(urls), list(imgs_url), list(imgs), list(archs))
    senales.omitidos = omitidos
    senales.whitelist_omitidos = kw.get("whitelist_omitidos", 0)
    return _construir_embed_unificado(fake_message(), senales)


class TestEmbedUnificado:
    @pytest.mark.asyncio
    async def test_todo_seguro(self):
        e = await construir(urls=[UrlResult("http://a.com", "seguro", 0, None, "url:http://a.com", False)])
        assert "Todos los elementos son seguros" in e.title
        assert e.color == discord.Color(emb.COLOR_SEGURO)
        assert "Seguros: **1**" in e.description

    @pytest.mark.asyncio
    async def test_url_maliciosa(self):
        e = await construir(urls=[UrlResult("http://a.com", "malicioso", 4, "http://vt", "url:http://a.com", False)])
        assert "Amenazas detectadas" in e.title
        assert e.color == discord.Color(emb.COLOR_MALICIOSO)
        assert "Maliciosos: **1**" in e.description

    @pytest.mark.asyncio
    async def test_solo_nsfw_usa_titulo_nsfw(self):
        e = await construir(imgs=[("foto.png", "nsfw", {"nudity": 0.9}, "h1")])
        assert "Contenido NSFW detectado" in e.title

    @pytest.mark.asyncio
    async def test_nsfw_por_url_tambien_usa_titulo_nsfw(self):
        e = await construir(imgs_url=[ImgUrlResult("http://i.png", "nsfw", "Desnudez 80%", "nsfw:h")])
        assert "Contenido NSFW detectado" in e.title
        assert any("Imágenes (URL)" in f.name for f in e.fields)

    @pytest.mark.asyncio
    async def test_errores(self):
        e = await construir(urls=[UrlResult("http://a.com", "error", 0, None, "url:http://a.com", False)])
        assert "errores" in e.title.lower()
        assert "Errores: **1**" in e.description
        assert e.color == discord.Color(emb.COLOR_ERROR)

    @pytest.mark.asyncio
    async def test_omitidos_reportados(self):
        e = await construir(urls=[UrlResult("http://a.com", "seguro", 0, None, "u", False)], omitidos=3)
        assert "3** archivo(s) omitido(s)" in e.description

    @pytest.mark.asyncio
    async def test_lista_vacia_devuelve_embed_vacio(self):
        e = await construir()
        assert e.title is not None

    @pytest.mark.asyncio
    async def test_tiene_pie_de_marca(self):
        e = await construir(urls=[UrlResult("http://a.com", "seguro", 0, None, "u", False)])
        assert e.footer.text.startswith(emb.MARCA), e.footer.text

    @pytest.mark.asyncio
    async def test_tiene_escudo(self):
        e = await construir(urls=[UrlResult("http://a.com", "seguro", 0, None, "u", False)])
        assert e.title.startswith(emb.EMOJI_SHIELD)

    @pytest.mark.asyncio
    async def test_campos_de_urls(self):
        e = await construir(urls=[
            UrlResult("http://a.com", "seguro", 0, None, "u1", False),
            UrlResult("http://b.com", "malicioso", 2, "http://vt", "u2", False),
        ])
        nombres = [f.name for f in e.fields]
        assert any("URLs" in n for n in nombres)
        # Las URLs maliciosas ya salen en el campo URLs con su icono y su informe;
        # no debe existir un segundo campo que las repita.
        assert not any("Enlaces maliciosos" in n for n in nombres)

    @pytest.mark.asyncio
    async def test_una_linea_por_url_sin_linea_vacia(self):
        e = await construir(urls=[
            UrlResult("http://a.com", "seguro", 0, None, "u1", False),
            UrlResult("http://b.com", "malicioso", 2, "http://vt", "u2", False),
            UrlResult("http://c.com", "error", 0, None, "u3", False),
        ])
        campo = next(f for f in e.fields if "URLs" in f.name)
        lineas = campo.value.split("\n")
        assert len(lineas) == 3, lineas
        assert all(l.strip() for l in lineas), "ninguna línea puede estar vacía"
        assert not campo.value.endswith("\n")

    @pytest.mark.asyncio
    async def test_informe_usa_la_etiqueta_unica(self):
        e = await construir(urls=[
            UrlResult("http://b.com", "malicioso", 2, "http://vt", "u2", False),
        ])
        campo = next(f for f in e.fields if "URLs" in f.name)
        assert f"[{emb.ETIQUETA_INFORME}](http://vt)" in campo.value
        assert "Ver informe" not in campo.value
        assert "[VT]" not in campo.value

    @pytest.mark.asyncio
    async def test_url_sin_informe_no_lleva_enlace(self):
        e = await construir(urls=[UrlResult("http://a.com", "seguro", 0, None, "u1", False)])
        campo = next(f for f in e.fields if "URLs" in f.name)
        assert "](" not in campo.value, campo.value

    @pytest.mark.asyncio
    async def test_conteo_consistente(self):
        e = await construir(
            urls=[UrlResult("http://a", "seguro", 0, None, "u", False)],
            imgs_url=[ImgUrlResult("http://i", "nsfw", "Desnudez 80%", "nsfw:h")],
            imgs=[("f.png", "seguro", {}, "h")],
            archs=[("x.exe", "malicioso", 7, "fh", "Extensión .png pero tipo real text/plain", False)],
        )
        assert "Seguros: **2**" in e.description
        assert "Maliciosos: **1**" in e.description
        assert "NSFW: **1**" in e.description
        nombres = [f.name for f in e.fields]
        assert not any("Redirección" in n for n in nombres)
        assert any("Archivos" in n for n in nombres)

    @pytest.mark.asyncio
    async def test_redireccion_aparece(self):
        e = await construir(
            urls=[UrlResult("http://short", "malicioso", 1, "http://vt", "url:http://real.com", False,
                            "http://real.com")],
        )
        assert any("Redirecci" in f.name for f in e.fields)

    @pytest.mark.asyncio
    async def test_no_rompe_con_muchos_elementos(self):
        urls = [UrlResult(f"http://s{i}.com", "seguro", 0, None, f"url:http://s{i}.com", False) for i in range(5)]
        e = await construir(urls=urls)
        for f in e.fields:
            assert len(f.value) <= 1024


class TestSospechosoEnElEmbedUnificado:
    @pytest.mark.asyncio
    async def test_url_sospechosa(self):
        e = await construir(urls=[UrlResult("http://a.com", "sospechoso", 0, "http://vt", "u", False)])
        assert "sospechos" in e.title.lower()
        assert e.color == discord.Color(emb.COLOR_SOSPECHOSO)
        assert "Sospechosos: **1**" in e.description

    @pytest.mark.asyncio
    async def test_no_cuenta_como_seguro(self):
        """El fallo original de leer solo `malicious`: un sospechoso salía como
        'Sin detecciones' y con el contador de seguros a 1."""
        e = await construir(urls=[UrlResult("http://a.com", "sospechoso", 0, "http://vt", "u", False)])
        assert "Seguros: **0**" in e.description
        assert "Sospechosos: **1**" in e.description

    @pytest.mark.asyncio
    async def test_el_malicioso_manda_en_el_titulo(self):
        e = await construir(urls=[
            UrlResult("http://a.com", "sospechoso", 0, "http://vt", "u1", False),
            UrlResult("http://b.com", "malicioso", 3, "http://vt", "u2", False),
        ])
        assert "Amenazas detectadas" in e.title
        assert e.color == discord.Color(emb.COLOR_MALICIOSO)
        # Los dos contadores aparecen: el sospechoso no desaparece por estar junto a
        # un malicioso.
        assert "Maliciosos: **1**" in e.description
        assert "Sospechosos: **1**" in e.description

    @pytest.mark.asyncio
    async def test_el_sospechoso_manda_al_error(self):
        """Un sospechoso es un hallazgo; un error es "no se pudo comprobar". Si hay
        ambos, el hallazgo manda: el moderador tiene algo que mirar aunque otro
        elemento se quedara sin analizar."""
        e = await construir(urls=[
            UrlResult("http://a.com", "sospechoso", 0, "http://vt", "u1", False),
            UrlResult("http://b.com", "error", 0, None, "u2", False),
        ])
        assert e.color == discord.Color(emb.COLOR_SOSPECHOSO)
        # El error no desaparece: sigue contado.
        assert "Errores: **1**" in e.description
        assert "Sospechosos: **1**" in e.description


class TestDobleExtensionYMime:
    @pytest.mark.asyncio
    async def test_doble_extension_aparece_en_el_embed(self):
        e = await construir(archs=[("informe.pdf.exe", "seguro", 0, "fh", "", True)])
        campo = next(f for f in e.fields if "Archivos" in f.name)
        assert "Doble extensión" in campo.value

    @pytest.mark.asyncio
    async def test_mime_sigue_apareciendo(self):
        e = await construir(archs=[("foto.png", "seguro", 0, "fh", "tipo real text/html", False)])
        campo = next(f for f in e.fields if "Archivos" in f.name)
        assert "text/html" in campo.value
        assert "Doble extensión" not in campo.value

    @pytest.mark.asyncio
    async def test_las_dos_avisos_a_la_vez(self):
        e = await construir(archs=[("foto.png.exe", "seguro", 0, "fh", "tipo real text/html", True)])
        campo = next(f for f in e.fields if "Archivos" in f.name)
        assert "Doble extensión" in campo.value
        assert "text/html" in campo.value


class TestDebeBorrar:
    """El modo estricto leía el slot del MIMEMismatch creyendo que era el de la doble
    extensión, así que borraba por el motivo equivocado y nunca por doble extensión.
    """

    @pytest.mark.parametrize("amenaza,doble_ext,mime,estricto,esperado", [
        # Con el modo estricto apagado nunca se borra.
        (True, True, True, False, False),
        (True, False, False, False, False),
        # Amenaza confirmada: siempre borra con el modo estricto puesto.
        (True, False, False, True, True),
        # Doble extensión real: este es el caso que antes NUNCA borraba.
        (False, True, False, True, True),
        # MIMEMismatch: el que sí borraba antes, y sigue borrando.
        (False, False, True, True, True),
        # Un archivo limpio no se toca.
        (False, False, False, True, False),
    ])
    def test_todas_las_combinaciones(self, amenaza, doble_ext, mime, estricto, esperado):
        assert debe_borrar(amenaza, doble_ext, mime, estricto) is esperado
