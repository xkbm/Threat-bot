"""Tests del embed unificado y de la deduplicación de mensajes (F2 y F8)."""

import types

import discord
import pytest

from ui.message_handler import (
    ImgUrlResult,
    UrlResult,
    _construir_embed_unificado,
    _huella_mensaje,
    _marcar_procesado,
    _procesados,
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


class TestUrlResult:
    def test_es_una_tupla_named(self):
        r = UrlResult("http://a", "malicioso", 3, "http://vt", "url:http://a", True)
        assert r.url == "http://a"
        assert r.tipo == "malicioso"
        assert r.mal == 3
        assert r.vt_link == "http://vt"
        assert r.elemento_id == "url:http://a"
        assert r.ya_logueado is True


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
    return _construir_embed_unificado(
        fake_message(), list(urls), list(imgs_url), list(imgs), list(archs), omitidos, **kw
    )


class TestEmbedUnificado:
    @pytest.mark.asyncio
    async def test_todo_seguro(self):
        e = await construir(urls=[UrlResult("http://a.com", "seguro", 0, None, "url:http://a.com", False)])
        assert "Todos los elementos son seguros" in e.title
        assert e.color == discord.Color.green()
        assert "Seguros: **1**" in e.description

    @pytest.mark.asyncio
    async def test_url_maliciosa(self):
        e = await construir(urls=[UrlResult("http://a.com", "malicioso", 4, "http://vt", "url:http://a.com", False)])
        assert "Amenazas detectadas" in e.title
        assert e.color == discord.Color.orange()
        assert "Maliciosos: **1**" in e.description

    @pytest.mark.asyncio
    async def test_solo_nsfw_usa_titulo_nsfw(self):
        e = await construir(imgs=[("foto.png", "nsfw", {"nudity": 0.9}, "h1")])
        assert "NSFW" in e.title

    @pytest.mark.asyncio
    async def test_nsfw_por_url_tambien_usa_titulo_nsfw(self):
        e = await construir(imgs_url=[ImgUrlResult("http://i.png", "nsfw", "Desnudez 80%", "nsfw:h")])
        assert "NSFW" in e.title
        assert any("Imágenes (URL)" in f.name for f in e.fields)

    @pytest.mark.asyncio
    async def test_errores(self):
        e = await construir(urls=[UrlResult("http://a.com", "error", 0, None, "url:http://a.com", False)])
        assert "errores" in e.title.lower()
        assert "Errores: **1**" in e.description
        assert e.color == discord.Color.red()

    @pytest.mark.asyncio
    async def test_omitidos_reportados(self):
        e = await construir(urls=[UrlResult("http://a.com", "seguro", 0, None, "u", False)], omitidos=3)
        assert "3** archivo(s) omitido(s)" in e.description

    @pytest.mark.asyncio
    async def test_lista_vacia_devuelve_embed_vacio(self):
        e = await construir()
        assert e.title is not None

    @pytest.mark.asyncio
    async def test_campos_de_urls(self):
        e = await construir(urls=[
            UrlResult("http://a.com", "seguro", 0, None, "url:http://a.com", False),
            UrlResult("http://b.com", "malicioso", 2, "http://vt", "url:http://b.com", False),
        ])
        nombres = [f.name for f in e.fields]
        assert any("URLs" in n for n in nombres)
        assert any("Enlaces maliciosos" in n for n in nombres)

    @pytest.mark.asyncio
    async def test_conteo_consistente(self):
        e = await construir(
            urls=[UrlResult("http://a", "seguro", 0, None, "u", False)],
            imgs_url=[ImgUrlResult("http://i", "nsfw", "Desnudez 80%", "nsfw:h")],
            imgs=[("f.png", "seguro", {}, "h")],
            archs=[("x.exe", "malicioso", 7, "fh", "Extensión .png pero tipo real text/plain")],
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
            urls=[UrlResult("http://short", "malicioso", 1, "http://vt", "url:http://real.com", False)],
            url_fue_expandida=True, url_original="http://short", url_expandida="http://real.com",
        )
        assert any("Redirección" in f.name for f in e.fields)

    @pytest.mark.asyncio
    async def test_no_rompe_con_muchos_elementos(self):
        urls = [UrlResult(f"http://s{i}.com", "seguro", 0, None, f"url:http://s{i}.com", False) for i in range(5)]
        e = await construir(urls=urls)
        for f in e.fields:
            assert len(f.value) <= 1024
