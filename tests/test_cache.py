import time
from unittest.mock import patch

import discord
import pytest

from core import cache
from core.cache import get_from_cache_mem, set_cache_mem

DATOS = {"valor": "https://ejemplo.com", "vt_link": "https://vt/gui/x", "top_text": None}


class TestCacheLegacy:
    """Entradas guardadas con el embed ya renderizado (sin `datos`).

    Son las que puede haber en un analisis.db de antes del sistema de embeds: se
    rehidratan tal cual y no deben romperse.
    """

    @pytest.mark.asyncio
    async def test_missing(self):
        assert await get_from_cache_mem("noexiste") == (None, None, 0)

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        embed = discord.Embed(title="test")
        await set_cache_mem("key1", "seguro", embed, 0)
        tipo, result_embed, mal = await get_from_cache_mem("key1")
        assert tipo == "seguro"
        assert result_embed.title == "test"
        assert mal == 0

    @pytest.mark.asyncio
    async def test_cache_expiry(self):
        await set_cache_mem("key2", "seguro", discord.Embed(title="test"), 0)
        with patch("core.cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 7200
            assert await get_from_cache_mem("key2") == (None, None, 0)

    @pytest.mark.asyncio
    async def test_cache_overwrite(self):
        await set_cache_mem("key3", "seguro", discord.Embed(title="first"), 0)
        await set_cache_mem("key3", "malicioso", discord.Embed(title="second"), 5)
        tipo, result_embed, mal = await get_from_cache_mem("key3")
        assert tipo == "malicioso"
        assert result_embed.title == "second"
        assert mal == 5

    @pytest.mark.asyncio
    async def test_cache_multiple_keys(self):
        embed = discord.Embed(title="test")
        await set_cache_mem("a", "seguro", embed, 0)
        await set_cache_mem("b", "malicioso", embed, 1)
        tipo_a, _, mal_a = await get_from_cache_mem("a")
        tipo_b, _, mal_b = await get_from_cache_mem("b")
        assert tipo_a == "seguro" and mal_a == 0
        assert tipo_b == "malicioso" and mal_b == 1


class TestCacheRenderOnRead:
    """Entradas guardadas con `datos`: el embed se construye al leer.

    Las claves llevan prefijo real (`url:`, `filehash:`…) porque de ahí deduce
    `core.cache` el tipo de elemento que necesita el render.
    """

    @pytest.mark.asyncio
    async def test_renderiza_al_leer(self):
        await set_cache_mem("url:https://ejemplo.com", "malicioso", mal=3, datos=DATOS)
        tipo, embed, mal = await get_from_cache_mem("url:https://ejemplo.com")
        assert tipo == "malicioso"
        assert mal == 3
        assert embed is not None
        assert "maliciosa" in embed.title.lower()
        assert embed.footer.text.startswith("Threat")

    @pytest.mark.asyncio
    async def test_determinista(self):
        """Un cache hit tiene que dar un embed idéntico al original, o /scan
        mostraría dos diseños distintos para el mismo análisis."""
        await set_cache_mem("url:det", "malicioso", mal=3, datos=DATOS)
        _, e1, _ = await get_from_cache_mem("url:det")
        _, e2, _ = await get_from_cache_mem("url:det")
        assert e1.to_dict() == e2.to_dict()

    @pytest.mark.asyncio
    async def test_no_depende_del_embed_pasado(self):
        """Con `datos`, el embed generado no se usa para nada."""
        await set_cache_mem("url:ignorado", "seguro", discord.Embed(title="IGNORADO"), 0, datos=DATOS)
        _, embed, _ = await get_from_cache_mem("url:ignorado")
        assert "IGNORADO" not in (embed.title or "")

    @pytest.mark.asyncio
    async def test_tipos_conocidos(self):
        for tipo, clave in (("url", "url:1"), ("hash", "hash:1"), ("ip", "ip:1"), ("file", "filehash:1")):
            await set_cache_mem(clave, tipo, mal=0, datos=DATOS)
            _, embed, _ = await get_from_cache_mem(clave)
            assert embed is not None, tipo
            assert "Resultado del análisis" not in (embed.title or ""), (
                f"{clave} no se asoció a un tipo de análisis conocido"
            )

    @pytest.mark.asyncio
    async def test_datos_invalidos_no_rompen(self):
        """Una entrada con `datos` inservible no debe tumbar la lectura: se
        devuelve None y el llamante la trata como fallo de caché."""
        # La tupla de RAM es (tipo, mal, tipo_analisis, datos, embed_dict, timestamp).
        cache._cache["url:basura"] = ("url", 0, "url", {"basura": True}, None, time.time())
        _, embed, _ = await get_from_cache_mem("url:basura")
        assert embed is None or embed.title
        cache._cache.pop("url:basura", None)

    @pytest.mark.asyncio
    async def test_expiracion_con_datos(self):
        await set_cache_mem("url:exp", "url", mal=1, datos=DATOS)
        with patch("core.cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 7200
            assert await get_from_cache_mem("url:exp") == (None, None, 0)
