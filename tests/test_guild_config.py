import asyncio

import pytest

from core import state
from core.guild_config import (
    _get_guild_lock,
    _guild_locks,
    agregar_dominio,
    obtener_config_guild,
    quitar_dominio,
    registrar_infraccion,
    remove_guild_lock,
)


class FakeBot:
    def __init__(self) -> None:
        self.guilds_data = {}


@pytest.fixture
def fake_bot():
    original = state.bot
    bot = FakeBot()
    state.bot = bot
    yield bot
    state.bot = original


@pytest.fixture(autouse=True)
def no_escribir_datos(monkeypatch):
    """guardar_datos tocaría core/data.json de verdad; aquí no interesa."""
    async def _noop(*args, **kwargs):
        return None
    monkeypatch.setattr("core.guild_config.guardar_datos", _noop)


@pytest.fixture(autouse=True)
def clear_locks():
    _guild_locks.clear()
    yield
    _guild_locks.clear()


class TestGetGuildLock:
    @pytest.mark.asyncio
    async def test_creates(self):
        lock = await _get_guild_lock(123456)
        assert isinstance(lock, asyncio.Lock)
        assert 123456 in _guild_locks

    @pytest.mark.asyncio
    async def test_reuses(self):
        lock1 = await _get_guild_lock(123456)
        lock2 = await _get_guild_lock(123456)
        assert lock1 is lock2

    @pytest.mark.asyncio
    async def test_different_guilds(self):
        lock1 = await _get_guild_lock(111)
        lock2 = await _get_guild_lock(222)
        assert lock1 is not lock2

    @pytest.mark.asyncio
    async def test_remove(self):
        await _get_guild_lock(333)
        assert 333 in _guild_locks
        await remove_guild_lock(333)
        assert 333 not in _guild_locks

    @pytest.mark.asyncio
    async def test_remove_nonexistent(self):
        await remove_guild_lock(999)
        assert 999 not in _guild_locks

    @pytest.mark.asyncio
    async def test_concurrent_creation(self):
        async def create_lock(gid):
            return await _get_guild_lock(gid)

        results = await asyncio.gather(*[create_lock(444) for _ in range(10)])
        assert all(r is results[0] for r in results)
        assert len(_guild_locks) == 1


class TestAgregarDominio:
    """Regresión de F1: el cog hacía `async with _get_guild_lock(...)` sin await,
    que es un AttributeError en runtime."""

    @pytest.mark.asyncio
    async def test_agrega(self, fake_bot):
        assert await agregar_dominio(1, "ejemplo.com") is True
        config = await obtener_config_guild(1)
        assert "ejemplo.com" in config["whitelist"]

    @pytest.mark.asyncio
    async def test_no_duplica(self, fake_bot):
        await agregar_dominio(1, "ejemplo.com")
        assert await agregar_dominio(1, "ejemplo.com") is False
        config = await obtener_config_guild(1)
        assert config["whitelist"].count("ejemplo.com") == 1

    @pytest.mark.asyncio
    async def test_concurrente_no_duplica(self, fake_bot):
        """Dos admins a la vez no deben dejar dos entradas iguales."""
        await asyncio.gather(*[agregar_dominio(1, "ejemplo.com") for _ in range(5)])
        config = await obtener_config_guild(1)
        assert config["whitelist"].count("ejemplo.com") == 1

    @pytest.mark.asyncio
    async def test_crea_guild_si_no_existe(self, fake_bot):
        await agregar_dominio(999, "nuevo.com")
        assert 999 in fake_bot.guilds_data

    @pytest.mark.asyncio
    async def test_guilds_aislados(self, fake_bot):
        await agregar_dominio(1, "solo-uno.com")
        config = await obtener_config_guild(2)
        assert "solo-uno.com" not in config["whitelist"]


class TestQuitarDominio:
    @pytest.mark.asyncio
    async def test_quita(self, fake_bot):
        await agregar_dominio(1, "ejemplo.com")
        assert await quitar_dominio(1, "ejemplo.com") is True
        config = await obtener_config_guild(1)
        assert "ejemplo.com" not in config["whitelist"]

    @pytest.mark.asyncio
    async def test_no_esta_no_falla(self, fake_bot):
        assert await quitar_dominio(1, "nunca-existio.com") is False

    @pytest.mark.asyncio
    async def test_concurrente_es_idempotente(self, fake_bot):
        await agregar_dominio(1, "ejemplo.com")
        resultados = await asyncio.gather(*[quitar_dominio(1, "ejemplo.com") for _ in range(5)])
        assert sum(1 for r in resultados if r) == 1
        config = await obtener_config_guild(1)
        assert "ejemplo.com" not in config["whitelist"]


class TestConfigPorDefecto:
    @pytest.mark.asyncio
    async def test_tiene_todas_las_claves(self, fake_bot):
        config = await obtener_config_guild(1)
        for clave in (
            # `silent_mode` ya no está: se tradujo a `avisar_todo` al leer, y que las dos
            # coexistieran en la configuración era justo el problema que se arregla.
            "avisar_todo", "notificar", "reacciones",
            "strict_mode", "auto_scan_enabled", "log_channel_id", "avisar_amenazas",
            "whitelist", "infracciones", "infracciones_registradas",
        ):
            assert clave in config, f"falta {clave} en la config por defecto"
        assert "silent_mode" not in config, "la clave vieja debe desaparecer al migrar"

    @pytest.mark.asyncio
    async def test_repone_claves_que_faltan(self, fake_bot):
        """Un data.json antiguo sin auto_scan_enabled no debe romper el handler."""
        fake_bot.guilds_data[1] = {"silent_mode": False}   # clave legada
        config = await obtener_config_guild(1)
        # La traducción conserva el comportamiento: `silent_mode: False` ya callaba, y
        # `avisar_todo: False` también.
        assert config["avisar_todo"] is False
        assert "silent_mode" not in config
        assert config["auto_scan_enabled"] is True


class TestRegistrarInfraccion:
    @pytest.mark.asyncio
    async def test_registra_y_deduplica(self, fake_bot):
        assert await registrar_infraccion(1, 55, "url:a") == 1
        assert await registrar_infraccion(1, 55, "url:a") == 1
        assert await registrar_infraccion(1, 55, "url:b") == 2

    @pytest.mark.asyncio
    async def test_crea_guild_con_todas_las_claves(self, fake_bot):
        await registrar_infraccion(7, 55, "url:a")
        assert "auto_scan_enabled" in fake_bot.guilds_data[7]
