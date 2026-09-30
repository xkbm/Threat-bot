"""Regresión de la cuota de API: selección y conteo deben ser atómicos.

Un test que solo compruebe "cuenta bien" pasa también con el código roto, porque
`obtener_siguiente_key` reservaba por su cuenta. Lo que hay que verificar es que N
tareas concurrentes no consigan la misma key por encima del tope.
"""

import asyncio

import pytest

from api import virustotal as vt
from core import state
from core.config import VT_MAX_ANALYSES_PER_DAY, VT_MAX_ANALYSES_PER_MINUTE


class FakeBot:
    def __init__(self) -> None:
        self.vt_key_index = 0
        self.vt_key_usage = {}
        self.vt_key_total_requests = {}
        self.vt_key_daily_usage = {}
        self.se_key_index = 0
        self.se_key_usage = {}
        self.se_key_total_requests = {}
        self.se_key_daily_usage = {}


@pytest.fixture
def fake_bot(monkeypatch):
    original = state.bot
    bot = FakeBot()
    state.bot = bot
    yield bot
    state.bot = original


@pytest.fixture
def una_key(monkeypatch):
    monkeypatch.setattr(vt, "VT_API_KEYS", ["k" * 48])


class TestAdquirirVt:
    @pytest.mark.asyncio
    async def test_devuelve_key_si_hay_cuota(self, fake_bot, una_key):
        assert await vt.adquirir_vt() == "k" * 48

    @pytest.mark.asyncio
    async def test_respeta_el_tope_por_minuto(self, fake_bot, una_key):
        for _ in range(VT_MAX_ANALYSES_PER_MINUTE):
            assert await vt.adquirir_vt() is not None
        assert await vt.adquirir_vt() is None

    @pytest.mark.asyncio
    async def test_concurrencia_no_rompe_el_tope(self, fake_bot, una_key):
        """El bug original: 20 tareas concurrentes obtenían la misma key sin_lock.

        Con un solo key y tope 4, como máximo 4 deben conseguir cuota.
        """
        resultados = await asyncio.gather(*[vt.adquirir_vt() for _ in range(20)])
        concedidas = [r for r in resultados if r is not None]
        assert len(concedidas) == VT_MAX_ANALYSES_PER_MINUTE
        assert len(fake_bot.vt_key_usage["k" * 48]) == VT_MAX_ANALYSES_PER_MINUTE

    @pytest.mark.asyncio
    async def test_ventana_se_libera_al_pasar_el_minuto(self, fake_bot, una_key, monkeypatch):
        reloj = {"t": 1_000_000.0}
        monkeypatch.setattr(vt.time, "time", lambda: reloj["t"])
        for _ in range(VT_MAX_ANALYSES_PER_MINUTE):
            await vt.adquirir_vt()
        assert await vt.adquirir_vt() is None
        reloj["t"] += 61
        assert await vt.adquirir_vt() is not None

    @pytest.mark.asyncio
    async def test_respeta_el_cupo_diario(self, fake_bot, una_key, monkeypatch):
        hoy = vt.time.strftime("%Y-%m-%d", vt.time.gmtime())
        fake_bot.vt_key_daily_usage["k" * 48] = {"count": VT_MAX_ANALYSES_PER_DAY, "date": hoy}
        assert await vt.adquirir_vt() is None

    @pytest.mark.asyncio
    async def test_cuota_diario_se_reinicia_al_cambiar_de_dia(self, fake_bot, una_key, monkeypatch):
        fake_bot.vt_key_daily_usage["k" * 48] = {"count": VT_MAX_ANALYSES_PER_DAY, "date": "2000-01-01"}
        assert await vt.adquirir_vt() is not None

    @pytest.mark.asyncio
    async def test_peticion_rechazada_no_inflaria_el_diario(self, fake_bot, una_key, monkeypatch):
        """Regresión del orden check-then-count: un 429 no debe gastar cupo diario."""
        reloj = {"t": 1_000_000.0}
        monkeypatch.setattr(vt.time, "time", lambda: reloj["t"])
        for _ in range(VT_MAX_ANALYSES_PER_MINUTE):
            await vt.adquirir_vt()
        diario_antes = fake_bot.vt_key_daily_usage["k" * 48]["count"]
        for _ in range(10):
            await vt.adquirir_vt()
        assert fake_bot.vt_key_daily_usage["k" * 48]["count"] == diario_antes

    @pytest.mark.asyncio
    async def test_sin_claves_devuelve_none(self, fake_bot, monkeypatch):
        monkeypatch.setattr(vt, "VT_API_KEYS", [])
        assert await vt.adquirir_vt() is None

    @pytest.mark.asyncio
    async def test_una_peticion_por_adquisicion(self, fake_bot, una_key):
        """`analizar_url` hace hasta 5 peticiones; cada una debe consumir su propio hueco."""
        await vt.adquirir_vt()
        assert len(fake_bot.vt_key_usage["k" * 48]) == 1
        assert fake_bot.vt_key_total_requests["k" * 48] == 1
        await vt.adquirir_vt()
        assert fake_bot.vt_key_total_requests["k" * 48] == 2

    @pytest.mark.asyncio
    async def test_rota_entre_varias_claves(self, fake_bot, monkeypatch):
        keys = ["a" * 48, "b" * 48, "c" * 48]
        monkeypatch.setattr(vt, "VT_API_KEYS", keys)
        obtenidos = [await vt.adquirir_vt() for _ in range(3)]
        assert sorted(obtenidos) == sorted(keys)


class TestObtenerSiguienteSeKey:
    @pytest.mark.asyncio
    async def test_cuenta_cuatro_ops_por_llamada(self, fake_bot, monkeypatch):
        par = ("user", "secret")
        monkeypatch.setattr(vt, "SE_API_KEYS_PAIRS", [par])
        assert await vt.obtener_siguiente_se_key() == par
        assert fake_bot.se_key_daily_usage["user"]["count"] == 4
        assert fake_bot.se_key_total_requests["user"] == 4

    @pytest.mark.asyncio
    async def test_respeta_el_tope_diario(self, fake_bot, monkeypatch):
        from core.config import SE_MAX_OPS_PER_DAY
        hoy = vt.time.strftime("%Y-%m-%d", vt.time.gmtime())
        monkeypatch.setattr(vt, "SE_API_KEYS_PAIRS", [("user", "secret")])
        fake_bot.se_key_daily_usage["user"] = {"count": SE_MAX_OPS_PER_DAY, "date": hoy}
        assert await vt.obtener_siguiente_se_key() is None

    @pytest.mark.asyncio
    async def test_peticion_rechazada_no_gasta_ops(self, fake_bot, monkeypatch):
        from core.config import SE_MAX_OPS_PER_DAY
        hoy = vt.time.strftime("%Y-%m-%d", vt.time.gmtime())
        monkeypatch.setattr(vt, "SE_API_KEYS_PAIRS", [("user", "secret")])
        fake_bot.se_key_daily_usage["user"] = {"count": SE_MAX_OPS_PER_DAY, "date": hoy}
        await vt.obtener_siguiente_se_key()
        assert fake_bot.se_key_daily_usage["user"]["count"] == SE_MAX_OPS_PER_DAY

    @pytest.mark.asyncio
    async def test_sin_pares_devuelve_none(self, fake_bot, monkeypatch):
        monkeypatch.setattr(vt, "SE_API_KEYS_PAIRS", [])
        assert await vt.obtener_siguiente_se_key() is None
