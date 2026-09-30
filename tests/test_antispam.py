import asyncio
import json

import pytest
from unittest.mock import patch

from core import state
from core.config import (
    ANTISPAM_ANALYSIS_PER_HOUR, ANTISPAM_COOLDOWN, ANTISPAM_WINDOW,
    VT_MAX_ANALYSES_PER_MINUTE,
)
from core.utils import comprobar_antispam, check_vt_user_limit, formatear_espera


class FakeBot:
    """Sustituto mínimo del Bot para probar el antispam sin Discord."""

    def __init__(self) -> None:
        self.user_scan_history = {}
        self.antispam_scan = {}
        self.vt_user_requests = {}


@pytest.fixture
def bot() -> FakeBot:
    return FakeBot()


@pytest.fixture(autouse=True)
def sin_estado_real():
    """Evita que un test toque el state.bot de verdad."""
    original = state.bot
    state.bot = None
    yield
    state.bot = original


class TestComprobarAntispam:
    @pytest.mark.asyncio
    async def test_primer_mensaje_permitido(self, bot):
        permitido, espera = await comprobar_antispam(bot, 1, 2)
        assert permitido is True
        assert espera == 0

    @pytest.mark.asyncio
    async def test_registra_el_consumo(self, bot):
        await comprobar_antispam(bot, 1, 2)
        assert len(bot.user_scan_history[(1, 2)]) == 1
        assert (1, 2) in bot.antispam_scan

    @pytest.mark.asyncio
    async def test_cooldown_bloquea_el_segundo(self, bot):
        await comprobar_antispam(bot, 1, 2)
        with patch("core.utils.time") as mock_time:
            mock_time.time.return_value = bot.antispam_scan[(1, 2)] + (ANTISPAM_COOLDOWN - 1)
            permitido, espera = await comprobar_antispam(bot, 1, 2)
        assert permitido is False
        assert espera == 1

    @pytest.mark.asyncio
    async def test_cooldown_expira(self, bot):
        await comprobar_antispam(bot, 1, 2)
        base = bot.antispam_scan[(1, 2)]
        with patch("core.utils.time") as mock_time:
            mock_time.time.return_value = base + ANTISPAM_COOLDOWN + 1
            permitido, _ = await comprobar_antispam(bot, 1, 2)
        assert permitido is True

    @pytest.mark.asyncio
    async def test_limite_por_hora(self, bot):
        # Se simula el paso del cooldown en cada iteración para aislar el límite horario.
        base = 1_000_000.0
        reloj = {"t": base}
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            for _ in range(ANTISPAM_ANALYSIS_PER_HOUR):
                reloj["t"] += ANTISPAM_COOLDOWN + 1
                permitido, _ = await comprobar_antispam(bot, 1, 2)
                assert permitido is True, "no debe bloquear antes de agotar el cupo"
            reloj["t"] += ANTISPAM_COOLDOWN + 1
            permitido, espera = await comprobar_antispam(bot, 1, 2)
        assert permitido is False
        assert espera > 0

    @pytest.mark.asyncio
    async def test_limite_horario_poda_la_ventana(self, bot):
        base = 1_000_000.0
        reloj = {"t": base}
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            for _ in range(ANTISPAM_ANALYSIS_PER_HOUR):
                reloj["t"] += ANTISPAM_COOLDOWN + 1
                await comprobar_antispam(bot, 1, 2)
            # Pasada la ventana de una hora, la cuenta vuelve a cero.
            reloj["t"] += ANTISPAM_WINDOW + 1
            permitido, _ = await comprobar_antispam(bot, 1, 2)
        assert permitido is True
        assert len(bot.user_scan_history[(1, 2)]) == 1

    @pytest.mark.asyncio
    async def test_guilds_distintos_no_se_bloquean(self, bot):
        """Regresión: con clave por user_id, un usuario en varios servidores se autobloqueaba."""
        for guild_id in (1, 2, 3):
            permitido, _ = await comprobar_antispam(bot, guild_id, 2)
            assert permitido is True

    @pytest.mark.asyncio
    async def test_usuarios_distintos_no_se_bloquean(self, bot):
        base = 1_000_000.0
        reloj = {"t": base}
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            for i in range(ANTISPAM_ANALYSIS_PER_HOUR + 5):
                reloj["t"] += ANTISPAM_COOLDOWN + 1
                permitido, _ = await comprobar_antispam(bot, 1, 100 + i)
                assert permitido is True

    @pytest.mark.asyncio
    async def test_mensaje_bloqueado_no_gasta_cuota(self, bot):
        """Un mensaje rechazado no debe restar cupo al usuario."""
        base = 1_000_000.0
        reloj = {"t": base}
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            for _ in range(ANTISPAM_ANALYSIS_PER_HOUR):
                reloj["t"] += ANTISPAM_COOLDOWN + 1
                await comprobar_antispam(bot, 1, 2)
            reloj["t"] += 1  # dentro del cooldown: debe ser rechazado
            antes = len(bot.user_scan_history[(1, 2)])
            permitido, _ = await comprobar_antispam(bot, 1, 2)
        assert permitido is False
        assert len(bot.user_scan_history[(1, 2)]) == antes

    @pytest.mark.asyncio
    async def test_sin_guild_usa_clave_plana(self, bot):
        await comprobar_antispam(bot, None, 2)
        assert 2 in bot.user_scan_history


class TestCheckVtUserLimit:
    @pytest.mark.asyncio
    async def test_permite_hasta_el_tope(self, bot):
        base = 1_000_000.0
        reloj = {"t": base}
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            for _ in range(VT_MAX_ANALYSES_PER_MINUTE):
                reloj["t"] += 1
                assert await check_vt_user_limit(bot, 1, 2) is True
            reloj["t"] += 1
            assert await check_vt_user_limit(bot, 1, 2) is False

    @pytest.mark.asyncio
    async def test_ventana_de_un_minuto_expira(self, bot):
        base = 1_000_000.0
        reloj = {"t": base}
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            for _ in range(VT_MAX_ANALYSES_PER_MINUTE):
                reloj["t"] += 1
                await check_vt_user_limit(bot, 1, 2)
            reloj["t"] += 61
            assert await check_vt_user_limit(bot, 1, 2) is True

    @pytest.mark.asyncio
    async def test_guilds_distintos_no_se_bloquean(self, bot):
        for guild_id in (1, 2, 3, 4, 5):
            assert await check_vt_user_limit(bot, guild_id, 2) is True


class TestFormatearEspera:
    def test_solo_segundos(self):
        assert formatear_espera(12) == "12s"

    def test_minutos_y_segundos(self):
        assert formatear_espera(252) == "4m 12s"

    def test_minutos_exactos(self):
        assert formatear_espera(120) == "2m 0s"

    def test_negativo_se_trunca_a_cero(self):
        assert formatear_espera(-5) == "0s"

    def test_asyncio_sleep_no_rompe(self):
        assert asyncio.iscoroutinefunction(comprobar_antispam)


class TestPersistenciaDeClaves:
    """La clave en memoria es una tupla (guild_id, user_id). Si al recargar del JSON
    quedara como lista, (1, 2) y [1, 2] serían claves distintas y el límite horario se
    perdería en cada reinicio."""

    def test_roundtrip_de_tupla(self):
        from core.database import _restaurar_claves_antispam, _serializar_clave_antispam

        original = {(1, 2): [1.0, 2.0], (3, 4): [5.0]}
        serializado = {_serializar_clave_antispam(k): v for k, v in original.items()}
        assert all(isinstance(s, str) for s in serializado)
        assert json.loads(next(iter(serializado))) == [1, 2]

        restaurado = _restaurar_claves_antispam(serializado)
        assert restaurado == original
        assert (1, 2) in restaurado
        assert isinstance(next(iter(restaurado)), tuple)

    def test_roundtrip_de_clave_plana(self):
        from core.database import _restaurar_claves_antispam, _serializar_clave_antispam

        serializado = {_serializar_clave_antispam(77): [1.0]}
        assert _restaurar_claves_antispam(serializado) == {77: [1.0]}

    def test_ignora_claves_corruptas(self):
        from core.database import _restaurar_claves_antispam

        assert _restaurar_claves_antispam({"[roto": [], "abc": [], "5": []}) == {}

    @pytest.mark.asyncio
    async def test_el_limite_sobrevive_al_reinicio(self, bot):
        from core.database import _restaurar_claves_antispam, _serializar_clave_antispam

        base = 1_000_000.0
        reloj = {"t": base}
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            for _ in range(ANTISPAM_ANALYSIS_PER_HOUR):
                reloj["t"] += ANTISPAM_COOLDOWN + 1
                await comprobar_antispam(bot, 1, 2)

        # Simular un reinicio: volcar a JSON y recargar en otro bot.
        volcado = {_serializar_clave_antispam(k): v for k, v in bot.user_scan_history.items()}
        reiniciado = FakeBot()
        reiniciado.user_scan_history = _restaurar_claves_antispam(volcado)
        assert len(reiniciado.user_scan_history[(1, 2)]) == ANTISPAM_ANALYSIS_PER_HOUR

        reloj["t"] += ANTISPAM_COOLDOWN + 1
        with patch("core.utils.time") as mock_time:
            mock_time.time.side_effect = lambda: reloj["t"]
            permitido, espera = await comprobar_antispam(reiniciado, 1, 2)
        assert permitido is False
        assert espera > 0
