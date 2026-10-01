"""Cuota de SightEngine: espaciado por segundo y caché de fallos.

Dos cosas que costaban cuota sin que se notara:

1. `SE_MAX_REQUESTS_PER_SECOND` estaba declarado y no se aplicaba en ningún sitio. El plan
   gratuito da 1 req/s, así que una ráfaga de imágenes se llenaba de 429.
2. Ninguna ruta de fallo se cacheaba. La cara es `sin_modelos`, que es un **200**: la API
   respondió y cobró sus operaciones, y al no cachearse cada reaparición de esa imagen
   volvía a pagar las 5. Con 2.000 operaciones al mes, 400 imágenes quemadas.
"""

import time

import pytest

from core.config import EXPIRACION


class TestElEspaciadoPorSegundo:
    @pytest.mark.asyncio
    async def test_separa_las_peticiones(self, monkeypatch):
        import asyncio

        import api.virustotal as vt
        from core.config import SE_MAX_REQUESTS_PER_SECOND

        monkeypatch.setattr(vt, "_se_ultima_peticion", 0.0)
        inicio = time.time()
        for _ in range(3):
            await vt.esperar_turno_se()
        elapsed = time.time() - inicio

        esperado = (3 - 1) / SE_MAX_REQUESTS_PER_SECOND
        assert elapsed >= esperado * 0.7, (
            f"3 peticiones en {elapsed:.2f}s; el plan gratuito permite "
            f"{SE_MAX_REQUESTS_PER_SECOND} req/s"
        )

    @pytest.mark.asyncio
    async def test_un_limite_de_cero_no_espera(self, monkeypatch):
        """Un valor a 0 significa "sin límite": no puede ser un `sleep` infinito."""
        import api.virustotal as vt

        monkeypatch.setattr(vt, "_se_ultima_peticion", time.time())
        monkeypatch.setattr(vt, "SE_MAX_REQUESTS_PER_SECOND", 0)
        inicio = time.time()
        await vt.esperar_turno_se()
        assert time.time() - inicio < 0.2

    def test_el_limite_esta_declarado(self):
        from core.config import SE_MAX_REQUESTS_PER_SECOND

        assert SE_MAX_REQUESTS_PER_SECOND == 1, (
            "el plan gratuito de SightEngine permite 1 petición por segundo"
        )


class TestReservaPorPeticion:
    def test_el_reintento_consume_tantas_ops_como_peticiones(self):
        """El fallo que existía: una reserva para hasta cinco peticiones."""
        from core.config import SE_OPS_PER_CALL

        from api import sightengine as se

        assert len(se.MODELOS_CON_FALLBACK) >= 2, (
            "si solo hay una combinación, la reserva por petición y la única no se "
            "distinguen y el test no mide nada"
        )
        assert SE_OPS_PER_CALL == 5


class TestCacheDeFallosDeSightEngine:
    @pytest.mark.asyncio
    async def test_un_200_sin_modelos_se_cachea(self, monkeypatch):
        """Es un 200: la API ya cobró. Sin caché, cada repost vuelve a pagar las 5."""
        import aiohttp

        from api import sightengine as se
        from core import state

        class _Bot:
            se_key_index = 0
            se_key_usage = {}
            se_key_total_requests = {}
            se_key_daily_usage = {}

        class _Resp:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def json(self):
                return {"status": "success"}      # 200, pero ningún modelo

        class _Sesion:
            def post(self, *a, **k):
                return _Resp()

        original = state.bot
        state.bot = _Bot()
        state.bot.session = _Sesion()

        guardados = []

        async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
            guardados.append(tipo)

        async def _miss(*a, **k):
            # Ambas cachés devuelven la tupla de 3; un None aquí se desempaqueta.
            return None, None, 0

        async def _nada(*a, **k):
            return None

        async def _con_clave():
            return ("user", "secret")

        monkeypatch.setattr(se, "guardar_analisis_db", _guardar)
        monkeypatch.setattr(se, "obtener_analisis_db", _miss)
        monkeypatch.setattr(se, "get_from_cache_mem", _miss)
        monkeypatch.setattr(se, "obtener_siguiente_se_key", _con_clave)
        monkeypatch.setattr(se, "SE_API_KEYS_PAIRS", [("u", "s")])
        monkeypatch.setattr(se, "esperar_turno_se", _nada)
        monkeypatch.setattr(se, "reservar_se_key", _nada)
        monkeypatch.setattr(se, "SE_TIMEOUT", aiohttp.ClientTimeout(total=1))

        try:
            await se.analizar_imagen_multimodelo("hash", b"\x89PNG")
        finally:
            state.bot = original

        assert "se_sin_modelos" in guardados, (
            f"un 200 sin modelos no se cacheo: {guardados}"
        )

    def test_los_fallos_caros_y_transitorios_tienen_caducidad_propia(self):
        assert EXPIRACION["se_sin_modelos"] == 24 * 3600

    def test_lo_transitorio_caduca_pronto(self):
        """Una hora de memoria: sin ella, una caída provoke avalancha contra la API."""
        assert EXPIRACION["se_transitorio"] == 15 * 60

    def test_lo_carroso_caduca_mas_que_lo_transitorio(self):
        """Un 200 cobrado no se arregla solo en 15 minutos; una caída sí."""
        assert EXPIRACION["se_sin_modelos"] > EXPIRACION["se_transitorio"]

    @pytest.mark.asyncio
    async def test_lo_transitorio_si_se_cachea(self, monkeypatch):
        from api import sightengine as se

        guardados = []

        async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
            guardados.append(tipo)

        monkeypatch.setattr(se, "guardar_analisis_db", _guardar)
        await se._cachear_fallo("c", se.ERROR_HTTP, "HTTP 500")
        await se._cachear_fallo("c", se.ERROR_EXCEPCION, "boom")
        assert guardados == ["se_transitorio", "se_transitorio"]

    @pytest.mark.asyncio
    async def test_lo_gratis_no_se_cachea(self, monkeypatch):
        """Sin cuota y sin claves no cuestan operaciones: cachearlas solo haría que el
        bot siguiera creyendo que no hay cuota después de que la hubiera."""
        from api import sightengine as se

        guardados = []

        async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
            guardados.append(tipo)

        monkeypatch.setattr(se, "guardar_analisis_db", _guardar)
        await se._cachear_fallo("c", se.ERROR_SIN_CUOTA, "x")
        await se._cachear_fallo("c", se.ERROR_SIN_CLAVES, "x")
        await se._cachear_fallo("c", se.ERROR_DEMASIADO_GRANDE, "x")
        assert guardados == []

    @pytest.mark.asyncio
    async def test_un_fallo_que_no_se_puede_cachear_no_revienta(self, monkeypatch):
        """Cachear un fallo es una optimización: si falla, el análisis sigue siendo válido."""
        from api import sightengine as se

        async def _falla(*a, **k):
            raise RuntimeError("base no disponible")

        monkeypatch.setattr(se, "guardar_analisis_db", _falla)
        await se._cachear_fallo("c", se.ERROR_SIN_MODELOS, "x")   # no debe lanzar

    @pytest.mark.asyncio
    async def test_el_error_guardado_llega_al_que_llama(self, monkeypatch):
        """Si se cachea como `no_consultado` a secas, el embed pierde el motivo."""
        from api import sightengine as se

        guardados = {}

        async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
            guardados.update(datos or {})

        monkeypatch.setattr(se, "guardar_analisis_db", _guardar)
        await se._cachear_fallo("c", se.ERROR_SIN_MODELOS, "la respuesta no incluye los modelos")

        assert guardados["error"] == se.ERROR_SIN_MODELOS
        assert guardados["detalle"] == "la respuesta no incluye los modelos"
