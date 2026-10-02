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
        """Lo que no llega a la API no se cachea: no cuesta nada y no hay nada que evitar.

        Se mantiene para `sin_claves` y `demasiado_grande`. Para `sin_cuota` ya NO es
        cierto, y por eso tiene su propio test abajo: una cuota agotada SÍ se cachea,
        porque hay una petición de por medio y porque repetirla cada pocos minutos durante
        el resto del mes solo genera llamadas que la API va a rechazar.
        """
        from api import sightengine as se

        guardados = []

        async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
            guardados.append(tipo)

        monkeypatch.setattr(se, "guardar_analisis_db", _guardar)
        await se._cachear_fallo("c", se.ERROR_SIN_CLAVES, "x")
        await se._cachear_fallo("c", se.ERROR_DEMASIADO_GRANDE, "x")
        assert guardados == []

    @pytest.mark.asyncio
    async def test_la_cuota_agotada_si_se_cachea(self, monkeypatch):
        """Regresión: la cuota agotada se cacheaba como transitorio y no como cuota.

        Un plan agotado no se arregla esperando 15 minutos: se arregla en el mes que
        viene. Con la caducidad de transitorio, cada imagen que apareciera durante el
        resto del mes llamaba a la API y chocaba contra el mismo muro. Y el embed decía
        "fallo de red", que manda al usuario a reiniciar el router en vez de a esperar.
        """
        from api import sightengine as se

        guardados = []

        async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
            guardados.append(tipo)

        monkeypatch.setattr(se, "guardar_analisis_db", _guardar)
        await se._cachear_fallo("c", se.ERROR_SIN_CUOTA, "agotada")
        assert guardados == ["se_sin_cuota"]

    def test_la_cuota_caduca_mas_que_lo_transitorio(self):
        from core.config import EXPIRACION

        assert EXPIRACION["se_sin_cuota"] > EXPIRACION["se_transitorio"], (
            "esperar 15 minutos no arregla un plan agotado; esperar unas horas tampoco, "
            "pero evita repetir la llamada en cada reaparición de una misma jornada"
        )

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


class TestDistinguirCuotaAgotadaDeFalloDeRed:
    """El plan se acaba un día. Antes el bot decía "fallo de red" y no era verdad.

    Cuando SightEngine rechaza porque se agotó el plan, el código hacía
    `if resp.status != 400: ERROR_HTTP`. Como el status con el que rechaza un plan
    agotado no es 400, todo lo que no fuera un 400 se traducía a "fallo de red", y el
    embed de ese error lo dice literalmente: "Fallo de red o respuesta ilegible de
    SightEngine". Un usuario con el router perfectamente bien leía que tenía la internet
    rota.

    Y como además se cacheaba como transitorio (15 minutos), cada imagen que apareciera
    durante el resto del mes volvía a llamar a la API y a chocar contra el mismo muro.

    Detalle importante: se decide por lo que DICE la respuesta, no por el status. El
    status con el que se rechaza un plan agotado no está documentado, y clavar el
    diagnóstico en un status adivinado sería peor que no comprobarlo.
    """

    @pytest.mark.parametrize("status", [400, 402, 403, 429, 500])
    def test_se_reconoce_por_el_texto_del_error(self, status):
        from api import sightengine as se

        cuerpo = {"status": "failure", "error": {"type": "quota_exceeded",
                                                 "message": "Your plan's monthly quota is used up"}}
        assert se._es_cuota_agotada(cuerpo, status) is True

    def test_un_error_normal_no_se_confunde_con_cuota(self):
        """Un 500 de verdad SÍ es un fallo de red, y debe seguir siéndolo."""
        from api import sightengine as se

        assert se._es_cuota_agotada(
            {"status": "failure", "error": {"type": "internal_error", "message": "oops"}}, 500
        ) is False
        assert se._es_cuota_agotada(None, 500) is False

    def test_un_400_de_modelo_no_disponible_no_es_cuota(self):
        """El 400 de "no tengo ese modelo" no es cuota agotada: es configuración.

        Confundir los dos convertiría "ajusta tus modelos" en "espera al mes que viene".
        """
        from api import sightengine as se

        cuerpo = {"error": {"type": "unsupported_model",
                            "message": "model 'nudity-2.1' not available"}}
        assert se._es_cuota_agotada(cuerpo, 400) is False
        assert se._clasificar_400(cuerpo)[0] == se.ERROR_MODELO_NO_DISPONIBLE

    def test_el_error_aplano_se_lee_tambien(self):
        """La documentación muestra el `error` como objeto y como texto según el endpoint."""
        from api import sightengine as se

        assert se._es_cuota_agotada({"error": "quota exceeded for this month"}, 400) is True

    def test_el_texto_de_error_se_normaliza(self):
        from api import sightengine as se

        texto = se._texto_de_error({"error": {"type": "Plan", "message": "No credits left"}})
        assert "plan" in texto and "credits" in texto
        assert se._texto_de_error(None) == ""
        assert se._texto_de_error({}) == ""


class TestElCableadoDeLaCuota:
    """Estos van a través de `analizar_imagen_multimodelo`, no contra la función suelta.

    Importa porque es exactamente donde fallaban los otros: `liberar_se_key` y
    `_es_cuota_agotada` se podían probar por encima y pasar, mientras el bucle de
    peticiones no llamaba a la primera ni miraba la segunda. Los dos comprobaban que la
    función era correcta, no que nadie la usara — y el defecto era justo que no la usaba.
    """

    async def _analizar_con_respuesta(self, monkeypatch, se, status, cuerpo):
        """Lanza un análisis contra una respuesta HTTP fabricada y devuelve el resultado."""
        import aiohttp

        from core import state

        class _Bot:
            se_key_index = 0
            se_key_usage = {}
            se_key_total_requests = {}
            se_key_daily_usage = {}
            se_key_monthly_usage = {}

        class _Resp:
            def __init__(self):
                self.status = status

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def json(self, content_type=None):
                return cuerpo

        class _Sesion:
            def post(self, *a, **k):
                return _Resp()

        original = state.bot
        state.bot = _Bot()
        state.bot.session = _Sesion()

        async def _nada(*a, **k):
            return None

        async def _miss(*a, **k):
            return None, None, 0

        async def _con_clave():
            return ("user", "secret")

        monkeypatch.setattr(se, "guardar_analisis_db", _nada)
        monkeypatch.setattr(se, "obtener_analisis_db", _miss)
        monkeypatch.setattr(se, "get_from_cache_mem", _miss)
        monkeypatch.setattr(se, "obtener_siguiente_se_key", _con_clave)
        monkeypatch.setattr(se, "SE_API_KEYS_PAIRS", [("u", "s")])
        monkeypatch.setattr(se, "esperar_turno_se", _nada)
        monkeypatch.setattr(se, "SE_TIMEOUT", aiohttp.ClientTimeout(total=1))

        # Se Deja `reservar_se_key` y `liberar_se_key` REALES, que es lo que se quiere
        # mirar: que la petición rechazada devuelva lo que reservó.
        try:
            return await se.analizar_imagen_multimodelo("hash", b"\x89PNG"), state.bot
        finally:
            state.bot = original

    @pytest.mark.asyncio
    async def test_un_400_devuelve_las_operaciones_reservadas(self, monkeypatch):
        """El bucle tiene que LLAMAR a liberar, no basta con que la función exista."""
        from api import sightengine as se

        cuerpo = {"error": {"type": "unsupported_model", "message": "model not available"}}
        (resultado, bot), _ = (await self._analizar_con_respuesta(monkeypatch, se, 400, cuerpo),)

        # Un 400 de modelo no disponible reintenta hasta agotar la lista; cada intento es
        # una petición rechazada, así que el contador tiene que volver a cero.
        assert bot.se_key_daily_usage.get("user", {"count": 0})["count"] == 0, (
            "las peticiones rechazadas se están cobrando: "
            f"{bot.se_key_daily_usage.get('user')}"
        )

    @pytest.mark.asyncio
    async def test_la_cuota_agotada_se_reporta_como_cuota(self, monkeypatch):
        """No como fallo de red: el embed de ERROR_HTTP dice "fallo de red"."""
        from api import sightengine as se

        cuerpo = {"status": "failure",
                  "error": {"type": "quota_exceeded", "message": "monthly quota used up"}}
        resultado, _bot = await self._analizar_con_respuesta(monkeypatch, se, 402, cuerpo)

        _ok, _conf, models, _cache = resultado
        assert models.get("error") == se.ERROR_SIN_CUOTA, models
        assert "red" not in str(models).lower(), models
        assert "cuota" in str(models).lower(), models

    @pytest.mark.asyncio
    async def test_un_500_sigue_siendo_fallo_de_red(self, monkeypatch):
        """La detección de cuota no debe tragarse los fallos de verdad."""
        from api import sightengine as se

        cuerpo = {"status": "failure",
                  "error": {"type": "internal_error", "message": "server exploded"}}
        resultado, _bot = await self._analizar_con_respuesta(monkeypatch, se, 500, cuerpo)

        _ok, _conf, models, _cache = resultado
        assert models.get("error") == se.ERROR_HTTP, models
