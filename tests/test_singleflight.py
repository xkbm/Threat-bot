"""Single-flight por clave de caché (F6).

Sin esto, veinte personas pegando a la vez el mismo enlace recién publicado
compartían el mismo cache-miss y disparaban veinte análisis: cien unidades de cuota
de VirusTotal para un único enlace, y veinte filas en `/stats`.
"""

import asyncio

import pytest

from core.utils import SIN_RESPUESTA, _vuelos, vuelo


@pytest.fixture(autouse=True)
def limpiar_vuelos():
    _vuelos.clear()
    yield
    _vuelos.clear()


class TestSerializaLaMismaClave:
    @pytest.mark.asyncio
    async def test_veinte_concurrentes_una_sola_llamada(self):
        """El corazón del defecto: 20 mensajes, la misma URL, 1 análisis."""
        llamadas = 0

        async def calcular():
            nonlocal llamadas
            llamadas += 1
            await asyncio.sleep(0.01)  # da tiempo a las demás a encolarse
            return ("malicioso", "embed", 4)

        resultados = await asyncio.gather(*[vuelo("url:https://x.com", calcular) for _ in range(20)])
        assert llamadas == 1
        assert resultados == [("malicioso", "embed", 4)] * 20

    @pytest.mark.asyncio
    async def test_claves_distintas_no_se_bloquean(self):
        """El vuelo es por clave: dos enlaces distintos no se esperan."""
        orden = []

        async def calcular(i):
            orden.append(f"entra{i}")
            await asyncio.sleep(0.01)
            orden.append(f"sale{i}")
            return i

        await asyncio.gather(vuelo("a", lambda: calcular(0)), vuelo("b", lambda: calcular(1)))
        # Serializados entre sí, "entra1" no podría aparecer antes que "sale0".
        assert orden.index("entra1") < orden.index("sale0")

    @pytest.mark.asyncio
    async def test_veinte_claves_distintas_veinte_llamadas(self):
        llamadas = 0

        async def calcular():
            nonlocal llamadas
            llamadas += 1
            await asyncio.sleep(0.005)
            return 1

        await asyncio.gather(*[vuelo(f"url:{i}", calcular) for i in range(20)])
        assert llamadas == 20


class TestLimpieza:
    @pytest.mark.asyncio
    async def test_el_dict_queda_vacio_al_salir(self):
        async def calcular():
            return 1

        await vuelo("url:https://x.com", calcular)
        assert _vuelos == {}

    @pytest.mark.asyncio
    async def test_una_excepcion_no_deja_la_clave_ocupada(self):
        """Si el cálculo revienta, la siguiente llamada tiene que poder entrar."""
        async def malo():
            raise RuntimeError("fallo de VT")

        for _ in range(3):
            with pytest.raises(RuntimeError):
                await vuelo("url:https://x.com", malo)
        assert _vuelos == {}

    @pytest.mark.asyncio
    async def test_una_cancelacion_no_deja_la_clave_ocupada(self):
        async def lento():
            await asyncio.sleep(10)
            return 1

        tarea = asyncio.create_task(vuelo("url:https://x.com", lento))
        await asyncio.sleep(0)
        tarea.cancel()
        with pytest.raises(asyncio.CancelledError):
            await tarea
        assert _vuelos == {}

    @pytest.mark.asyncio
    async def test_la_clave_se_reutiliza_tras_un_fallo(self):
        async def malo():
            raise ValueError("VT caído")

        with pytest.raises(ValueError):
            await vuelo("k", malo)

        async def bueno():
            return "recuperado"

        assert await vuelo("k", bueno) == "recuperado"


class TestErrores:
    @pytest.mark.asyncio
    async def test_el_error_llega_a_todos_los_esperadores(self):
        """Si el primero falla, quien espera tiene que enterarse. Un resultado vacío
        se leería como "la URL está limpia", que es lo contrario de la verdad."""
        async def malo():
            await asyncio.sleep(0.005)
            raise ValueError("VT caído")

        resultados = await asyncio.gather(*[vuelo("k", malo) for _ in range(5)], return_exceptions=True)
        assert all(isinstance(r, ValueError) for r in resultados)

    @pytest.mark.asyncio
    async def test_cancelar_un_esperador_no_rompe_a_los_demas(self):
        """Un `Future` compartido sin `shield` se cancela con el primero que se va,
        y los demás se quedan colgados sin resultado."""
        async def lento():
            await asyncio.sleep(0.05)
            return "final"

        t1 = asyncio.create_task(vuelo("k", lento))
        t2 = asyncio.create_task(vuelo("k", lento))
        await asyncio.sleep(0.005)
        t2.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t2
        assert await t1 == "final"


class TestSinRespuesta:
    """La tasa por usuario es personal: que a uno le toque su límite no puede dejar
    al resto sin análisis."""

    @pytest.mark.asyncio
    async def test_el_esperador_reintenta_por_su_cuenta(self):
        intentos = []

        async def sin_cuota():
            intentos.append("primero")
            await asyncio.sleep(0.01)
            return SIN_RESPUESTA

        async def con_derecho():
            intentos.append("segundo")
            await asyncio.sleep(0.01)
            return "analizado"

        primero, segundo = await asyncio.gather(
            vuelo("k", sin_cuota),
            vuelo("k", con_derecho),
        )
        assert primero is SIN_RESPUESTA
        assert segundo == "analizado"
        assert intentos == ["primero", "segundo"]

    @pytest.mark.asyncio
    async def test_todos_sin_cuota_no_entran_en_bucle(self):
        async def sin_cuota():
            await asyncio.sleep(0.005)
            return SIN_RESPUESTA

        resultados = await asyncio.gather(*[vuelo("k", sin_cuota) for _ in range(4)])
        assert all(r is SIN_RESPUESTA for r in resultados)
        assert _vuelos == {}
