"""Caché del "VirusTotal no conoce este archivo".

Viene del log de producción: el mismo hash salía con `SQLITE MISS` + `VT HASH NUEVO` dos
veces en un segundo, y ninguna se cacheaba. Con el plan gratuito son 500 requests al día,
así que una imagen que se repite en la comunidad drena cuota para volver a aprender lo
mismo.

El detalle que hace que esto no sea "cachea todo": `sin_cuota` y `error` **no** se
cachean. Son transitorios, y cachearlos dejaría al bot sin comprobar imágenes de forma
permanente por un fallo pasajero.
"""

import time

import pytest

from core.config import EXPIRACION


@pytest.fixture
def vt(monkeypatch):
    """Parchea la ruta de reputación. Devuelve (contador, _bot) con las llamadas contadas."""
    import types

    from ui import message_handler as mh

    estado = {
        "llamadas": 0, "respuesta": ("desconocido", 0, None, None),
        "cache": {},       # clave -> {"tipo":..., "mal":..., "vt_link":..., "top":...}
    }

    async def _reputacion_hash(content_hash):
        estado["llamadas"] += 1
        return estado["respuesta"]

    async def _obtener(clave):
        v = estado["cache"].get(clave)
        return (v["tipo"], None, v["mal"]) if v is not None else (None, None, 0)

    async def _obtener_datos(clave):
        return estado["cache"].get(clave)

    async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
        if datos is not None:
            estado["cache"][clave] = dict(datos)
        else:
            estado["cache"][clave] = {"tipo": resultado, "mal": mal,
                                      "vt_link": None, "top": None}

    async def _permitido(*a, **k):
        return True

    async def _nada(*a, **k):
        return None

    monkeypatch.setattr(mh, "reputacion_hash", _reputacion_hash)
    monkeypatch.setattr(mh, "obtener_analisis_db", _obtener)
    monkeypatch.setattr(mh, "obtener_datos_analisis", _obtener_datos)
    monkeypatch.setattr(mh, "guardar_analisis_db", _guardar)
    monkeypatch.setattr(mh, "check_vt_user_limit", _permitido)
    monkeypatch.setattr(mh, "registrar_infraccion", _nada)
    monkeypatch.setattr(mh, "set_cache_mem", _nada)
    monkeypatch.setattr(mh, "VT_API_KEYS", ["clave"])
    return estado, types.SimpleNamespace()


async def _preguntar(vt, hash_="abc123"):
    """Llama dos veces al mismo hash: lo que hace una imagen que se republica."""
    from ui import message_handler as mh

    estado, bot = vt
    primero = await mh._reputacion_de_imagen(bot, hash_, 1, 7)
    segundo = await mh._reputacion_de_imagen(bot, hash_, 1, 7)
    return primero, segundo


class TestElDesconocidoSeCachea:
    @pytest.mark.asyncio
    async def test_un_404_no_se_vuelve_a_preguntar(self, vt):
        """El bug del log: dos llamadas al mismo hash, dos requests a VT."""
        primero, segundo = await _preguntar(vt)
        assert vt[0]["llamadas"] == 1, "el 404 se volvió a preguntar a VT"
        assert primero == segundo == ("no_consultado", 0, None, None)

    @pytest.mark.asyncio
    async def test_se_guarda_con_el_tipo_que_tiene_caducidad_corta(self, monkeypatch, vt):
        from ui import message_handler as mh

        guardados = []

        async def _guardar(clave, tipo, resultado, **kw):
            guardados.append((clave, tipo, resultado))
            vt[0]["cache"][clave] = {"tipo": resultado, "mal": 0,
                                    "vt_link": None, "top": None}

        monkeypatch.setattr(mh, "guardar_analisis_db", _guardar)
        await _preguntar(vt)

        clave, tipo, resultado = guardados[0]
        assert clave == mh.clave_analisis("imgmal", "abc123")
        assert tipo == mh.TIPO_HASH_DESCONOCIDO == "imgmal_desconocido"
        # Lo que se relee tiene que ser lo mismo que devuelve el camino fresco, o los
        # dos caminos discreparían en lo que le dicen a `_procesar_imagem`.
        assert resultado == "no_consultado"

    @pytest.mark.asyncio
    async def test_cache_y_fresco_dicen_lo_mismo(self, vt):
        """La regresión: el acierto de caché devolvía "desconocido" y el fresco
        "no_consultado", así que solo uno marcaba la imagen como no comprobada."""
        primero, segundo = await _preguntar(vt)
        assert primero == segundo


class TestLoTransitorioNoSeCachea:
    """Cachear un fallo de red o una cuota agotada dejaría el bot ciego para siempre."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("respuesta", [("sin_cuota", 0, None, None), ("error", 0, None, None)])
    async def test_vuelve_a_preguntar(self, monkeypatch, vt, respuesta):
        from ui import message_handler as mh

        vt[0]["respuesta"] = respuesta

        async def _siempre_miss(clave):
            return (None, None, 0)

        async def _nada(clave):
            return None

        monkeypatch.setattr(mh, "obtener_analisis_db", _siempre_miss)
        monkeypatch.setattr(mh, "obtener_datos_analisis", _nada)
        await _preguntar(vt)

        assert vt[0]["llamadas"] == 2, "un fallo transitorio no debe cachearse"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("respuesta", [("sin_cuota", 0, None, None), ("error", 0, None, None)])
    async def test_y_no_se_escribe_nada_en_cache(self, monkeypatch, vt, respuesta):
        from ui import message_handler as mh

        vt[0]["respuesta"] = respuesta
        guardados = []

        async def _guardar(clave, tipo, resultado, **kw):
            guardados.append(tipo)

        monkeypatch.setattr(mh, "guardar_analisis_db", _guardar)
        await _preguntar(vt)

        assert guardados == [], f"se cacheó un fallo transitorio: {guardados}"


class TestLosVeredictosReales:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("veredicto,mal", [("malicioso", 3), ("sospechoso", 1)])
    async def test_se_cachean_con_caducidad_normal(self, vt, veredicto, mal):
        """Un veredicto real sí es estable: 30 días, no 1."""
        vt[0]["respuesta"] = (veredicto, mal, "https://vt/x", "Windows")

        r1, r2 = await _preguntar(vt)

        assert vt[0]["llamadas"] == 1
        assert r1[0] == veredicto and r1[1] == mal
        assert r2 == r1

    @pytest.mark.asyncio
    async def test_el_enlace_al_informe_sobrevive_a_la_cache(self, vt):
        """El acierto de caché no puede dar menos información que el camino fresco."""
        vt[0]["respuesta"] = ("malicioso", 3, "https://vt/gui/file/abc", "Windows, Linux")

        primero, segundo = await _preguntar(vt)

        assert primero[2] == "https://vt/gui/file/abc", "el camino fresco no dio el enlace"
        assert segundo[2] == primero[2], (
            "el acierto de cache perdio el enlace al informe: el moderador ve el "
            "veredicto pero no donde comprobarlo"
        )
        assert segundo[3] == "Windows, Linux"

    @pytest.mark.asyncio
    async def test_el_enlace_se_guarda_para_poder_recuperarlo(self, monkeypatch, vt):
        from ui import message_handler as mh

        guardados = []

        async def _guardar(clave, tipo, resultado, *, mal=0, datos=None, **kw):
            guardados.append(datos)
            vt[0]["cache"][clave] = dict(datos or {})

        monkeypatch.setattr(mh, "guardar_analisis_db", _guardar)
        vt[0]["respuesta"] = ("malicioso", 3, "https://vt/gui/file/abc", "Windows")
        await _preguntar(vt)

        assert guardados and guardados[0]["vt_link"] == "https://vt/gui/file/abc"
        assert guardados[0]["mal"] == 3

    @pytest.mark.asyncio
    async def test_un_malicioso_registra_infraccion(self, monkeypatch, vt):
        from ui import message_handler as mh

        vt[0]["respuesta"] = ("malicioso", 3, "https://vt/x", "Windows")
        marcadas = []

        async def _registrar(guild_id, user_id, elemento):
            marcadas.append((guild_id, user_id, elemento))

        monkeypatch.setattr(mh, "registrar_infraccion", _registrar)
        await _preguntar(vt)

        assert marcadas == [(1, 7, "filehash:abc123")]


class TestLaCaducidadEsCorta:
    """El test que impide subir el TTL a 30 días sin darse cuenta."""

    def test_el_tipo_desconocido_caduca_a_un_dia(self):
        assert EXPIRACION["imgmal_desconocido"] == 24 * 3600

    def test_no_es_la_caducidad_de_un_veredicto_real(self):
        """Si se igualaran, una imagen desconocida se olvidaría en 30 días."""
        assert EXPIRACION["imgmal_desconocido"] < EXPIRACION["hash"]
        assert EXPIRACION["imgmal_desconocido"] < EXPIRACION["file"]

    @pytest.mark.asyncio
    async def test_expira_de_verdad_al_dia_siguiente(self, tmp_path, monkeypatch):
        """Un día después el mismo hash vuelve a consultarse.

        Es el otro lado del compromiso: si alguien sube el archivo a VT, queremos
        enterarnos al día siguiente como muy tarde.
        """
        from core import database as db

        anterior_f, anterior_p, anterior_t = db.DATA_FILE, db.POOL, db.time.time
        reloj = {"t": time.time()}
        db.DATA_FILE = str(tmp_path / "a.db")
        db.POOL = db.DatabasePool(str(tmp_path / "a.db"), size=1)
        monkeypatch.setattr(db.time, "time", lambda: reloj["t"])

        await db.POOL.start()
        try:
            await db.guardar_analisis_db("imgmal:x", "imgmal_desconocido", "desconocido")
            antes = await db.obtener_analisis_db("imgmal:x")
            reloj["t"] += EXPIRACION["imgmal_desconocido"] - 10
            dentro = await db.obtener_analisis_db("imgmal:x")
            reloj["t"] += 20
            fuera = await db.obtener_analisis_db("imgmal:x")
        finally:
            await db.POOL.stop()
            db.DATA_FILE, db.POOL, db.time.time = anterior_f, anterior_p, anterior_t

        assert antes[0] is not None, "no se guardó"
        assert dentro[0] is not None, "expiró antes de tiempo"
        assert fuera[0] is None, "sigue vivo después de un día"
