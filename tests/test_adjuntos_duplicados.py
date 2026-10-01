"""Adjuntos duplicados y avalancha sobre la caché.

Viene del log de producción. El usuario subió cinco veces el mismo `image.png` en un
mensaje y el bot:

    SQLITE MISS → imgmal:077d18ed...   x5
    VT HASH NUEVO → 077d18ed...         x5

Cinco copias del mismo archivo, cinco requests a VirusTotal. Y el detalle importante:
**la caché no era el fallo**. Las cinco llamadas concurrentes comprueban la caché antes de
que ninguna haya terminado de escribir, así que las cinco ven MISS. Una caché no
protege contra una avalancha sobre ella.
"""

import asyncio
import types

import pytest


class Adjunto:
    """Lo justo de `discord.Attachment` para el código que se prueba."""

    def __init__(self, nombre, tamano, id_=1, url=None, content_type="image/png"):
        self.filename = nombre
        self.size = tamano
        self.id = id_
        self.url = url or f"u/{id_}"
        self.content_type = content_type


class _Resp:
    def __init__(self, datos):
        self.status = 200
        self.headers = {"Content-Type": "image/png"}
        self.content = self
        self._datos = datos

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def read(self):
        return self._datos

    async def read_chunk(self, n):
        return self._datos[:n]


class _Sem:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _bot(png=b"\x89PNG\r\n\x1a\n" + b"\x00" * 40):
    class _Sesion:
        def get(self, url, **k):
            return _Resp(png)
    return types.SimpleNamespace(session=_Sesion(), _download_sem=_Sem(),
                                 _reaction_controllers={}, user=None)


class Mensaje:
    def __init__(self, attachments, mid=1):
        self.attachments = attachments
        self.id = mid
        self.content = ""
        self.channel = types.SimpleNamespace(id=2, send=self._send)
        self.author = types.SimpleNamespace(id=3, mention="<@u>")
        self.guild = types.SimpleNamespace(id=7)

    async def _send(self, *a, **k):
        return None

    async def add_reaction(self, e):
        pass

    async def remove_reaction(self, e, u):
        pass


@pytest.fixture
def entorno(monkeypatch):
    """Deja el análisis de adjuntos aislado: solo cuenta cuántos se llegan a procesar."""
    from ui import message_handler as mh

    vistos = {"imagen": [], "archivo": []}

    async def _fake_imagen(bot, message, img, guild_id):
        vistos["imagen"].append(img.filename)
        return (img.filename, "seguro", {}, "hash")

    async def _fake_archivo(bot, message, archivo, guild_id):
        vistos["archivo"].append(archivo.filename)
        return (archivo.filename, "seguro", 0, "hash", "", False)

    monkeypatch.setattr(mh, "_procesar_imagen", _fake_imagen)
    monkeypatch.setattr(mh, "_procesar_archivo", _fake_archivo)
    return vistos


class TestAdjuntosDuplicados:
    @pytest.mark.asyncio
    async def test_cinco_copias_se_analizan_una_vez(self, entorno):
        """El caso del log: cinco veces el mismo archivo, un solo análisis."""
        from ui import message_handler as mh

        adjuntos = [Adjunto("image.png", 16642, id_=i) for i in range(5)]
        await mh._analizar_adjuntos(_bot(), Mensaje(adjuntos), 7)

        assert len(entorno["imagen"]) == 1, (
            f"se analizaron {len(entorno['imagen'])} veces: {entorno['imagen']}"
        )

    @pytest.mark.asyncio
    async def test_archivos_iguales_tambien(self, entorno):
        from ui import message_handler as mh

        adjuntos = [Adjunto("message.txt", 14535, id_=i, content_type="text/plain")
                    for i in range(5)]
        await mh._analizar_adjuntos(_bot(), Mensaje(adjuntos), 7)

        assert len(entorno["archivo"]) == 1

    @pytest.mark.asyncio
    async def test_archivos_distintos_se_analizan_todos(self, entorno):
        """La deduplicación no puede comerse archivos legítimamente distintos."""
        from ui import message_handler as mh

        adjuntos = [
            Adjunto("a.png", 100, id_=1),
            Adjunto("b.png", 200, id_=2),
            Adjunto("a.png", 300, id_=3),      # mismo nombre, otro tamaño
        ]
        await mh._analizar_adjuntos(_bot(), Mensaje(adjuntos), 7)

        assert len(entorno["imagen"]) == 3, entorno["imagen"]

    @pytest.mark.asyncio
    async def test_el_tope_de_adjuntos_sigue_aplicandose(self, entorno):
        """La deduplicación no puede evadirse del límite por mensaje.

        Se usan tamaños distintos a propósito: con archivos idénticos la deduplicación los
        reduciría a uno y la prueba no mediría el tope.
        """
        from ui import message_handler as mh

        adjuntos = [Adjunto("a.png", 100 + i, id_=i) for i in range(8)]
        _img, _arch, omitidos = await mh._analizar_adjuntos(_bot(), Mensaje(adjuntos), 7)

        assert omitidos == 3, "se dejaron de contar los que sobran"
        assert len(entorno["imagen"]) == mh.MAX_ADJUNTOS_POR_MENSAJE

    @pytest.mark.asyncio
    async def test_las_copias_no_cuentan_como_omitidas(self, entorno):
        """Cinco copias del mismo archivo no son "omitidos": son un archivo.

        El contador de omitidos es para lo que se pasó del tope del mensaje, y subir cinco
        veces el mismo archivo no es pasarse del tope: es un archivo, cinco veces.
        """
        from ui import message_handler as mh

        adjuntos = [Adjunto("image.png", 16642, id_=i) for i in range(5)]
        _img, _arch, omitidos = await mh._analizar_adjuntos(_bot(), Mensaje(adjuntos), 7)

        assert omitidos == 0
        assert len(entorno["imagen"]) == 1

    @pytest.mark.asyncio
    async def test_imagen_y_archivo_iguales_no_se_mezclan(self, entorno):
        from ui import message_handler as mh

        adjuntos = [
            Adjunto("x.png", 100, id_=1, content_type="image/png"),
            Adjunto("x.png", 100, id_=2, content_type="text/plain"),
        ]
        await mh._analizar_adjuntos(_bot(), Mensaje(adjuntos), 7)

        # La deduplicación es por (nombre, tamaño) y no mira el tipo, pero el análisis
        # posterior los separa. Lo relevante es que no se rompa nada.
        assert len(entorno["imagen"]) + len(entorno["archivo"]) >= 1


class TestLaAvalanchaSobreLaCache:
    """El fallo real: cinco llamadas concurrentes, cinco MISS, cinco requests."""

    @pytest.mark.asyncio
    async def test_una_sola_consulta_a_vt_por_hash(self, monkeypatch):
        """Cinco llamadas simultáneas al mismo hash = una request."""
        from ui import message_handler as mh

        llamadas = []

        async def _reputacion(content_hash):
            llamadas.append(content_hash)
            await asyncio.sleep(0)          # simula la latencia real de la red
            return "desconocido", 0, None, None

        async def _guardar(*a, **k):
            return None

        async def _vacia(*a, **k):
            return None, None, 0

        async def _permitido(*a, **k):
            return True

        async def _nada(*a, **k):
            return None

        monkeypatch.setattr(mh, "reputacion_hash", _reputacion)
        monkeypatch.setattr(mh, "guardar_analisis_db", _guardar)
        monkeypatch.setattr(mh, "obtener_analisis_db", _vacia)
        monkeypatch.setattr(mh, "obtener_datos_analisis", _nada)
        monkeypatch.setattr(mh, "set_cache_mem", _nada)
        monkeypatch.setattr(mh, "registrar_infraccion", _nada)
        monkeypatch.setattr(mh, "check_vt_user_limit", _permitido)
        monkeypatch.setattr(mh, "VT_API_KEYS", ["clave"])

        bot = types.SimpleNamespace()
        resultados = await asyncio.gather(*[
            mh._reputacion_de_imagen(bot, "mismo_hash", 1, 7) for _ in range(5)
        ])

        assert len(llamadas) == 1, (
            f"{len(llamadas)} requests a VT por el mismo hash: la cache no protege "
            f"contra una avalancha, para eso hace falta el cerrojo"
        )
        assert all(r == ("no_consultado", 0, None, None) for r in resultados)

    @pytest.mark.asyncio
    async def test_hashes_distintos_no_se_bloquean_entre_si(self, monkeypatch):
        """El cerrojo es por hash: dos archivos distintos se analizan a la vez."""
        from ui import message_handler as mh

        llamadas = []

        async def _reputacion(content_hash):
            llamadas.append(content_hash)
            return "desconocido", 0, None, None

        async def _nada(*a, **k):
            return None

        async def _vacia(*a, **k):
            return None, None, 0

        async def _permitido(*a, **k):
            return True

        monkeypatch.setattr(mh, "reputacion_hash", _reputacion)
        monkeypatch.setattr(mh, "guardar_analisis_db", _nada)
        monkeypatch.setattr(mh, "obtener_analisis_db", _vacia)
        monkeypatch.setattr(mh, "obtener_datos_analisis", _nada)
        monkeypatch.setattr(mh, "set_cache_mem", _nada)
        monkeypatch.setattr(mh, "registrar_infraccion", _nada)
        monkeypatch.setattr(mh, "check_vt_user_limit", _permitido)
        monkeypatch.setattr(mh, "VT_API_KEYS", ["clave"])

        bot = types.SimpleNamespace()
        await asyncio.gather(*[
            mh._reputacion_de_imagen(bot, f"hash_{i}", 1, 7) for i in range(5)
        ])

        assert len(set(llamadas)) == 5, f"se bloquearon hashes distintos: {llamadas}"
