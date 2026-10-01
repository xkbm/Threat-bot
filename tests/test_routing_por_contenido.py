"""Enrutado de adjuntos según su contenido real, no su nombre.

El bug que fija este archivo: `_analizar_adjuntos` partía los adjuntos con `es_imagen()`,
que mira la extensión y el `Content-Type` que Discord deduce del nombre. Un ejecutable
llamado `malware.png` salía como imagen, iba solo a SightEngine y el malware no se
escaneaba nunca. Al revés, un `foto.exe.png` entraba como imagen y se saltaba la
verificación MIME y la detección de doble extensión.

Aquí se comprueba **a qué analizador llega cada adjunto**, sustituyendo los dos
analizadores por centinelas. Lo que importa no es qué dicen las APIs, sino que el
archivo malicioso llegue al motor de malware.
"""

import hashlib
import types

import pytest

from ui import message_handler as mh

# Contenido de un ejecutable PE (cabecera MZ) y de una imagen PNG real.
PE = b"MZ\x90\x00\x03" + b"\x00" * 300
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 300


class _Contenido:
    """Flujo que solo entrega los primeros bytes, como hace el Range real."""

    def __init__(self, datos):
        self._datos = datos

    async def read(self, n=-1):
        return self._datos if n < 0 else self._datos[:n]


class _Respuesta:
    def __init__(self, datos, content_type):
        self.status = 200
        self.content = _Contenido(datos)
        self.headers = {"Content-Type": content_type}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def read(self):
        return self.content._datos


class _Sesion:
    def __init__(self, por_adjunto, content_type_por_defecto="application/octet-stream"):
        self._por_adjunto = por_adjunto
        self._por_defecto = content_type_por_defecto

    def get(self, url, **kwargs):
        datos = self._por_adjunto.get(url, b"")
        ct = self._por_adjunto.get(url + "::ct", self._por_defecto)
        return _Respuesta(datos, ct)


class _Sem:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Mensaje:
    def __init__(self, attachments):
        self.attachments = attachments
        self.id = 1
        self.content = ""

        class _A:
            bot = None
        self.author = _A()

    async def add_reaction(self, emoji):
        pass

    async def remove_reaction(self, emoji, user):
        pass


def _adjunto(nombre, tamano, ident):
    # `content_type` es lo que Discord deduce del nombre, no del contenido.
    ct = "image/png" if nombre.lower().endswith(".png") else "application/octet-stream"
    return types.SimpleNamespace(filename=nombre, size=tamano, url=f"u{ident}", id=ident, content_type=ct)


@pytest.fixture
def spies(monkeypatch):
    """Sustituye los dos analizadores y registra qué adjunto llega a cada uno."""
    vistos = {"imagen": [], "archivo": []}

    async def _fake_imagen(bot, message, img, guild_id):
        vistos["imagen"].append(img.filename)
        return (img.filename, "seguro", {}, hashlib.sha256(PNG).hexdigest())

    async def _fake_archivo(bot, message, archivo, guild_id):
        vistos["archivo"].append(archivo.filename)
        return (archivo.filename, "seguro", 0, hashlib.sha256(PE).hexdigest(), "", False)

    monkeypatch.setattr(mh, "_procesar_imagen", _fake_imagen)
    monkeypatch.setattr(mh, "_procesar_archivo", _fake_archivo)
    return vistos


def _bot_para(adjuntos_por_url):
    class Bot:
        def __init__(self):
            self.session = _Sesion(adjuntos_por_url)
            self._download_sem = _Sem()
            self._reaction_controllers = {}
            self.user = None
    return Bot()


class TestEnrutadoPorBytes:
    @pytest.mark.asyncio
    async def test_malware_png_va_al_motor_de_malware(self, spies):
        """El caso del bug: `.png` + `image/png` para Discord, bytes de ejecutable."""
        a = _adjunto("malware.png", len(PE), 1)
        bot = _bot_para({"u1": PE, "u1::ct": "image/png"})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert spies["archivo"] == ["malware.png"], "el ejecutable tiene que ir a VirusTotal"
        assert spies["imagen"] == [], "no debe pasar por SightEngine: ahí no se escanea malware"

    @pytest.mark.asyncio
    async def test_png_real_sigue_por_sightengine(self, spies):
        a = _adjunto("foto.png", len(PNG), 1)
        bot = _bot_para({"u1": PNG, "u1::ct": "image/png"})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert spies["imagen"] == ["foto.png"]
        assert spies["archivo"] == []

    @pytest.mark.asyncio
    async def test_pdf_va_a_malware(self, spies):
        pdf = b"%PDF-1.7\n" + b"\x00" * 300
        a = _adjunto("informe.pdf", len(pdf), 1)
        bot = _bot_para({"u1": pdf, "u1::ct": "application/pdf"})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert spies["archivo"] == ["informe.pdf"]

    @pytest.mark.asyncio
    async def test_extension_jpg_con_bytes_pe_tambien_a_malware(self, spies):
        """No es solo `.png`: la regla es el contenido, no la extensión concreta."""
        a = _adjunto("foto.jpg", len(PE), 1)
        bot = _bot_para({"u1": PE, "u1::ct": "image/jpeg"})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert spies["archivo"] == ["foto.jpg"]

    @pytest.mark.asyncio
    async def test_imagen_sin_extension_pero_con_bytes_png(self, spies):
        """Se renombró a algo sin extensión: los bytes siguen diciendo que es imagen."""
        a = _adjunto("captura", len(PNG), 1)
        bot = _bot_para({"u1": PNG, "u1::ct": "image/png"})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert spies["imagen"] == ["captura"]

    @pytest.mark.asyncio
    async def test_mezcla_de_imagen_y_ejecutable_en_el_mismo_mensaje(self, spies):
        a1 = _adjunto("foto.png", len(PNG), 1)
        a2 = _adjunto("malware.png", len(PE), 2)
        a3 = _adjunto("doc.pdf", len(PE), 3)
        bot = _bot_para({
            "u1": PNG, "u1::ct": "image/png",
            "u2": PE, "u2::ct": "image/png",
            "u3": PE, "u3::ct": "application/pdf",
        })

        await mh._analizar_adjuntos(bot, _Mensaje([a1, a2, a3]), 1)

        assert spies["imagen"] == ["foto.png"]
        assert sorted(spies["archivo"]) == ["doc.pdf", "malware.png"]

    @pytest.mark.asyncio
    async def test_si_no_se_puede_leer_cae_a_la_pista_por_extension(self, spies):
        """Sin bytes no se puede decidir: se usa la extensión, que es lo de antes.

        Peor que mirar los bytes, pero nunca rompe el análisis.
        """
        a = _adjunto("foto.png", 10, 1)
        # El servidor no devuelve nada: la detección por bytes falla.
        bot = _bot_para({})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert spies["imagen"] == ["foto.png"], "sin bytes, manda la extensión"


class TestCacheDeDetecciones:
    @pytest.mark.asyncio
    async def test_la_deteccion_se_libera_al_terminar(self, spies):
        """Un mapa que solo crece sería una fuga de memoria."""
        a = _adjunto("malware.png", len(PE), 4242)
        bot = _bot_para({"u4242": PE, "u4242::ct": "image/png"})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert 4242 not in mh._detecciones

    @pytest.mark.asyncio
    async def test_sin_id_no_revienta(self, spies):
        """Un adjunto sin `id` no puede cachearse, pero el análisis sigue."""
        a = types.SimpleNamespace(filename="x.png", size=len(PNG), url="u9",
                                  content_type="image/png")
        bot = _bot_para({"u9": PNG, "u9::ct": "image/png"})

        await mh._analizar_adjuntos(bot, _Mensaje([a]), 1)

        assert spies["imagen"] == ["x.png"]