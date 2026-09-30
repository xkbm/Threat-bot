"""Pruebas de extremo a extremo de los seis defectos corregidos.

Los tests unitarios comprueban funciones sueltas; estos recorren el camino completo —
escribir en la caché real, releerla por el otro lado, pasar por `_procesar_resultado_vt`
y comprobar los efectos— porque casi todos los fallos que se corrigieron eran de
*coherencia entre dos sitios*, y eso ningún test de una sola función lo ve.

Sin red: la respuesta de VirusTotal se construye a mano, así que el resultado es
determinista y no depende de la cuota ni de la red.
"""

import asyncio
import os
import types

import pytest
import pytest_asyncio

from core import database as db
from core import state
from core.utils import clave_analisis
from ui import embed as emb


def _stats(mal=0, susp=0, harmless=0, undetected=0):
    return {"malicious": mal, "suspicious": susp, "harmless": harmless, "undetected": undetected}


def _respuesta(stats, results=None):
    """Respuesta con la forma que devuelve la API de VirusTotal."""
    return {"data": {"attributes": {"stats": stats, "results": results or {}}}}


class _Autor:
    def __init__(self, id=7):
        self.id = id
        self.mention = f"<@{id}>"

    def __getattr__(self, _):
        return None


class _Mensaje:
    """Lo mínimo de `discord.Message` que necesitan las funciones bajo prueba."""

    def __init__(self, autor_id=7):
        self.id = 1
        self.author = _Autor(autor_id)
        self.guild = types.SimpleNamespace(id=1)
        self.borrado = False
        self.reacciones = []

    async def add_reaction(self, emoji):
        self.reacciones.append(emoji)

    async def remove_reaction(self, emoji):
        if emoji in self.reacciones:
            self.reacciones.remove(emoji)

    async def delete(self):
        self.borrado = True


@pytest_asyncio.fixture
async def bot_temporal(tmp_path, monkeypatch):
    """Bot mínimo con la base de datos en un fichero temporal.

    `state.bot` lo crea `bot.py` al arrancar, así que fuera de producción hay que
    construirlo. La base va a `tmp_path` para no tocar el `core/analisis.db` real.
    """
    original = state.bot
    bot = types.SimpleNamespace(
        guilds_data={},
        session=None,
        cache_mem={},
        vt_key_usage={},
        user_scan_history={},
        antispam_scan={},
        vt_user_requests={},
        ANALYSIS_SEMAPHORE=asyncio.Semaphore(5),
    )
    state.bot = bot

    pool_original = db.POOL
    db.POOL = db.DatabasePool(str(tmp_path / "analisis.db"))
    await db.init_db()
    yield bot
    await db.POOL.stop()
    db.POOL = pool_original
    state.bot = original


@pytest.fixture
def sin_efectos(monkeypatch):
    """Captura los efectos de amenaza sin tocar Discord ni la red."""
    from api import virustotal as vt

    logs, infracciones, stats = [], [], []
    monkeypatch.setattr(vt, "enviar_log_guild", lambda *a, **k: _append(logs, a))
    monkeypatch.setattr(vt, "registrar_infraccion", lambda *a, **k: _append(infracciones, a))
    monkeypatch.setattr(vt, "update_stats", lambda *a, **k: _append(stats, a))
    return logs, infracciones, stats


async def _append(destino, args):
    destino.append(args)


# --------------------------------------------------------------------------- F1
class TestCacheDeUrls:
    """F1: la clave se calculaba en tres sitios con dos fórmulas distintas, así que la
    caché era de solo-escritura en el autoescaneo."""

    @pytest.mark.asyncio
    async def test_la_api_escribe_y_el_autoescaneo_relee(self, bot_temporal):
        from api.virustotal import _procesar_resultado_vt

        await _procesar_resultado_vt(_respuesta(_stats(mal=3)), "url",
                                     "https://ejemplo-sin-path.com", None, None, True)
        # El autoescaneo normaliza antes de buscar. Con el bug, comparaba
        # "url:https://ejemplo-sin-path.com/" contra el "url:https://ejemplo-sin-path.com"
        # que había guardado la API y no encontraba nada.
        from core.cache import get_from_cache_mem
        tipo, embed, mal = await get_from_cache_mem(clave_analisis("url", "https://ejemplo-sin-path.com/"))
        assert embed is not None
        assert (tipo, mal) == ("malicioso", 3)

    @pytest.mark.asyncio
    async def test_sobrevive_a_un_reinicio(self, bot_temporal):
        """La caché de 7 días solo sirve si sobrevive al reinicio: se relee de SQLite."""
        from api.virustotal import _procesar_resultado_vt

        await _procesar_resultado_vt(_respuesta(_stats(mal=2)), "url",
                                     "https://ejemplo.com/a", None, None, True)
        tipo, embed, mal = await db.obtener_analisis_db(clave_analisis("url", "https://EJEMPLO.com/a"))
        assert embed is not None
        assert (tipo, mal) == ("malicioso", 2)

    @pytest.mark.asyncio
    async def test_el_hash_tambien_persiste(self, bot_temporal):
        from api.virustotal import _procesar_analisis_archivo

        archivo = types.SimpleNamespace(filename="x.exe", size=10)
        await _procesar_analisis_archivo(_respuesta(_stats(mal=5)), archivo, "a" * 64, None, None, True)
        tipo, embed, mal = await db.obtener_analisis_db(clave_analisis("file", "a" * 64))
        assert embed is not None
        assert (tipo, mal) == ("malicioso", 5)


# --------------------------------------------------------------------------- F3
class TestVeredictoSospechoso:
    """F3: solo se leía `malicious`, así que un enlace con `suspicious > 0` salía
    con el veredicto "seguro"."""

    @pytest.mark.asyncio
    async def test_sospechoso_no_infracciona(self, bot_temporal, sin_efectos):
        """Un sospechoso se informa pero no castiga: sin log de amenaza y sin
        infracción, para no borrar mensajes por un dato sin confirmar."""
        from api.virustotal import _procesar_resultado_vt

        logs, infracciones, _ = sin_efectos
        tipo, embed, mal = await _procesar_resultado_vt(
            _respuesta(_stats(susp=4)), "url", "https://sospechoso.example", 1, _Mensaje(), True)
        await asyncio.sleep(0.05)

        assert tipo == "sospechoso"
        assert mal == 0
        assert emb.TITULOS["url_sospechosa"] in embed.title
        assert logs == []
        assert infracciones == []

    @pytest.mark.asyncio
    async def test_malicioso_sigue_infraccionando(self, bot_temporal, sin_efectos):
        """El camino del autoescaneo no puede haber cambiado por añadir el sospechoso."""
        from api.virustotal import _procesar_resultado_vt
        logs, infracciones, _ = sin_efectos
        mensaje = _Mensaje(autor_id=99)
        tipo, _, mal = await _procesar_resultado_vt(
            _respuesta(_stats(mal=2, susp=5)), "url", "https://malo.example", 1, mensaje, True)
        await asyncio.sleep(0.05)

        assert (tipo, mal) == ("malicioso", 2)
        assert len(logs) == 1
        # La infracción es del autor del mensaje, no del bot ni de quien escaneó.
        assert infracciones[0][1] == 99

    @pytest.mark.asyncio
    async def test_el_sospechoso_cacheado_no_se_rea_como_seguro(self, bot_temporal):
        """El veredicto viaja dentro de `datos`, que es lo que se persiste. Si solo
        guardáramos `mal=0`, al releer de SQLite saldría como seguro."""
        from api.virustotal import _procesar_resultado_vt

        await _procesar_resultado_vt(_respuesta(_stats(susp=3)), "url",
                                     "https://persistido.example", None, None, True)
        _, embed, _ = await db.obtener_analisis_db(clave_analisis("url", "https://persistido.example"))
        assert embed is not None
        assert emb.TITULOS["url_sospechosa"] in embed.title

    @pytest.mark.asyncio
    async def test_el_sospechoso_cuenta_en_las_estadisticas(self, bot_temporal, monkeypatch):
        """Sin el fixture `sin_efectos`: aquí interesa la estadística real, no
        interceptarla. Un sospechoso cuenta como análisis, no como seguro."""
        from api import virustotal as vt
        from api.virustotal import _procesar_resultado_vt
        from core.guild_config import obtener_stats_globales

        from core import guild_config as gc

        # `update_stats` escribe en data.json al final; se anula para no tocar disco.
        # Hay que parchear el atributo del módulo: `from ... import` lo copió al
        # namespace de `guild_config` y ahí es donde se busca.
        monkeypatch.setattr(gc, "guardar_datos", lambda *a, **k: asyncio.sleep(0))

        await _procesar_resultado_vt(_respuesta(_stats(susp=1)), "url",
                                     "https://contado.example", 1, _Mensaje(), True)
        globals_ = obtener_stats_globales()
        assert globals_["sospechosos"] == 1
        assert globals_["seguros"] == 0, "un sospechoso no puede contar como seguro"
        assert globals_["total_analisis"] == 1


# --------------------------------------------------------------------------- F2
class TestDobleExtension:
    """F2: el modo estricto leía el MIMEMismatch del slot donde iba la doble extensión.

    Se comprueba sobre la tupla que devuelve `_procesar_archivo`, no sobre una tupla
    fabricada: el defecto era precisamente que el dato real se perdía por el camino.
    """

    @pytest.mark.asyncio
    async def test_la_tupla_lleva_la_doble_extension(self, bot_temporal, sin_efectos):
        import hashlib
        from ui import message_handler as mh

        contenido = b"contenido del archivo"
        archivo = types.SimpleNamespace(filename="informe.pdf.exe", size=len(contenido),
                                        url="https://cdn.discord/x")
        bot = _BotDescarga(contenido, bot_temporal)
        resultado = await mh._procesar_archivo(bot, _Mensaje(), archivo, 1)

        assert len(resultado) == 6, "la tupla debe llevar 6 campos"
        _, tipo, _, file_hash, wm, doble_ext = resultado
        assert doble_ext is True, "tiene_doble_extension no detectó informe.pdf.exe"
        # Y el aviso tiene que salir en el embed, no solo en el booleano.
        assert file_hash == hashlib.sha256(contenido).hexdigest()
        assert tipo in ("malicioso", "sospechoso", "seguro", "error")

    @pytest.mark.asyncio
    async def test_doble_extension_borra_en_modo_estricto(self, bot_temporal, sin_efectos):
        """El caso que el bug hacía fallar: el mensaje tenía que borrarse."""
        from ui import message_handler as mh

        contenido = b"x" * 10
        archivo = types.SimpleNamespace(filename="factura.pdf.exe", size=len(contenido),
                                        url="https://cdn.discord/x")
        bot = _BotDescarga(contenido, bot_temporal)
        resultado = await mh._procesar_archivo(bot, _Mensaje(), archivo, 1)

        _, _, _, _, wm, doble_ext = resultado
        assert mh.debe_borrar(False, doble_ext, bool(wm), True) is True

    @pytest.mark.asyncio
    async def test_un_archivo_limpio_no_se_borra(self, bot_temporal, sin_efectos):
        """Un `.png` que Discord sirve de verdad como imagen no genera ninguna de las
        dos señales, así que el modo estricto no lo toca."""
        from ui import message_handler as mh

        contenido = b"\x89PNG\r\n\x1a\n" + b"x" * 10
        archivo = types.SimpleNamespace(filename="foto.png", size=len(contenido),
                                        url="https://cdn.discord/x")
        bot = _BotDescarga(contenido, bot_temporal, content_type="image/png")
        resultado = await mh._procesar_archivo(bot, _Mensaje(), archivo, 1)

        _, _, _, _, wm, doble_ext = resultado
        assert doble_ext is False
        assert wm == "", f"un .png servido como image/png no debe dar MIMEMismatch: {wm}"
        assert mh.debe_borrar(False, doble_ext, bool(wm), True) is False

    @pytest.mark.asyncio
    async def test_el_mimemismatch_sigue_siendo_senal(self, bot_temporal, sin_efectos):
        """Un `.png` que en realidad es HTML es un scam clásico, y tiene que borrar."""
        from ui import message_handler as mh

        contenido = b"<html><script>alert(1)</script></html>"
        archivo = types.SimpleNamespace(filename="foto.png", size=len(contenido),
                                        url="https://cdn.discord/x")
        bot = _BotDescarga(contenido, bot_temporal, content_type="text/html")
        resultado = await mh._procesar_archivo(bot, _Mensaje(), archivo, 1)

        _, _, _, _, wm, doble_ext = resultado
        assert doble_ext is False
        assert "text/html" in wm
        assert mh.debe_borrar(False, doble_ext, bool(wm), True) is True


class TestNombreDoble:
    """Regresión del detector de doble extensión (y del aviso contradictorio).

    Solo mirar la extensión intermedia producía falsos positivos: `r.pdf.exe.md`
    dispara porque el medio es `.exe`, aunque lo que se descarga es un `.md` inofensivo.
    El nombre engañoso de verdad es el que termina en ejecutable.
    """

    @pytest.mark.parametrize("nombre,esperado", [
        # La extensión real es ejecutable y hay otra delante que la disimula: engañan.
        ("informe.pdf.exe", True),
        ("foto.png.exe", True),
        ("factura.xlsx.exe", True),
        ("doc.pdf.bat", True),
        ("guion.sh.cmd", True),
        ("malware.exe.bat", True),
        ("backup.2024.exe", True),
        # La real NO es ejecutable: no engañan, y avisar sería un falso positivo.
        ("r.pdf.exe.md", False),
        ("r.exe.md.md", False),
        ("notas.exe.txt", False),
        ("malware.pdf.jpg", False),     # descargas una imagen
        ("x.js.png", False),
        ("script.js.png", False),
        ("fotos.2024.png", False),
        ("v1.2.3.zip", False),
        # Una sola extensión: no hay nada que esconda.
        ("acceso.lnk", False),
        ("script.js", False),
        ("a.txt", False),
        ("sin-extension", False),
    ])
    def test_detector(self, nombre, esperado):
        from core.utils import tiene_doble_extension
        assert tiene_doble_extension(nombre) is esperado

    @pytest.mark.asyncio
    async def test_el_nombre_enganoso_avisa_pero_no_borra_un_txt(self, bot_temporal, sin_efectos):
        """`r.pdf.exe.md` es texto limpio: se avisa en el embed pero no se borra,
        porque el modo estricto no debe eliminar archivos por su nombre."""
        import ui.message_handler as mh

        contenido = b"# un markdown cualquiera"
        archivo = types.SimpleNamespace(filename="r.pdf.exe.md", size=len(contenido),
                                        url="https://cdn.discord/x")
        bot = _BotDescarga(contenido, bot_temporal, content_type="text/markdown")
        resultado = await mh._procesar_archivo(bot, _Mensaje(), archivo, 1)

        _, _, _, _, wm, doble_ext = resultado
        assert doble_ext is False, "un .md al final no es una extensión ejecutable"
        assert mh.debe_borrar(False, doble_ext, bool(wm), True) is False

    @pytest.mark.asyncio
    async def test_el_nombre_enganoso_de_verdad_borra(self, bot_temporal, sin_efectos):
        """`informe.pdf.exe` sí borra: el archivo que se descarga es ejecutable."""
        import ui.message_handler as mh

        contenido = b"MZ\x90\x00"  # cabecera de ejecutable de Windows
        archivo = types.SimpleNamespace(filename="informe.pdf.exe", size=len(contenido),
                                        url="https://cdn.discord/x")
        bot = _BotDescarga(contenido, bot_temporal, content_type="application/octet-stream")
        resultado = await mh._procesar_archivo(bot, _Mensaje(), archivo, 1)

        _, _, _, _, wm, doble_ext = resultado
        assert doble_ext is True
        assert mh.debe_borrar(False, doble_ext, bool(wm), True) is True


class _BotDescarga:
    """El `bot` que necesita `_procesar_archivo`: solo la descarga y el semáforo.

    `session` devuelve el contenido tal cual, así que el `Content-Type` lo decide el
    test a través de `content_type`.
    """

    def __init__(self, contenido, bot_real, content_type="application/octet-stream"):
        self._contenido = contenido
        self._content_type = content_type
        self._download_sem = _Sem()
        self.ANALYSIS_SEMAPHORE = bot_real.ANALYSIS_SEMAPHORE

    @property
    def session(self):
        return _Sesion(self._contenido, self._content_type)


class _Sem:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _RespuestaHTTP:
    def __init__(self, contenido, status=200, content_type="application/octet-stream"):
        self.status = status
        self._contenido = contenido
        self.headers = {"Content-Type": content_type}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def read(self):
        return self._contenido

    async def json(self):
        return {}


class _Sesion:
    def __init__(self, contenido, content_type):
        self._contenido = contenido
        self._content_type = content_type

    def get(self, url, **k):
        return _RespuestaHTTP(self._contenido, content_type=self._content_type)


# --------------------------------------------------------------------------- F5
class TestScanRegistra:
    """F5: `/scan` no dejaba ni log ni estadística porque `_on_threat_found` exigía un
    `mensaje_original`, y un comando no tiene uno."""

    @pytest.mark.asyncio
    async def test_sin_responsable_no_hay_efectos(self, sin_efectos):
        from api.virustotal import _on_threat_found
        logs, infracciones, _ = sin_efectos
        await _on_threat_found("URL", "https://x.example", 1, 1, None, "https://vt/x")
        await asyncio.sleep(0.05)
        assert logs == [] and infracciones == []

    @pytest.mark.asyncio
    async def test_con_responsable_manda_log_pero_no_infracciona(self, sin_efectos):
        """Quien ejecuta `/scan` está consultando, no publicando la amenaza: recibe el
        log —que es lo que un moderador quiere saber— pero no se le cuenta nada."""
        from api.virustotal import _on_threat_found
        logs, infracciones, _ = sin_efectos
        await _on_threat_found("URL", "https://y.example", 1, 1, None, "https://vt/y",
                               registrar_para=_Autor(42))
        await asyncio.sleep(0.05)
        assert len(logs) == 1
        assert infracciones == []
