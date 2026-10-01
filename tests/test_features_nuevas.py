"""Features nuevas: anti-phishing en el pipeline, `/history` y menú contextual.

Lo que se comprueba aquí es la **integración**, no las piezas sueltas (esas ya tienen sus
propios ficheros de test): que el phishing se aplica antes de gastar cuota, que el
historial registra de verdad, y que el menú extrae lo que toca de un mensaje.
"""

import types

import pytest

from core.senales import Elemento, Senales
from core.veredictos import Veredicto


class FakeAttachment:
    def __init__(self, nombre="a.png", tamano=10):
        self.filename = nombre
        self.size = tamano
        self.url = f"u/{nombre}"


class _Canal:
    id = 2

    async def send(self, *args, **kwargs):
        return None


class FakeMessage:
    def __init__(self, content="", attachments=()):
        self.content = content
        self.attachments = list(attachments)
        self.id = 1
        self.channel = _Canal()
        self.author = types.SimpleNamespace(id=3, mention="<@U>")
        self.guild = types.SimpleNamespace(id=7)

        class _A:
            bot = None
        self.author.bot = _A()

    async def add_reaction(self, e):
        pass

    async def remove_reaction(self, e, u):
        pass


class FakeSession:
    def __init__(self, por_url=None):
        self.peticiones = []
        self._por_url = por_url or {}

    def get(self, url, **kwargs):
        self.peticiones.append(url)
        return _Resp(self._por_url.get(url, b""))


class _Resp:
    def __init__(self, datos):
        self.status = 200
        self.headers = {"Content-Type": "image/png"}
        self._datos = datos
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def read(self):
        return self._datos


class _Sem:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _bot(session=None):
    return types.SimpleNamespace(
        session=session or FakeSession(), _download_sem=_Sem(),
        _reaction_controllers={}, user=None, db_pool=None,
        guilds_data={}, vt_key_total_requests={}, vt_key_daily_usage={},
        se_key_total_requests={}, se_key_daily_usage={},
        user_scan_history={}, antispam_scan={}, vt_key_usage={}, se_key_usage={},
        vt_user_requests={}, vt_request_times={}, keys={},
    )


class TestPhishingEnElPipeline:
    @pytest.fixture(autouse=True)
    def _bot_global(self):
        import core.state as state

        bot = _bot()
        anterior = state.bot
        state.bot = bot
        self.bot_de_prueba = bot
        yield
        state.bot = anterior

    @pytest.mark.asyncio
    async def test_una_url_de_phishing_no_llega_a_virustotal(self, monkeypatch):
        """El motivo de existir: filtrar antes de gastar cuota."""
        from ui import message_handler as mh

        llamadas = []

        async def _analizar_url(url, **kwargs):
            llamadas.append(url)
            return "seguro", None, 0
        monkeypatch.setattr(mh, "analizar_url", _analizar_url)
        monkeypatch.setattr(mh, "registrar_evento", _no_registrar)
        monkeypatch.setattr(mh, "obtener_analisis_db", _miss_db)
        monkeypatch.setattr(mh, "get_from_cache_mem", _miss_cache)

        await mh.procesar_analisis(
            self.bot_de_prueba,
            FakeMessage(content="entra https://rnicrosoft.com/gift ya"),
        )
        assert "rnicrosoft.com" not in llamadas, "una URL de phishing no debe gastar request"

    @pytest.mark.asyncio
    async def test_una_url_limpia_sigue_pasando_a_vt(self, monkeypatch):
        from ui import message_handler as mh

        llamadas = []

        async def _analizar_url(url, **kwargs):
            llamadas.append(url)
            return "seguro", None, 0
        monkeypatch.setattr(mh, "analizar_url", _analizar_url)
        monkeypatch.setattr(mh, "registrar_evento", _no_registrar)
        monkeypatch.setattr(mh, "obtener_analisis_db", _miss_db)
        monkeypatch.setattr(mh, "get_from_cache_mem", _miss_cache)

        # Ojo: `github.com` está en DOMINIOS_PROTEGIDOS, así que un dominio en
        # whitelist nunca llegaría a VT y la prueba pasaría sin comprobar nada.
        await mh.procesar_analisis(
            self.bot_de_prueba,
            FakeMessage(content="mira https://ejemplo-cualquiera.com/x"),
        )
        assert llamadas == ["https://ejemplo-cualquiera.com/x"]

    def test_el_phishing_genera_su_propio_veredicto(self):
        s = Senales()
        s.anadir(Elemento(nombre="rnicrosoft.com", tipo="url", veredicto=Veredicto.PHISHING))
        assert s.phishing is True
        assert s.hay_amenaza is False, "phishing avisa pero no borra"

    def test_phishing_es_informativo(self):
        assert Veredicto.PHISHING.borra_en_modo_estricto is False


async def _no_registrar(*a, **k):
    return None


async def _miss_db(*a, **k):
    return None, None, 0


async def _miss_cache(*a, **k):
    return None, None, 0


class TestMenuContextual:
    def test_extrae_una_url(self):
        from cogs.historial import _extraer_objetivo

        m = FakeMessage(content="mira https://rnicrosoft.com/gift porfa")
        assert _extraer_objetivo(m) == ("url", "https://rnicrosoft.com/gift")

    def test_extrae_un_hash_md5(self):
        from cogs.historial import _extraer_objetivo

        m = FakeMessage(content="d41d8cd98f00b204e9800998ecf8427e")
        assert _extraer_objetivo(m) == ("hash", "d41d8cd98f00b204e9800998ecf8427e")

    def test_extrae_un_hash_sha256(self):
        from cogs.historial import _extraer_objetivo

        h = "a" * 64
        assert _extraer_objetivo(FakeMessage(content=f"sha256: {h}")) == ("hash", h)

    def test_el_hash_gana_si_ademas_hay_url(self):
        """Un hash es inequívoco; una URL podría ser cualquier cosa."""
        from cogs.historial import _extraer_objetivo

        h = "b" * 40
        m = FakeMessage(content=f"https://ejemplo.com y el hash {h}")
        assert _extraer_objetivo(m) == ("hash", h)

    def test_limpia_la_puntuacion_del_enlace(self):
        from cogs.historial import _extraer_objetivo

        m = FakeMessage(content="(https://ejemplo.com).")
        assert _extraer_objetivo(m) == ("url", "https://ejemplo.com")

    def test_prefiere_el_adjunto_si_no_hay_texto(self):
        from cogs.historial import _extraer_objetivo

        m = FakeMessage(content="", attachments=[FakeAttachment("x.exe")])
        assert _extraer_objetivo(m) == ("file", "x.exe")

    def test_sin_nada_que_analizar_devuelve_none(self):
        from cogs.historial import _extraer_objetivo

        assert _extraer_objetivo(FakeMessage(content="hola")) is None

    def test_una_palabra_corta_no_es_un_hash(self):
        """Un id de usuario o una palabra suelta no debe ir a VT como hash."""
        from cogs.historial import _extraer_objetivo

        assert _extraer_objetivo(FakeMessage(content="abcdef")) is None

    def test_el_menu_se_registra_en_el_arbol(self):
        import discord

        from cogs.historial import menu_analizar

        assert isinstance(menu_analizar, discord.app_commands.ContextMenu)
        assert menu_analizar.name == "Analizar con Threat"

    def test_el_menu_recibe_el_mensaje(self):
        """Sin el parámetro `message` no funcionaría: es lo que da el contexto."""
        import inspect

        import cogs.historial as h

        assert list(inspect.signature(h._analizar_mensaje).parameters) == ["interaction", "message"]

    def test_el_menu_no_esta_dentro_de_una_clase(self):
        """discord.py lo rechaza: `TypeError: context menus cannot be defined inside a
        class`. Es una restricción de la librería, no una preferencia."""
        import inspect

        import cogs.historial as h

        assert not any(
            isinstance(m, (staticmethod, classmethod)) and getattr(m, "__func__", None)
            and getattr(m.__func__, "__name__", "") == "_analizar_mensaje"
            for m in vars(h.HistorialCog).values()
        )


class TestHistory:
    def test_tiempo_relativo(self):
        import time

        from cogs.historial import _tiempo_relativo

        ahora = time.time()
        assert "momento" in _tiempo_relativo(ahora - 5)
        assert "min" in _tiempo_relativo(ahora - 600)
        assert "h" in _tiempo_relativo(ahora - 7200)
        assert "d" in _tiempo_relativo(ahora - 86400 * 3)

    def test_tiempo_relativo_no_cede_con_relojes_desfasados(self):
        from cogs.historial import _tiempo_relativo

        assert _tiempo_relativo(99999999999) == "hace un momento"

    def test_history_exige_manage_messages(self):
        """El registro de un canal no es público: el expediente tampoco.

        El decorador envuelve el método en un `Command`, así que `getsource` sobre el
        atributo de clase falla; se lee el fichero.
        """
        import pathlib

        texto = pathlib.Path("cogs/historial.py").read_text(encoding="utf-8")
        bloque = texto[texto.index("name=\"history\""):texto.index("async def history")]
        assert "manage_messages" in bloque


class TestTablaEventos:
    def test_se_crea_al_arrancar(self):
        """Si no se crea, `/history` está vacío y no hay aviso de por qué."""
        import pathlib

        fuente = pathlib.Path("core/database.py").read_text(encoding="utf-8")
        assert "CREATE TABLE IF NOT EXISTS eventos" in fuente
        assert "idx_eventos_canal" in fuente

    def test_registrar_un_evento_nunca_lanza(self):
        """Perder un registro no puede tumbar un análisis ya publicado."""
        import inspect

        import core.database as db

        assert "except Exception" in inspect.getsource(db.registrar_evento)

    def test_leer_eventos_tolera_la_tabla_ausente(self):
        import inspect

        import core.database as db

        assert "except Exception" in inspect.getsource(db.obtener_eventos)
        assert "return []" in inspect.getsource(db.obtener_eventos)

    def test_el_limite_de_historial_esta_acotado(self):
        """Un `limite` sin tope sería una consulta que se lleva la base."""
        import inspect

        import core.database as db

        assert "min(limite, 25)" in inspect.getsource(db.obtener_eventos)
