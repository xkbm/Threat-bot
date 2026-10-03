"""Reproduce el fallo de /settings con una interaction falsa.

Discord devuelve 400 cuando se llama a `followup.send()` sin haber respondido o
deferido antes. `discord.py` no lo valida en cliente: lo comprueba el servidor. Aquí se
replica ese contrato para poder reproducirlo sin gateway.
"""

import asyncio
import types

import discord
import pytest


class FakeResponse:
    def __init__(self):
        self.respondida = False
        self.deferida = False
        self.defer_efimera = None
        self.embed = None
        self.view = None
        self.editados = []

    async def edit_message(self, **kwargs):
        """Lo usan los botones del panel al repintar tras un cambio."""
        self.editados.append(kwargs)
        self.embed = kwargs.get("embed")
        self.view = kwargs.get("view")

    async def send_message(self, content=None, *, embed=None, view=None, ephemeral=False, **kw):
        if self.respondida or self.deferida:
            raise discord.HTTPException(
                types.SimpleNamespace(status=400, reason="Bad Request"),
                "This interaction has already been responded to.")
        self.respondida = True
        self.embed, self.view = embed, view

    async def defer(self, *, ephemeral=False, thinking=False):
        if self.respondida or self.deferida:
            raise discord.HTTPException(
                types.SimpleNamespace(status=400, reason="Bad Request"),
                "This interaction has already been responded to.")
        self.deferida = True
        self.defer_efimera = ephemeral


class FakeFollowup:
    def __init__(self, interaction):
        self._interaccion = interaction

    async def send(self, content=None, *, embed=None, view=None, ephemeral=False, **kw):
        if not (self._interaccion.response.respondida or self._interaccion.response.deferida):
            raise discord.HTTPException(
                types.SimpleNamespace(status=400, reason="Bad Request"),
                "This interaction has not been sent yet")
        self._interaccion.followup_enviados.append(
            types.SimpleNamespace(content=content, embed=embed, view=view, ephemeral=ephemeral))


class FakeInteraction:
    def __init__(self, guild=None):
        self.guild = guild
        self.response = FakeResponse()
        self.followup = FakeFollowup(self)
        self.followup_enviados = []
        self.channel = types.SimpleNamespace(send=self._send_canal)
        self.user = types.SimpleNamespace(id=99)
        self.guild_id = self.guild.id if self.guild else None

    async def _send_canal(self, *a, **kw):
        return None


class _Canal:
    id = 555
    mention = "<#555>"


class _Guild:
    id = 42

    def get_channel(self, cid):
        return _Canal() if cid == 555 else None


def _fake_bot():
    """Un bot con los emojis reales. `state.bot` lo instala el fixture."""
    import core.config as cfg
    emojis = {n: getattr(cfg, n) for n in dir(cfg) if n.startswith("EMOJI_")}
    return types.SimpleNamespace(
        **emojis,
        guilds_data={},
        user_scan_history={}, antispam_scan={}, vt_user_requests={},
        vt_key_usage={}, se_key_usage={},
        vt_key_total_requests={}, vt_key_daily_usage={},
        se_key_total_requests={}, se_key_daily_usage={}, se_key_monthly_usage={},
        guardar_datos=_no_guardar,
    )


async def _no_guardar(*a, **k):
    return None


@pytest.fixture(autouse=True)
def _sin_tareas_colgadas():
    """`guardar_datos` programa un debounce que sobrevive al test y peta al cerrar el loop."""
    from core import database as db

    db._guardar_datos_task = None
    db._guardar_datos_pendiente = False
    yield
    db._guardar_datos_task = None
    db._guardar_datos_pendiente = False


@pytest.fixture(autouse=True)
def bot_global():
    """`core.guild_config` lee de `state.bot`, que es global."""
    import core.state as state

    anterior = state.bot
    state.bot = _fake_bot()
    yield state.bot
    state.bot = anterior


class TestSettingsResponde:
    @pytest.mark.asyncio
    async def test_abre_el_panel(self, monkeypatch):
        import cogs.configuracion as cfg_mod

        cog = cfg_mod.ConfiguracionCog(_fake_bot())
        interaccion = FakeInteraction(_Guild())

        await cog.settings.callback(cog, interaccion)

        assert interaccion.followup_enviados, "no se envió nada: el comando falló en silencio"
        enviado = interaccion.followup_enviados[0]
        assert enviado.embed is not None, "sin embed"
        assert enviado.view is not None, "sin panel"
        assert enviado.ephemeral is True
        assert len(enviado.view.children) > 0

    @pytest.mark.asyncio
    async def test_responde_o_difiere_antes_de_hablar(self, monkeypatch):
        """La causa raíz: `followup.send` sin `defer` previo devuelve 400 de Discord.

        Este test falla si alguien quita el `defer` de `/settings`.
        """
        import cogs.configuracion as cfg_mod

        cog = cfg_mod.ConfiguracionCog(_fake_bot())
        interaccion = FakeInteraction(_Guild())

        await cog.settings.callback(cog, interaccion)

        assert interaccion.response.deferida or interaccion.response.respondida, (
            "/settings usa followup.send sin defer ni response: Discord devuelve 400 "
            "y el comando no muestra nada"
        )


class TestLosControlesNuevosDelPanel:
    """Canal de logs y whitelist se cambian desde el panel, no solo con comandos."""

    @pytest.fixture(autouse=True)
    def _panel(self, monkeypatch):
        import core.config_schema as esq
        from core import guild_config as gc_mod
        from ui import panel as pan

        self.panel = pan          # antes del yield: si no, el test no lo ve
        self.config = dict(esq.defaults())
        self.guardados = {}

        async def _obtener(guild_id):
            return dict(self.config)

        async def _actualizar(guild_id, _c=None, _g=None, **campos):
            _g.update(campos)
            _c.update(campos)
            return _c

        monkeypatch.setattr(gc_mod, "obtener_config_guild", _obtener)
        monkeypatch.setattr(pan, "obtener_config_guild", _obtener)
        gc_mod.actualizar_config = lambda gid, _c=None, _g=None, **kw: _actualizar(
            gid, _c=self.config, _g=self.guardados, **kw)
        monkeypatch.setattr(pan, "actualizar_config", gc_mod.actualizar_config)
        yield

    async def _vista(self, seccion, guild=None):
        class _Perm:
            send_messages = True

        class _Canal:
            def __init__(self, i, n):
                self.id, self.name, self.topic = i, n, ""

            def permissions_for(self, m):
                return _Perm()

        class _Guild:
            id = 1
            text_channels = [_Canal(1, "general"), _Canal(2, "registros")]
            me = object()

            def get_channel(self, c):
                return None

        return await self.panel.PanelConfig.crear(seccion, guild or _Guild())

    @pytest.mark.asyncio
    async def test_general_tiene_selector_de_canal(self):
        v = await self._vista("general")
        selectores = [h for h in v.children if type(h).__name__ == "SelectorCanalLog"]
        assert selectores, "el canal de logs solo se mostraba, no se podía cambiar"
        valores = {o.value for o in selectores[0].options}
        assert {"0", "1", "2"} <= valores, "faltan canales del servidor"

    @pytest.mark.asyncio
    async def test_el_selector_marca_el_canal_actual(self):
        self.config["log_channel_id"] = 2
        v = await self._vista("general")
        sel = next(h for h in v.children if type(h).__name__ == "SelectorCanalLog")
        marcados = [o.value for o in sel.options if o.default]
        assert marcados == ["2"]

    @pytest.mark.asyncio
    async def test_sin_canal_esta_marcado_el_primero(self):
        v = await self._vista("general")
        sel = next(h for h in v.children if type(h).__name__ == "SelectorCanalLog")
        assert [o.value for o in sel.options if o.default] == ["0"]

    @pytest.mark.asyncio
    async def test_exclusiones_tiene_el_boton_de_anadir(self):
        v = await self._vista("exclusiones")
        assert any(type(h).__name__ == "BotonAnadirWhitelist" for h in v.children)

    @pytest.mark.asyncio
    async def test_un_guild_sin_canales_no_rompe(self):
        """Sin canales de texto no hay selector, pero el panel se construye igual."""
        class _GuildVacio:
            id = 1
            text_channels = []
            me = object()

            def get_channel(self, c):
                return None

        v = await self._vista("general", _GuildVacio())
        assert len(v.children) > 0

    @pytest.mark.asyncio
    async def test_permisos_que_fallan_no_rompen(self):
        class _GuildLento:
            id = 1
            text_channels = [object()]

            @property
            def me(self):
                raise RuntimeError("sin permisos")

            def get_channel(self, c):
                return None

        v = await self._vista("general", _GuildLento())
        assert len(v.children) > 0


class TestElBotonDeWhitelistReutilizaLaValidacionDelComando:
    """Dos copias del chequeo de dominio divergen; por eso se reutiliza la del comando."""

    def test_el_panel_usa_el_validador_de_core(self):
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        panel = (raiz / "ui" / "panel.py").read_text(encoding="utf-8")
        # No debe reimplementar el patrón: lo toma de donde está.
        assert "PATRON_DOMINIO: re.Pattern" not in panel
        assert "from core.utils import es_dominio_valido" in panel

    @pytest.mark.parametrize(
        "entrada,esperado",
        [
            ("ejemplo.com", "ejemplo.com"),
            ("EJEMPLO.COM", "ejemplo.com"),
            ("www.ejemplo.com", "ejemplo.com"),
            ("https://www.ejemplo.com/path?a=1", "ejemplo.com"),
            ("http://user:pw@ejemplo.com:8080/x", "ejemplo.com"),
        ],
    )
    def test_acepta_urls_completas(self, entrada, esperado):
        from core.utils import normalizar_dominio

        assert normalizar_dominio(entrada) == esperado

    @pytest.mark.parametrize("entrada", ["", "no-es-un-dominio", "ejemplo.com.", " "])
    def test_rechaza_lo_que_no_es_dominio(self, entrada):
        from core.utils import es_dominio_valido, normalizar_dominio

        assert not es_dominio_valido(normalizar_dominio(entrada))


class TestTodoSeConfiguraDesdeElPanel:
    """Ningún otro comando cambia configuración: todo pasa por el panel."""

    def test_no_quedan_comandos_de_configuracion(self):
        import inspect

        import cogs.configuracion as cfg_mod

        nombres = []
        for attr in vars(cfg_mod.ConfiguracionCog).values():
            comando = getattr(attr, "callback", None)
            if comando is not None and getattr(comando, "__name__", "") != "settings":
                nombres.append(comando.__name__)
        assert nombres == [], f"comandos de configuración fuera del panel: {nombres}"

    def test_no_existe_cog_de_whitelist(self):
        """El panel añade y quita dominios; el comando se fue con el resto."""
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        assert not (raiz / "cogs" / "whitelist.py").exists()

    def test_ayuda_no_anuncia_comandos_que_no_existen(self):
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "cogs" / "help.py").read_text(encoding="utf-8")
        for eliminado in ("/silentmode", "/strictmode", "/autoscan",
                          "/setlogchannel", "/disablelogchannel", "/whitelist"):
            assert eliminado not in texto, f"/help sigue anunciando {eliminado}"


class TestQuitarDominioDesdeElPanel:
    @pytest.fixture(autouse=True)
    def _panel(self, monkeypatch):
        import core.config_schema as esq
        from core import guild_config as gc_mod
        from ui import panel as pan

        self.panel = pan
        self.config = dict(esq.defaults())
        self.quitados = []

        async def _obtener(guild_id):
            return dict(self.config)

        async def _actualizar(guild_id, _c=None, _q=None, **campos):
            _c.update(campos)
            return _c

        import core.config_schema as esq
        self.protegidos = set(esq.DOMINIOS_PROTEGIDOS)
        self.quitar_rechazados = []

        async def _quitar(guild_id, dominio):
            self.quitados.append(dominio)
            if dominio in self.protegidos:
                self.quitar_rechazados.append(dominio)
                return False
            self.config["whitelist"] = [
                d for d in self.config["whitelist"] if d != dominio]
            return True

        monkeypatch.setattr(gc_mod, "obtener_config_guild", _obtener)
        monkeypatch.setattr(pan, "obtener_config_guild", _obtener)
        monkeypatch.setattr(gc_mod, "actualizar_config", _actualizar)
        monkeypatch.setattr(pan, "actualizar_config", _actualizar)
        monkeypatch.setattr(gc_mod, "quitar_dominio", _quitar)
        yield

    class _Guild:
        id = 1
        text_channels = []
        me = object()

    @pytest.mark.asyncio
    async def test_hay_selector_para_quitar_los_propios(self):
        """El desplegable ofrece los dominios del admin, y solo esos.

        Con la config de serie no hay ninguno propio, así que no hay desplegable: los
        protegidos no se pueden quitar y ofrecerlos era ofrecer algo que va a fallar.
        """
        v = await self.panel.PanelConfig.crear("exclusiones", self._Guild())
        assert not [h for h in v.children
                    if type(h).__name__ == "SelectorQuitarWhitelist"]

        self.config["whitelist"] = ["mi-web.es", "discord.gg"]
        v = await self.panel.PanelConfig.crear("exclusiones", self._Guild())
        quitas = [h for h in v.children
                  if type(h).__name__ == "SelectorQuitarWhitelist"]
        assert quitas, "no hay forma de quitar un dominio propio desde el panel"
        assert {o.value for o in quitas[0].options} == {"mi-web.es", "discord.gg"}

    @pytest.mark.asyncio
    async def test_los_protegidos_no_se_ofrecen(self):
        """Están para ahorrar peticiones. Quitarlos sería gastar, no ahorrar."""
        # Se AÑADE un dominio propio sin tocar los de serie: si se reemplazara la lista,
        # no habría protegidos que ofrecer y el test pasaría sin comprobar nada. Ya
        # pasó una vez.
        assert self.config["whitelist"], "la config de serie ya no trae los protegidos"
        self.config["whitelist"] = list(self.config["whitelist"]) + ["mi-web.es"]

        v = await self.panel.PanelConfig.crear("exclusiones", self._Guild())
        sel = next(h for h in v.children
                   if type(h).__name__ == "SelectorQuitarWhitelist")
        ofrecidos = {o.value for o in sel.options}
        assert self.protegidos, "el test necesita saber cuáles son los protegidos"
        assert not (ofrecidos & self.protegidos), (
            f"se están ofreciendo protegidos: {ofrecidos & self.protegidos}"
        )
        assert "mi-web.es" in ofrecidos, "el propio sí debe ofrecerse"

    @pytest.mark.asyncio
    async def test_sin_dominios_no_hay_selector_vacio(self):
        """Un desplegable sin opciones no se puede construir y se lee como un fallo."""
        self.config["whitelist"] = []
        v = await self.panel.PanelConfig.crear("exclusiones", self._Guild())
        assert not [h for h in v.children
                    if type(h).__name__ == "SelectorQuitarWhitelist"]
        # Pero el botón de añadir sigue ahí, que es lo que importa con la lista vacía.
        assert [h for h in v.children
                if type(h).__name__ == "BotonAnadirWhitelist"]

    @pytest.mark.asyncio
    async def test_quitar_un_protegido_no_dice_que_se_quito(self):
        """`quitar_dominio` es el que decide de verdad, no el desplegable.

        Si dice que no, el panel no puede responder "quitado": el admin creería que ya
        está pagando por ese tráfico. Antes el desplegable ofrecía los protegidos con un
        texto que prometía que volverían al reiniciar, y no era verdad.
        """
        self.config["whitelist"] = ["mi-web.es"]
        v = await self.panel.PanelConfig.crear("exclusiones", self._Guild())
        sel = next(h for h in v.children
                   if type(h).__name__ == "SelectorQuitarWhitelist")

        enviados = []

        class _Resp:
            async def send_message(self, *a, **k):
                enviados.append(a[0] if a else k.get("content", ""))

        inter = types.SimpleNamespace(guild=self._Guild(), response=_Resp())
        # `values` es una propiedad de clase que en 2.7 no guarda nada en la instancia,
        # así que se sustituye la propiedad entera en vez de tocar un atributo interno.
        from unittest.mock import PropertyMock, patch
        with patch.object(type(sel), "values", new_callable=PropertyMock,
                          return_value=["youtube.com"]):
            await sel.callback(inter)

        assert enviados, "no respondió nada al moderador"
        assert "protegido" in enviados[0].lower(), enviados[0]
        assert "quitado" not in enviados[0].lower(), enviados[0]
