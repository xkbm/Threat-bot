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
        se_key_total_requests={}, se_key_daily_usage={},
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


class TestTodosLosComandosResponden:
    """Guarda para los siete: el mismo fallo se repite si alguien lo copia."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "nombre,args",
        [
            ("silentmode", (True,)),
            ("strictmode", (True,)),
            ("autoscan", (True,)),
            ("setlogchannel", (_Canal(),)),
        ],
    )
    async def test_cada_comando_responde_o_difiere(self, nombre, args):
        import cogs.configuracion as cfg_mod

        cog = cfg_mod.ConfiguracionCog(_fake_bot())
        interaccion = FakeInteraction(_Guild())
        comando = getattr(cog, nombre)
        await comando.callback(cog, interaccion, *args)
        assert interaccion.response.deferida or interaccion.response.respondida, nombre
        assert interaccion.followup_enviados, nombre


class TestElMasterYElInterruptorVanJuntos:
    """El panel y `/silentmode` no pueden divergir.

    Con el master apagado, `debe_enviar_embed` devuelve True siempre, así que el
    comportamiento no depende de `avisar_limpios`. Pero el valor **que se muestra** en el
    panel sí, y si divergen el usuario ve "general apagado" junto a "no avisar limpios" sin
    ninguna pista de que se contradicen.
    """

    @pytest.mark.asyncio
    async def test_el_panel_ajusta_los_dos(self):
        import cogs.configuracion as cfg_mod
        from core import config_schema as esq
        from core.guild_config import obtener_config_guild
        from ui import panel as pan

        guild = _Guild()
        vista = await pan.PanelConfig.crear(esq.AVISO, guild)
        boton = next(h for h in vista.children
                     if getattr(h, "custom_id", "").endswith("silent_mode"))

        await boton.callback(FakeInteraction(guild))

        config = await obtener_config_guild(guild.id)
        assert config["silent_mode"] is False
        assert config["avisar_limpios"] is True, (
            "el panel dejó el master apagado sin tocar 'avisar limpios': "
            "/silentmode sí lo haría y las dos vías divergen"
        )

    @pytest.mark.asyncio
    async def test_el_comando_y_el_panel_dejan_el_mismo_estado(self):
        """Cada vía, desde cero, y el resultado se compara.

        Antes esta prueba mutaba el mismo guild dos veces y comparaba, lo que la hacía
        depender del orden de ejecución: si otro test dejaba el guild a medias, fallaba
        sin que hubiera ningún cambio real.
        """
        import cogs.configuracion as cfg_mod
        from core import config_schema as esq
        from core.guild_config import obtener_config_guild
        from ui import panel as pan

        async def _por_el_panel():
            guild = _Guild()
            vista = await pan.PanelConfig.crear(esq.AVISO, guild)
            boton = next(h for h in vista.children
                         if getattr(h, "custom_id", "").endswith("silent_mode"))
            await boton.callback(FakeInteraction(guild))
            return {k: v for k, v in (await obtener_config_guild(guild.id)).items()
                    if k in ("silent_mode", "avisar_limpios")}

        async def _por_el_comando():
            guild = _Guild()
            cog = cfg_mod.ConfiguracionCog(_fake_bot())
            interaccion = FakeInteraction(guild)
            await cog.silentmode.callback(cog, interaccion, False)
            return {k: v for k, v in (await obtener_config_guild(guild.id)).items()
                    if k in ("silent_mode", "avisar_limpios")}

        assert await _por_el_panel() == await _por_el_comando()
