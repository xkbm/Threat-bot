"""Lo que ve un owner el día 0: el DM de bienvenida y `/setup`.

Existe por un motivo concreto: un owner añadió el bot, el bot le borró un mensaje sin
explicación, y lo desinstaló al día siguiente. Estas dos piezas son la defensa —avisar
antes de actuar— y la explicación de lo que ya está pasando.

Aquí se comprueba lo que no se puede ver en un test de lectura: que el DM sobreviva a
un owner inalcanzable, y que `/setup` lea el estado real en vez de afirmar un estado.
"""

import sys

import discord
import pytest


class _Miembro:
    def __init__(self, error=None):
        self.id = 42
        self.enviados = []
        self._error = error

    async def send(self, embed=None):
        if self._error is not None:
            raise self._error
        self.enviados.append(embed)


class _Guild:
    def __init__(self, owner, fetch=None):
        self.id = 100
        self.name = "Servidor de prueba"
        self.owner = owner
        self.owner_id = 42
        self._fetch = fetch
        self.fetches = 0

    async def fetch_member(self, member_id):
        self.fetches += 1
        if self._fetch is None:
            raise discord.errors.NotFound(_FakeResp(), "miembro no encontrado")
        return self._fetch


class _FakeResp:
    status = 404
    reason = "Not Found"
    text = "Unknown Member"


def _saludar():
    from tests import test_arranque

    # `_bot_cargado` es un fixture; su función real queda bajo `__wrapped__`. Se ejecuta
    # una vez y se cachea en `sys.modules`, que es justo lo que hace el propio fixture.
    cargar = getattr(test_arranque._bot_cargado, "__wrapped__", test_arranque._bot_cargado)
    cargar()
    return sys.modules["threat_bot_entorno"]["_saludar_owner"]


class TestDmDeBienvenida:
    @pytest.mark.asyncio
    async def test_llega_si_el_owner_esta_en_cache(self):
        owner = _Miembro()
        await _saludar()(_Guild(owner))

        assert len(owner.enviados) == 1
        texto = owner.enviados[0].description
        assert "no borro nada" in texto
        assert "/settings" in texto
        assert "/setup" in texto

    @pytest.mark.asyncio
    async def test_cae_a_rest_cuando_el_owner_no_esta_en_cache(self):
        """Sin el intent `members` la caché va vacía y `guild.owner` sale `None`.

        Es el caso normal en un servidor grande recién añadido. Sin este fallback el DM
        no llegaría justo a quien más lo necesita, y sin ningún error que lo delatara.
        """
        owner = _Miembro()
        guild = _Guild(None, fetch=owner)

        await _saludar()(guild)

        assert guild.fetches == 1
        assert len(owner.enviados) == 1

    @pytest.mark.asyncio
    async def test_los_dms_cerrados_no_tumban_la_entrada(self):
        """Que el owner tenga los DMs bloqueados es lo habitual, no un fallo."""
        owner = _Miembro(error=discord.errors.Forbidden(_FakeResp(), "Missing Access"))
        await _saludar()(_Guild(owner))  # no debe propagar

    @pytest.mark.asyncio
    async def test_un_owner_inexistente_no_tumba_la_entrada(self):
        guild = _Guild(None, fetch=None)
        await _saludar()(guild)  # `fetch_member` lanza NotFound; no debe propagar

    @pytest.mark.asyncio
    async def test_cualquier_otro_fallo_tampoco(self):
        guild = _Guild(object())
        await _saludar()(guild)  # owner sin `send`; no debe propagar


class _Interaccion:
    def __init__(self, guild):
        self.guild = guild
        self.enviados = []
        self.deferida = False
        fuera = self

        class _Respuesta:
            async def defer(self, **kwargs):
                fuera.deferida = True

        class _Followup:
            async def send(self, *args, **kwargs):
                fuera.enviados.append((args, kwargs))

        self.response = _Respuesta()
        self.followup = _Followup()


class _BotMinimo:
    EMOJI_INCORRECTO = ":x:"
    EMOJI_SHIELD = ":shield:"
    EMOJI_WARNING = ":warning:"


class TestComandoSetup:
    @pytest.mark.asyncio
    async def test_dice_que_no_borra_cuando_no_borra(self, monkeypatch):
        import cogs.configuracion as cfg_mod

        monkeypatch.setattr(cfg_mod, "obtener_config_guild",
                            _devuelve({"strict_mode": False}))
        comando = _ComandoSetup(cfg_mod).callback
        interaccion = _Interaccion(_Guild(_Miembro()))

        await comando(interaccion)

        embed = interaccion.enviados[0][1]["embed"]
        assert "no borro nada" in embed.description

    @pytest.mark.asyncio
    async def test_avisa_que_si_borra_cuando_borra(self, monkeypatch):
        """Si el admin lo activó a mano, el texto no puede seguir diciendo que no borra.

        Un explicador que afirma lo contrario de lo que hace es peor que no tener ninguno:
        el owner lee "no borra nada", confía y pierde el mensaje.
        """
        import cogs.configuracion as cfg_mod

        monkeypatch.setattr(cfg_mod, "obtener_config_guild",
                            _devuelve({"strict_mode": True}))
        comando = _ComandoSetup(cfg_mod).callback
        interaccion = _Interaccion(_Guild(_Miembro()))

        await comando(interaccion)

        embed = interaccion.enviados[0][1]["embed"]
        assert "no borro nada" not in embed.description
        assert "sí borro" in embed.description

    @pytest.mark.asyncio
    async def test_sin_analisis_automatico_no_dice_que_revisa(self, monkeypatch):
        """Con auto_scan apagado el bot no revisa nada: el texto no puede decir que sí.

        Es el mismo fallo que se arregló para el borrado, un poco más allá: un explicador
        que afirma una capacidad apagada es peor que no tener ninguno.
        """
        import cogs.configuracion as cfg_mod

        monkeypatch.setattr(cfg_mod, "obtener_config_guild",
                            _devuelve({"auto_scan_enabled": False}))
        comando = _ComandoSetup(cfg_mod).callback
        interaccion = _Interaccion(_Guild(_Miembro()))

        await comando(interaccion)

        texto = interaccion.enviados[0][1]["embed"].description.lower()
        assert "reviso cada mensaje" not in texto
        assert "no estoy revisando" in texto

    @pytest.mark.asyncio
    async def test_es_efimero_y_difiere_antes_de_responder(self, monkeypatch):
        """Sin el defer, Discord devuelve 400 y el comando no muestra nada."""
        import cogs.configuracion as cfg_mod

        monkeypatch.setattr(cfg_mod, "obtener_config_guild", _devuelve({}))
        comando = _ComandoSetup(cfg_mod).callback
        interaccion = _Interaccion(_Guild(_Miembro()))

        await comando(interaccion)

        assert interaccion.deferida
        assert interaccion.enviados[0][1]["ephemeral"] is True

    @pytest.mark.asyncio
    async def test_fuera_de_un_servidor_no_revienta(self, monkeypatch):
        import cogs.configuracion as cfg_mod

        monkeypatch.setattr(cfg_mod, "obtener_config_guild", _devuelve({}))
        comando = _ComandoSetup(cfg_mod).callback
        interaccion = _Interaccion(None)

        await comando(interaccion)

        assert interaccion.enviados, "debe contestar algo aunque no haya servidor"


def _config(valores):
    """Config mínima con lo que `/setup` lee. Lo que falte, su default."""
    from core import config_schema as esq

    base = esq.defaults()
    base.update(valores)
    return base


def _devuelve(valores):
    """`obtener_config_guild` es async; el sustituto también tiene que serlo."""
    async def _fake(*args):
        return _config(valores)

    return _fake


class _ComandoSetup:
    """Invoca el callback de `/setup` con un cog mínimo."""

    def __init__(self, mod):
        self.bot = _BotMinimo()

    @property
    def callback(self):
        from cogs.configuracion import ConfiguracionCog

        return ConfiguracionCog.puesta_en_marcha.callback.__get__(
            ConfiguracionCog(self.bot))