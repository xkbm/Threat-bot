"""Retrocompatibilidad: actualizar el bot no puede cambiar lo que ve un servidor.

El riesgo concreto que fija este archivo: `silent_mode` se está reemplazando por tres
interruptores, y si la derivación de los defaults no usa el valor **de ese** guild, una
configuración existente cambia de comportamiento al actualizar, en silencio.

`silent_mode` valía False = "manda el embed siempre, también lo limpio". Al derivar
`avisar_limpios` del True por defecto en lugar del False guardado, ese servidor pasaba a
`avisar_limpios=False` y dejaba de recibir los embeds de mensajes limpios de golpe.
"""

import pytest

from core import guild_config as gc
from core.aviso import config_aviso_por_defecto, debe_enviar_embed
from core.senales import Elemento, Senales
from core.veredictos import Veredicto


@pytest.fixture
def guild_vacia(monkeypatch):
    """Una guild tal y como saldría de `data.json`, sin claves nuevas."""
    import types

    bot = types.SimpleNamespace(guilds_data={})
    import core.state as state
    monkeypatch.setattr(state, "bot", bot)
    return bot


class TestDerivacionDesdeElValorGuardado:
    def test_silent_false_derivavisar_limpios_true(self, guild_vacia):
        """El caso que se rompe: un servidor que quiere ver también lo limpio."""
        guild_vacia.guilds_data[1] = {"silent_mode": False, "strict_mode": True}

        config = gc._asegurar_guild(1)

        assert config["silent_mode"] is False
        assert config["avisar_limpios"] is True, (
            "un guild con silent_mode=False debe seguir viendo los mensajes limpios"
        )

    def test_silent_true_deriva_avisar_limpios_false(self, guild_vacia):
        guild_vacia.guilds_data[1] = {"silent_mode": True}

        config = gc._asegurar_guild(1)

        assert config["silent_mode"] is True
        assert config["avisar_limpios"] is False

    def test_guild_nueva_sin_silent_guardado(self, guild_vacia):
        """Sin nada guardado, manda el default: silencioso."""
        config = gc._asegurar_guild(99)
        assert config["silent_mode"] is True
        assert config["avisar_limpios"] is False

    def test_el_resto_de_claves_se_crea_igual(self, guild_vacia):
        guild_vacia.guilds_data[1] = {"silent_mode": False}
        config = gc._asegurar_guild(1)
        for clave in ("avisar_sospechosos", "avisar_errores", "reacciones"):
            assert clave in config
            assert config[clave] is True

    def test_las_claves_existentes_no_se_pisan(self, guild_vacia):
        """Si el usuario ya lo toco desde el panel, su valor manda."""
        guild_vacia.guilds_data[1] = {
            "silent_mode": False,
            "avisar_limpios": False,   # lo apagó a propósito
        }
        config = gc._asegurar_guild(1)
        assert config["avisar_limpios"] is False


class TestComportamientoEquivalenteAntesYDespues:
    """La garantía que de verdad importa: la misma config da el mismo resultado."""

    def _senales_limpias(self):
        s = Senales()
        s.anadir(Elemento(nombre="a", tipo="url", veredicto=Veredicto.SEGURO))
        return s

    @pytest.mark.parametrize("silent_mode", [True, False])
    def test_guardar_y_mandar_coincide_con_el_comportamiento_antiguo(self, guild_vacia, silent_mode):
        """Regla antigua: `has_threat or ... or not silent_mode`.

        Es decir: con el modo silencioso solo mandaba si había algo que mirar; sin él,
        siempre.
        """
        # Lo que había antes de los interruptores.
        config_antigua = {"silent_mode": silent_mode, "strict_mode": True}
        señales = {"amenaza": False, "sospechoso": False, "error": False, "omitidos": 0}
        antes = (señales["amenaza"] or señales["sospechoso"] or señales["error"]
                 or señales["omitidos"] or not silent_mode)

        # Lo de ahora, partiendo de una config guardada sin claves nuevas.
        guild_vacia.guilds_data[1] = dict(config_antigua)
        config = gc._asegurar_guild(1)
        ahora = debe_enviar_embed(self._senales_limpias(), config)

        assert ahora is antes, f"silent_mode={silent_mode}: cambió el comportamiento"

    @pytest.mark.parametrize("silent_mode", [True, False])
    def test_con_amenaza_siempre_manda(self, guild_vacia, silent_mode):
        """Con el master off, antes mandaba siempre. Ahora también."""
        guild_vacia.guilds_data[1] = {"silent_mode": silent_mode}
        config = gc._asegurar_guild(1)

        s = Senales()
        s.anadir(Elemento(nombre="a", tipo="url", veredicto=Veredicto.MALICIOSO))
        assert debe_enviar_embed(s, config) is True

    @pytest.mark.parametrize("silent_mode", [True, False])
    def test_con_error_respeta_el_comportamiento_antiguo(self, guild_vacia, silent_mode):
        """Un error antes mandaba siempre. Con el master activo, ahora depende del
        interruptor, pero su default reproduce ese comportamiento."""
        guild_vacia.guilds_data[1] = {"silent_mode": silent_mode}
        config = gc._asegurar_guild(1)

        s = Senales()
        s.anadir(Elemento(nombre="a", tipo="file", veredicto=Veredicto.ERROR))
        assert config["avisar_errores"] is True
        assert debe_enviar_embed(s, config) is True

    @pytest.mark.parametrize("silent_mode", [True, False])
    def test_con_omitidos_respeta_el_comportamiento_antiguo(self, guild_vacia, silent_mode):
        guild_vacia.guilds_data[1] = {"silent_mode": silent_mode}
        config = gc._asegurar_guild(1)

        s = Senales()
        s.omitidos = 2
        assert debe_enviar_embed(s, config) is True


class TestNoSePierdeNadaDeLaConfigVieja:
    def test_whitelist_y_strict_no_se_tocan(self, guild_vacia):
        guild_vacia.guilds_data[1] = {
            "silent_mode": False,
            "strict_mode": False,
            "whitelist": ["discord.com"],
            "log_channel_id": 12345,
        }
        config = gc._asegurar_guild(1)
        assert config["strict_mode"] is False
        assert config["whitelist"] == ["discord.com"]
        assert config["log_channel_id"] == 12345

    def test_infracciones_viejas_intactas(self, guild_vacia):
        guild_vacia.guilds_data[1] = {"infracciones": {"42": 3}}
        assert gc._asegurar_guild(1)["infracciones"] == {"42": 3}


class TestDefaultDeFabrica:
    def test_config_por_defecto_es_coherente_consigo_misma(self):
        """Lo que se usa al crear una guild desde cero."""
        cfg = gc._config_por_defecto()
        esperado = config_aviso_por_defecto(cfg["silent_mode"])
        for clave, valor in esperado.items():
            assert cfg[clave] == valor, clave