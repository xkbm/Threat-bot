"""Defaults de una guild nueva: que sean una decisión y no una casualidad.

`strict_mode` está declarado en dos sitios vivos —el `ESQUEMA` y `_config_por_defecto()`.
Ese default decide si el bot borra mensajes, así que un desajuste entre los dos no da un
error: da una guild nueva que se comporta distinto según por qué camino entró, y solo se
ve en producción.

Aquí se atan los dos, y se fija el comportamiento que una guild nueva debe tener.
"""

import types

import pytest

from core import config_schema as esq
from core import guild_config as gc
from core import state


@pytest.fixture
def bot_falso(monkeypatch):
    bot = types.SimpleNamespace(guilds_data={})
    monkeypatch.setattr(state, "bot", bot)
    return bot


class TestDefaultDeBorrado:
    def test_una_guild_nueva_no_borra_mensajes(self):
        """El día 0 no se borra nada.

        Es la decisión de producto que evita que un owner que añade el bot sin más le
        desaparezcan mensajes y lo desinstale. Activarlo es un clic en `/settings`.
        """
        assert gc._config_por_defecto()["strict_mode"] is False

    def test_el_esquema_no_contradice_al_default_por_guild(self, bot_falso):
        """Las claves que viven en los dos sitios deben decir lo mismo.

        Se compara contra `esq.defaults()` y no contra `Clave.default`: `defaults()` es
        la que aplica la whitelist real de serie, y comparar contra el default crudo
        daría un falso positivo con `whitelist` (vacía en el esquema, los dominios
        protegidos en la realidad).
        """
        por_defecto = gc._config_por_defecto()
        for nombre, valor in esq.defaults().items():
            if nombre not in por_defecto:
                continue
            if isinstance(valor, list):
                assert por_defecto[nombre] == valor, nombre
            else:
                assert por_defecto[nombre] == valor, nombre


class TestGuildNueva:
    def test_tiene_las_claves_de_analisis(self, bot_falso):
        config = gc._asegurar_guild(123)
        assert config["strict_mode"] is False
        assert config["auto_scan_enabled"] is True
        assert config["log_channel_id"] is None

    def test_viene_con_la_whitelist_de_serie(self, bot_falso):
        config = gc._asegurar_guild(123)
        assert "youtube.com" in config["whitelist"]

    def test_cada_guild_tiene_su_propia_whitelist(self, bot_falso):
        """Un admin que toque su lista no puede contaminar la de los demás."""
        a = gc._asegurar_guild(1)
        b = gc._asegurar_guild(2)
        a["whitelist"].append("midominio.es")
        assert "midominio.es" not in b["whitelist"]


class TestGuildExistente:
    """Cambiar el default no puede tocar a quien ya lo tenía decidido."""

    def test_conserva_el_strict_mode_que_ya_tenia(self, bot_falso):
        bot_falso.guilds_data[123] = {"strict_mode": True}
        assert gc._asegurar_guild(123)["strict_mode"] is True

    def test_un_servidor_que_no_borraba_sigue_sin_borrar(self, bot_falso):
        bot_falso.guilds_data[456] = {"strict_mode": False}
        assert gc._asegurar_guild(456)["strict_mode"] is False