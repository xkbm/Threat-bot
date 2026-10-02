"""Retrocompatibilidad: actualizar el bot no puede dejar un servidor a medias.

Aquí hubo antes un bloque entero con la garantía de que los interruptores antiguos
derivaban su valor por defecto del `silent_mode` guardado, para que un servidor que
actualizase no viera cambiar lo que recibe. Ese diseño se sustituyó por una lista de
categorías con un dial cada una, y los interruptores antiguos ya no existen.

La garantía que queda, y que es la que importa: **una configuración antigua, sin la
clave nueva, tiene que seguir produciendo un bot que funciona y que avisa de lo grave.**
No se intenta adivinar qué interruptores dejó puestos quien configuró el bot antes de que
existiera el dial por categoría: no hay forma honesta de hacerlo, y una suposición
equivocada silencia justo lo que ese admin quería vigilar.
"""

import types

import pytest

from core import config_schema as esq
from core.aviso import (
    categorias_aviso,
    config_aviso_por_defecto,
    debe_enviar_embed,
    reacciones_activas,
)
from core.senales import Elemento, Senales
from core.veredictos import Veredicto


@pytest.fixture
def guild_vacia(monkeypatch):
    import core.state as state
    from core import guild_config as gc

    bot = types.SimpleNamespace(guilds_data={})
    monkeypatch.setattr(state, "bot", bot)
    return bot


async def _config_de(guild_id):
    """`obtener_config_guild` es async; los tests de abajo son async por eso.

    Antes esto creaba un event loop nuevo por llamada, y como los locks de
    `core.guild_config` se asocian al loop en su primer uso, al ejecutarse el fichero
    entero los tests fallaban porштрас el fallo venía de la mezcla de loops.
    """
    from core.guild_config import obtener_config_guild

    return await obtener_config_guild(guild_id)


def _con_veredicto(v) -> Senales:
    s = Senales()
    s.anadir(Elemento(nombre="x", tipo="url", veredicto=v))
    return s


def _con_error(motivo_se) -> Senales:
    s = Senales()
    s.anadir(Elemento(nombre="x", tipo="file", veredicto=Veredicto.ERROR,
                      modelos={"error": motivo_se}))
    return s


class TestConfiguracionAntigua:
    @pytest.mark.asyncio
    async def test_sin_la_clave_nueva_avisa_de_lo_grave(self, guild_vacia):
        """Un `data.json` viejo no tiene `notificar`; el bot debe seguir avisando."""
        guild_vacia.guilds_data[1] = {"silent_mode": True, "strict_mode": True}
        config = await _config_de(1)
        for grave in (Veredicto.MALICIOSO, Veredicto.NSFW, Veredicto.PHISHING):
            assert debe_enviar_embed(_con_veredicto(grave), config) is True, grave

    @pytest.mark.asyncio
    async def test_las_claves_antiguas_se_ignoran_en_vez_de_dar_error(self, guild_vacia):
        """Un servidor puede tener `avisar_limpios` y compañía: sobran, no rompen."""
        guild_vacia.guilds_data[1] = {
            "silent_mode": True, "strict_mode": True,
            "avisar_limpios": False, "avisar_sospechosos": True,
            "avisar_errores": True, "motivos_fallo": ["sin_cuota"],
        }
        config = await _config_de(1)
        # La clave vieja se traduce y desaparece: si se quedara, habría dos
        # interruptores con el mismo nombre y sentidos distintos en la misma config.
        assert config["avisar_todo"] is True
        assert "silent_mode" not in config
        assert debe_enviar_embed(_con_veredicto(Veredicto.MALICIOSO), config) is True

    @pytest.mark.asyncio
    async def test_el_resto_de_claves_se_crea_igual(self, guild_vacia):
        guild_vacia.guilds_data[1] = {"silent_mode": False}
        config = await _config_de(1)
        assert config["notificar"] == list(esq.CATEGORIAS_POR_DEFECTO)
        assert reacciones_activas(config) is True

    @pytest.mark.asyncio
    async def test_whitelist_y_strict_no_se_tocan(self, guild_vacia):
        guild_vacia.guilds_data[1] = {
            "silent_mode": True, "strict_mode": False,
            "whitelist": ["discord.com"], "log_channel_id": 42,
        }
        config = await _config_de(1)
        assert config["strict_mode"] is False
        assert config["whitelist"] == ["discord.com"]
        assert config["log_channel_id"] == 42


class TestLoQueSigueImportando:
    @pytest.mark.asyncio
    async def test_el_default_no_depende_del_silent_mode_guardado(self, guild_vacia):
        """Con el interruptor general apagado el bot no avisa de nada, solo importa qué
        haya en la lista. Ese estado es el que un admin elige a propósito."""
        guild_vacia.guilds_data[1] = {"avisar_todo": False, "notificar": ["nsfw"]}
        config = await _config_de(1)
        assert debe_enviar_embed(_con_veredicto(Veredicto.NSFW), config) is False
        assert debe_enviar_embed(_con_veredicto(Veredicto.NSFW),
                                 {**config, "avisar_todo": True}) is True

    @pytest.mark.asyncio
    async def test_el_ruido_no_avisa_sin_que_haya_que_configurar_nada(self, guild_vacia):
        guild_vacia.guilds_data[1] = {"silent_mode": True}
        config = await _config_de(1)
        assert debe_enviar_embed(_con_veredicto(Veredicto.SEGURO), config) is False

    @pytest.mark.asyncio
    async def test_un_error_de_cuota_si_avisa(self, guild_vacia):
        """Con la configuración por defecto, quedarse sin cuota es justo lo que hay que
        decir: el bot ha dejado de trabajar."""
        guild_vacia.guilds_data[1] = {"silent_mode": True}
        config = await _config_de(1)
        assert debe_enviar_embed(_con_error("sin_cuota"), config) is True

    @pytest.mark.asyncio
    async def test_un_mensaje_con_amenaza_si_avisa(self, guild_vacia):
        guild_vacia.guilds_data[1] = {"silent_mode": True}
        config = await _config_de(1)
        s = _con_veredicto(Veredicto.MALICIOSO)
        s.anadir(Elemento(nombre="y", tipo="file", veredicto=Veredicto.ERROR,
                          modelos={"error": "sin_cuota"}))
        assert debe_enviar_embed(s, config) is True


class TestDefaultsDelCatalogo:
    @pytest.mark.asyncio
    async def test_una_lista_vacia_significa_silencio(self):
        """La ambigüedad que hace que un filtro mal entendido calle lo importante."""
        assert len(categorias_aviso({"notificar": []})) == 0

    @pytest.mark.asyncio
    async def test_sin_clave_usa_el_default_del_catalogo(self):
        assert categorias_aviso({}) == set(esq.CATEGORIAS_POR_DEFECTO)

    @pytest.mark.asyncio
    async def test_el_default_equivale_a_todo_menos_el_ruido(self):
        esperados = set(esq.CATEGORIAS_AVISO) - {"limpio", "omitidos"}
        assert set(esq.CATEGORIAS_POR_DEFECTO) == esperados

    @pytest.mark.asyncio
    async def test_el_default_no_deja_al_bot_mudo(self):
        """Con los defaults, un malware y una caída de cuota se avisan."""
        cfg = config_aviso_por_defecto(True)
        for v in (Veredicto.MALICIOSO, Veredicto.PHISHING, Veredicto.NSFW):
            assert debe_enviar_embed(_con_veredicto(v), cfg) is True, v
        assert debe_enviar_embed(_con_error("sin_cuota"), cfg) is True
