"""Motivos por los que se avisa de un fallo.

El problema que resuelve: `avisar_errores` era un interruptor único para dos cosas que
no significan lo mismo. "Se agotó la cuota de la API" y "este archivo era grande" caían
en el mismo booleán, así que no había forma de callar el segundo sin callar el primero.

La forma de arreglarlo que NO se ha elegido, a propósito: un interruptor por motivo. Serían
256 combinaciones, algunas contradictorias, y duplicarían los tres maestros que ya
existen. Es **un** control con los motivos, y solo cuentan si el maestro está activo.
"""

import pytest

from core.config_schema import MOTIVOS_FALLO as MOTIVOS
from core.config_schema import MOTIVOS_POR_DEFECTO
from core.aviso import (
    _hay_fallo,
    _motivos_aviso,
    config_aviso_por_defecto,
    debe_enviar_embed,
    razon_para_embeder,
)
from core.senales import Elemento, Senales, motivo_de_error
from core.veredictos import Veredicto


def _con_error(motivo_se, veredicto=Veredicto.ERROR):
    s = Senales()
    s.anadir(Elemento(nombre="x", tipo="file", veredicto=veredicto,
                      modelos={"error": motivo_se}))
    return s


def _solo_whitelist(n=1):
    s = Senales()
    s.whitelist_omitidos = n
    return s


def _solo_omitidos(n=2):
    s = Senales()
    s.omitidos = n
    return s


def _solo_cooldown():
    s = Senales()
    s.cooldown = True
    return s


class TestElCatalogo:
    def test_todo_motivo_interno_tiene_su_traduccion(self):
        """Si un motivo interno no está en el catálogo, se mostraría como texto crudo."""
        from api import sightengine as se

        for interno in (se.ERROR_SIN_CLAVES, se.ERROR_SIN_CUOTA, se.ERROR_SIN_BYTES,
                        se.ERROR_DEMASIADO_GRANDE, se.ERROR_HTTP, se.ERROR_EXCEPCION,
                        se.ERROR_SIN_MODELOS, se.ERROR_MODELO_NO_DISPONIBLE):
            assert motivo_de_error({"error": interno}) in MOTIVOS, interno

    def test_un_motivo_desconocido_cae_en_red(self):
        assert motivo_de_error({"error": "inventado"}) == "red"
        assert motivo_de_error({}) == "red"
        assert motivo_de_error(None) == "red"

    def test_todo_motivo_del_catalogo_tiene_texto(self):
        for clave, texto in MOTIVOS.items():
            assert texto and texto[0].isupper(), clave


class TestLosMotivosSeDerivan:
    def test_sin_nada_no_hay_motivos(self):
        assert Senales().motivos_calculados == set()

    def test_acumula_varios(self):
        s = _con_error("sin_cuota")
        s.cooldown = True
        s.omitidos = 1
        s.whitelist_omitidos = 1
        assert s.motivos_calculados == {"sin_cuota", "cooldown", "omitidos", "whitelist"}

    def test_un_elemento_limpio_no_aporta_motivos(self):
        s = Senales()
        s.anadir(Elemento(nombre="x", tipo="url", veredicto=Veredicto.SEGURO))
        assert s.motivos_calculados == set()

    def test_no_hay_que_mantenerlo_a_mano(self):
        """Si se rellenara a mano, el embed y la decisión de mandarlo divergirían."""
        s = _solo_omitidos(3)
        s.motivos = set()          # aunque alguien lo vacíe a mano
        assert "omitidos" in s.motivos_calculados


class TestFiltrado:
    def _cfg(self, motivos=None, **kw):
        base = config_aviso_por_defecto(True)
        if motivos is not None:
            base["motivos_fallo"] = motivos
        return {**base, **kw}

    def test_sin_configurar_se_usan_los_del_catalogo(self):
        """Un `data.json` viejo sin la clave no puede acabar callado entero."""
        assert _motivos_aviso({}) == set(MOTIVOS_POR_DEFECTO)

    def test_una_lista_vacia_silencia_todos_los_motivos(self):
        """Vacío a propósito es silencio a propósito, no "sin configurar"."""
        assert _motivos_aviso({"motivos_fallo": []}) == set()

    def test_el_maestro_apaga_todos_los_motivos(self):
        cfg = self._cfg(["sin_cuota", "red"], avisar_errores=False)
        for s in (_con_error("sin_cuota"), _solo_omitidos(), _solo_whitelist(), _solo_cooldown()):
            assert debe_enviar_embed(s, cfg) is False

    @pytest.mark.parametrize("motivo_interno,motivo_catalogo", [
        ("sin_cuota", "sin_cuota"),
        ("sin_claves", "sin_claves"),
        ("error_http", "red"),
        ("error_excepcion", "red"),
        ("too_large", "tamano"),
        ("sin_modelos", "sin_resultados"),
        ("modelo_no_disponible", "sin_resultados"),
        ("inventado", "red"),
    ])
    def test_cada_motivo_del_catalogo_solo_avisa_si_esta_activo(
        self, motivo_interno, motivo_catalogo
    ):
        """Con un único motivo activo, solo ese motivo debe hacer que avise."""
        s = _con_error(motivo_interno)
        assert debe_enviar_embed(s, self._cfg([motivo_catalogo])) is True
        for otro in MOTIVOS:
            if otro != motivo_catalogo:
                assert debe_enviar_embed(s, self._cfg([otro])) is False, (
                    f"un motivo interno ({motivo_interno}) avivaba por {otro}"
                )

    def test_callar_el_ruido_no_calla_lo_que_importa(self):
        """El caso concreto: callar 'demasiados adjuntos' y no callar la cuota."""
        cfg = self._cfg([m for m in MOTIVOS if m != "omitidos"])
        assert debe_enviar_embed(_solo_omitidos(4), cfg) is False
        assert debe_enviar_embed(_con_error("sin_cuota"), cfg) is True

    def test_callar_lo_importante_no_calla_el_ruido(self):
        cfg = self._cfg(["omitidos"])
        assert debe_enviar_embed(_con_error("sin_cuota"), cfg) is False
        assert debe_enviar_embed(_solo_omitidos(4), cfg) is True


class TestLoQueNoSeCallaNunca:
    """Un filtro de motivos que se traga una amenaza no es un filtro, es un agujero."""

    @pytest.mark.parametrize("v", [Veredicto.MALICIOSO, Veredicto.NSFW])
    def test_una_amenaza_avisa_siempre(self, v):
        s = Senales()
        s.anadir(Elemento(nombre="x", tipo="url", veredicto=v))
        cfg = {**config_aviso_por_defecto(True), "motivos_fallo": [],
               "avisar_limpios": False, "avisar_sospechosos": False,
               "avisar_errores": False}
        assert debe_enviar_embed(s, cfg) is True

    def test_un_hallazgo_avisa_si_este_interruptor_esta_activo(self):
        s = Senales()
        s.anadir(Elemento(nombre="x", tipo="url", veredicto=Veredicto.SOSPECHOSO))
        assert debe_enviar_embed(s, {**config_aviso_por_defecto(True),
                                      "motivos_fallo": []}) is True

    def test_un_mensaje_limpio_sigue_dependiendo_de_su_propio_interruptor(self):
        s = Senales()
        s.anadir(Elemento(nombre="x", tipo="url", veredicto=Veredicto.SEGURO))
        assert debe_enviar_embed(s, {**config_aviso_por_defecto(True),
                                      "motivos_fallo": []}) is False

    def test_mensaje_con_amenaza_y_fallo_silenciado_avisa(self):
        s = _con_error("sin_cuota")
        s.anadir(Elemento(nombre="y", tipo="url", veredicto=Veredicto.MALICIOSO))
        cfg = {**config_aviso_por_defecto(True), "motivos_fallo": []}
        assert debe_enviar_embed(s, cfg) is True


class TestLaWhitelistEsUnMotivo:
    """Antes se saltaba el maestro y avisaba siempre. Ahora es un motivo más."""

    def test_por_defecto_avisa(self):
        """El usuario pidió la whitelist: con el default tiene que ver que se aplicó."""
        assert debe_enviar_embed(_solo_whitelist(), config_aviso_por_defecto(True)) is True

    def test_se_puede_callar(self):
        cfg = {**config_aviso_por_defecto(True), "motivos_fallo": ["sin_cuota"]}
        assert debe_enviar_embed(_solo_whitelist(), cfg) is False

    def test_cuenta_como_fallo(self):
        assert _hay_fallo(_solo_whitelist()) is True

    def test_una_whitelist_con_amenicia_avisa_por_el_otro_lado(self):
        s = _solo_whitelist()
        s.anadir(Elemento(nombre="malo", tipo="url", veredicto=Veredicto.MALICIOSO))
        cfg = {**config_aviso_por_defecto(True), "motivos_fallo": []}
        assert debe_enviar_embed(s, cfg) is True


class TestLaExplicacion:
    def test_distingue_silenciado_por_maestro_de_silenciado_por_motivo(self):
        """Son dos cosas distintas y quien lee el log necesita saber cuál."""
        s = _solo_omitidos()
        por_maestro = razon_para_embeder(s, {**config_aviso_por_defecto(True),
                                             "avisar_errores": False})
        por_motivo = razon_para_embeder(s, {**config_aviso_por_defecto(True),
                                            "motivos_fallo": ["sin_cuota"]})
        assert por_maestro == "fallo silenciado"
        assert por_motivo == "fallo de motivo silenciado"

    def test_explica_cual_motivo_fue(self):
        s = _solo_whitelist()
        assert "whitelist" in razon_para_embeder(s, config_aviso_por_defecto(True))


class TestElEsquemeNoRompe:
    def test_la_clave_esta_declarada(self):
        from core import config_schema as esq

        assert "motivos_fallo" in esq.POR_NOMBRE
        assert esq.POR_NOMBRE["motivos_fallo"].tipo == "list"
        assert esq.POR_NOMBRE["motivos_fallo"].opciones == tuple(MOTIVOS)

    def test_el_default_son_motivos_del_catalogo(self):
        from core.config_schema import defaults

        assert set(defaults()["motivos_fallo"]) <= set(MOTIVOS)

    def test_omitidos_no_avisa_por_defecto(self):
        """Criterio: es ruido informativo y no requiere acción."""
        assert "omitidos" not in MOTIVOS_POR_DEFECTO

    def test_lo_critico_si_esta_por_defecto(self):
        assert "sin_cuota" in MOTIVOS_POR_DEFECTO
        assert "sin_claves" in MOTIVOS_POR_DEFECTO

    def test_un_motivo_inventado_se_rechaza(self):
        from core.config_schema import POR_NOMBRE

        with pytest.raises(ValueError):
            POR_NOMBRE["motivos_fallo"].valida(["inventado"])

    def test_la_validacion_acepta_una_lista_vacia(self):
        from core.config_schema import POR_NOMBRE

        assert POR_NOMBRE["motivos_fallo"].valida([]) == []
