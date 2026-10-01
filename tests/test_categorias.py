"""Un dial por categoría: qué avisa en el canal y qué no.

Antes eran tres interruptores (limpios, sospechosos, errores) más una lista aparte para
los motivos de fallo. Eso dejaba cosas imposibles de expresar: callar "se acabó la cuota"
sin callar también "había demasiados adjuntos", y callar el NSFW sin callar el malware.

Ahora hay una categoría por lo que puede salir en un mensaje, y cada una con su dial. La
regla es una intersección: si el mensaje tiene alguna categoría activa, se avisa. Sin
jerarquías ni casos especiales.

El estado "todo apagado" es legítimo: hay quien prefiere mirar el panel en silencio y
usar solo la reacción. Por eso la lista vacía significa silencio, no "sin configurar".
"""

import pytest

from core import config_schema as esq
from core.aviso import (
    categorias_aviso,
    config_aviso_por_defecto,
    debe_enviar_embed,
    razon_para_embeder,
    reacciones_activas,
)
from core.senales import Elemento, Senales
from core.veredictos import Veredicto


def _senales(*veredictos, **flags) -> Senales:
    s = Senales()
    for v in veredictos:
        s.anadir(Elemento(nombre=f"e-{getattr(v, 'value', v)}", tipo="file", veredicto=v))
    s.cooldown = flags.get("cooldown", False)
    s.omitidos = flags.get("omitidos", 0)
    s.whitelist_omitidos = flags.get("whitelist", 0)
    return s


def _cfg(notificar=None, **kw) -> dict:
    base = {**config_aviso_por_defecto(True), "reacciones": True}
    if notificar is not None:
        base["notificar"] = list(notificar)
    return {**base, **kw}


class TestElCatalogo:
    def test_toda_categoria_generada_existe_en_el_catalogo(self):
        """Si el análisis produce una categoría sin dial, no se puede silenciar."""
        s = Senales()
        for v in Veredicto:
            if v is Veredicto.ERROR:
                s.anadir(Elemento(nombre="a", tipo="file", veredicto=v,
                                  modelos={"error": "sin_cuota"}))
                s.anadir(Elemento(nombre="b", tipo="file", veredicto=v,
                                  modelos={"error": "too_large"}))
                s.anadir(Elemento(nombre="c", tipo="file", veredicto=v,
                                  modelos={"error": "error_http"}))
                s.anadir(Elemento(nombre="d", tipo="file", veredicto=v,
                                  modelos={"error": "sin_modelos"}))
            else:
                s.anadir(Elemento(nombre="a", tipo="file", veredicto=v))
        s.anadir(Elemento(nombre="e", tipo="file", veredicto=Veredicto.SEGURO,
                          doble_extension=True))
        s.omitidos, s.whitelist_omitidos, s.cooldown = 1, 1, True
        s.anadir(Elemento(nombre="f", tipo="file", veredicto=Veredicto.ERROR,
                          modelos={"error": "sin_bytes"}))
        assert s.categorias <= set(esq.CATEGORIAS), sorted(s.categorias - set(esq.CATEGORIAS))

    def test_toda_categoria_tiene_etiqueta_y_ayuda(self):
        for clave, (etiqueta, ayuda) in esq.CATEGORIAS.items():
            assert etiqueta and ayuda, clave

    def test_el_default_no_incluye_el_ruido(self):
        assert "limpio" not in esq.CATEGORIAS_POR_DEFECTO
        assert "omitidos" not in esq.CATEGORIAS_POR_DEFECTO

    def test_lo_critico_cubre_lo_que_requiere_accion(self):
        for clave in ("malicioso", "phishing", "nsfw", "sin_cuota", "sin_claves"):
            assert clave in esq.CATEGORIAS_CRITICAS, clave


class TestUnDialPorCategoria:
    @pytest.mark.parametrize("categoria", [c for c in esq.CATEGORIAS if c != "limpio"])
    def test_cada_categoria_se_puede_silenciar_sola(self, categoria):
        """El requisito: nunca sabemos qué quiere el usuario, así que todo lleva dial."""
        # Un mensaje con esa categoría y solo esa.
        s = Senales()
        if categoria in ("malicioso", "phishing", "nsfw", "restringido", "sospechoso"):
            s.anadir(Elemento(nombre="x", tipo="file",
                              veredicto=Veredicto(categoria)))
        elif categoria == "nombre_sospechoso":
            s.anadir(Elemento(nombre="x", tipo="file", veredicto=Veredicto.SEGURO,
                              doble_extension=True))
        elif categoria == "cooldown":
            s.cooldown = True
        elif categoria == "whitelist":
            s.whitelist_omitidos = 1
        elif categoria == "omitidos":
            s.omitidos = 1
        else:
            s.anadir(Elemento(nombre="x", tipo="file", veredicto=Veredicto.ERROR,
                              modelos={"error": {
                                  "sin_cuota": "sin_cuota", "sin_claves": "sin_claves",
                                  "red": "error_http", "tamano": "too_large",
                                  "sin_resultados": "sin_modelos",
                              }[categoria]}))

        activas = [c for c in esq.CATEGORIAS if c != categoria]
        assert debe_enviar_embed(s, _cfg(notificar=activas)) is False, (
            f"'{categoria}' se avisó sin su dial activado"
        )
        assert debe_enviar_embed(s, _cfg(notificar=activas + [categoria])) is True

    def test_nada_activado_no_avisa_nunca(self):
        """Estado legítimo: solo la reacción."""
        s = _senales(Veredicto.MALICIOSO, Veredicto.NSFW, cooldown=True, whitelist=1)
        assert debe_enviar_embed(s, _cfg(notificar=[])) is False

    def test_todo_activado_avisa_de_todo(self):
        s = _senales(Veredicto.MALICIOSO, whitelist=1)
        assert debe_enviar_embed(s, _cfg(notificar=esq.CATEGORIAS_AVISO)) is True

    def test_una_lista_vacia_no_es_lo_mismo_que_sin_configurar(self):
        """La ambigüedad que hace que un filtro mal entendido calle lo importante."""
        vacio = categorias_aviso({"notificar": []})
        sin_clave = categorias_aviso({})
        assert len(vacio) == 0
        assert sin_clave == set(esq.CATEGORIAS_POR_DEFECTO)


class TestElInterruptorGeneral:
    def test_apagado_silencia_todas_las_categorias(self):
        s = _senales(Veredicto.MALICIOSO)
        cfg = _cfg(notificar=esq.CATEGORIAS_AVISO, silent_mode=False)
        assert debe_enviar_embed(s, cfg) is False

    def test_encendido_respeta_los_diales(self):
        s = _senales(Veredicto.MALICIOSO)
        assert debe_enviar_embed(s, _cfg(notificar=["malicioso"], silent_mode=True)) is True
        assert debe_enviar_embed(s, _cfg(notificar=["nsfw"], silent_mode=True)) is False


class TestReacciones:
    def test_es_un_interruptor_aparte(self):
        """La reacción es retroalimentación, no una notificación."""
        assert reacciones_activas({"reacciones": False}) is False
        assert reacciones_activas({"reacciones": True}) is True

    def test_apagar_reacciones_no_apaga_el_embed(self):
        s = _senales(Veredicto.MALICIOSO)
        cfg = _cfg(notificar=esq.CATEGORIAS_AVISO, reacciones=False)
        assert debe_enviar_embed(s, cfg) is True


class TestMensajesConVariasCategorias:
    def test_basta_una_categoria_activa(self):
        s = _senales(Veredicto.MALICIOSO, cooldown=True, whitelist=1)
        assert debe_enviar_embed(s, _cfg(notificar=["cooldown"])) is True

    def test_todas_silenciadas_no_avisa(self):
        s = _senales(Veredicto.MALICIOSO, cooldown=True, whitelist=1)
        assert debe_enviar_embed(s, _cfg(notificar=[])) is False

    def test_limpio_necesita_su_propio_dial(self):
        s = Senales()
        s.anadir(Elemento(nombre="x", tipo="url", veredicto=Veredicto.SEGURO))
        assert debe_enviar_embed(s, _cfg(notificar=esq.CATEGORIAS_POR_DEFECTO)) is False
        assert debe_enviar_embed(s, _cfg(notificar=["limpio"])) is True


class TestExplicacion:
    def test_nombra_las_categorias_que_mandan(self):
        s = _senales(Veredicto.MALICIOSO, cooldown=True)
        cfg = _cfg(notificar=["malicioso"])
        assert "malicioso" in razon_para_embeder(s, cfg)
        assert "cooldown" not in razon_para_embeder(s, cfg)

    def test_distingue_el_interruptor_general(self):
        s = _senales(Veredicto.MALICIOSO)
        cfg = _cfg(notificar=esq.CATEGORIAS_AVISO, silent_mode=False)
        assert "general" in razon_para_embeder(s, cfg)

    def test_distingue_todo_silenciado(self):
        s = _senales(Veredicto.MALICIOSO, cooldown=True)
        assert "silenciado" in razon_para_embeder(s, _cfg(notificar=[]))
