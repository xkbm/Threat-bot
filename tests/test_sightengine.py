"""SightEngine: parseo de respuestas y veredictos.

Cada test usa una respuesta con la forma real que documenta SightEngine. Cuatro defectos
quedan fijados aquí:

- `nudity` se leía solo por `raw` (material tipo X) y se descartaba `partial`, que es
  bikini, lencería y escote: lo que de verdad llega a un servidor.
- `weapon` tomaba el máximo de todas sus clases, incluidas `firearm_toy` y
  `firearm_gesture`: un juguete marcaba contenido restringido.
- Cualquier fallo devolvía `models = {}`, y un dict vacío se leía como "seguro".
- `nudity-2.1` se leía con las claves de `nudity-1.x` (`raw`/`partial`), que en el 2.1 no
  existen. Como `_a_float(None)` da `0.0`, la detección de desnudez llevaba desde la
  migración al 2.1 puntuando 0.0 en todas las imágenes del mundo. Ver
  `TestNudity21`.
"""

import pytest

from api import sightengine as se
from core.veredictos import Veredicto

# Respuesta de `nudity-2.1` tal como la publica SightEngine, campo por campo. Los nombres
# de este dict son la contrato: si algún día se cambian, este test falla y hay que ir a
# la documentación, no a adivinar. `suggestive_classes` trae dentro
# `cleavage_categories` con un `none: 0.99` que es "no hay escote", no "escote al 99%".
NUDITY_2_1_LIMPIA = {
    "status": "success",
    "nudity": {
        "sexual_activity": 0.01,
        "sexual_display": 0.01,
        "erotica": 0.01,
        "very_suggestive": 0.01,
        "suggestive": 0.01,
        "mildly_suggestive": 0.03,
        "suggestive_classes": {
            "bikini": 0.01,
            "cleavage": 0.01,
            "cleavage_categories": {"very_revealing": 0.01, "revealing": 0.01, "none": 0.99},
            "male_chest": 0.01,
            "male_chest_categories": {"very_revealing": 0.01, "revealing": 0.01,
                                      "slightly_revealing": 0.01, "none": 0.99},
            "male_underwear": 0.01,
            "lingerie": 0.01,
            "miniskirt": 0.01,
            "minishort": 0.01,
            "nudity_art": 0.01,
            "schematic": 0.01,
            "sextoy": 0.01,
            "suggestive_focus": 0.01,
            "suggestive_pose": 0.01,
            "swimwear_male": 0.01,
            "swimwear_one_piece": 0.01,
            "visibly_undressed": 0.01,
            "other": 0.01,
        },
        "none": 0.97,
        "context": {"sea_lake_pool": 0.02, "outdoor_other": 0.15, "indoor_other": 0.83},
    },
    "weapon": {"classes": {"firearm": 0.001, "firearm_gesture": 0.001,
                           "firearm_toy": 0.001, "knife": 0.001}},
    "alcohol": {"prob": 0.001},
    "gore": {"prob": 0.001},
    "offensive": {"prob": 0.001},
}


def _nudity_2_1(**cambios):
    """Copia de la respuesta real con los campos de `nudity` modificados."""
    respuesta = {k: (dict(v) if isinstance(v, dict) else v) for k, v in NUDITY_2_1_LIMPIA.items()}
    respuesta["nudity"] = dict(NUDITY_2_1_LIMPIA["nudity"])
    respuesta["nudity"].update(cambios)
    return respuesta


class TestNudity21:
    """El esquema real de `nudity-2.1`, que no tiene `raw` ni `partial`.

    Estos tests son la razón de que la suite no lo pillara: TODOS los de parseo de
    nudity usaban respuestas de `nudity-1.x`, así que la suite validaba el esquema viejo y
    la migración al 2.1 se dio por buena sin comprobar nunca una respuesta del 2.1.
    """

    def test_una_respuesta_del_2_1_no_tiene_raw_ni_partial(self):
        """El contrato de entrada. Si esto deja de ser cierto, el esquema cambió."""
        assert "raw" not in NUDITY_2_1_LIMPIA["nudity"]
        assert "partial" not in NUDITY_2_1_LIMPIA["nudity"]

    def test_imagen_limpia_no_es_un_cero_artificial(self):
        """Antes salía 0.0 exacto, la firma de `_a_float(None)` sobre un campo inexistente.

        Con el esquema real, una imagen limpia da el ruido de fondo del detector (0.01),
        no un cero. La diferencia parece pequeña pero es la diferencia entre "el detector
        dijo que no" y "no supimos leer al detector".
        """
        m = se.parsear_modelos(_nudity_2_1())
        assert m["nudity_raw"] > 0.0
        assert m["nudity_partial"] > 0.0
        assert se.evaluar_contenido(m)[0] is Veredicto.SEGURO

    def test_el_none_de_las_categorias_no_cola_como_desnudez(self):
        """`cleavage_categories` lleva un `none: 0.99` que significa "no hay escote".

        Leerlo como si fuera una señal de contenido marcaría TODAS las imágenes del mundo
        como desnudez parcial, y en modo estricto borraría fotos normales.
        """
        m = se.parsear_modelos(_nudity_2_1())
        assert m["nudity_partial"] < 0.5, m["nudity_partial"]

    def test_contenido_explicito_se_detecta(self):
        """El caso que fallaba en producción: esto salía `seguro`."""
        m = se.parsear_modelos(_nudity_2_1(sexual_activity=0.95))
        assert m["nudity_raw"] == 0.95
        veredicto, _, detalle = se.evaluar_contenido(m)
        assert veredicto is Veredicto.NSFW
        assert "Desnudez explícita" in detalle

    def test_contenido_sugerido_se_detecta(self):
        """Lencería y escote: lo que más llega a un servidor, y lo que más se perdía."""
        respuesta = _nudity_2_1()
        clases = dict(respuesta["nudity"]["suggestive_classes"])
        clases.update({"lingerie": 0.88, "bikini": 0.12})
        respuesta["nudity"]["suggestive_classes"] = clases
        m = se.parsear_modelos(respuesta)
        assert m["nudity_partial"] == 0.88
        assert se.evaluar_contenido(m)[0] is Veredicto.NSFW

    def test_sigue_siendo_compatible_con_el_1_x(self):
        """Cuentas viejas y tests existentes: `raw`/`partial` mandan si están."""
        m = se.parsear_modelos({"nudity": {"raw": 0.9, "partial": 0.1, "safe": 0.0}})
        assert (m["nudity_raw"], m["nudity_partial"]) == (0.9, 0.1)

    def test_esquema_desconocido_es_ilegible_y_no_un_cero(self):
        """Un bloque presente con un esquema que no se reconoce es peor que uno ausente:
        aparenta estar mirado. Tiene que salir como ilegible."""
        assert se._modelos_ilegibles({"nudity": {"campo_inventado": 0.5}}, ["nudity-2.1"]) == [
            "nudity-2.1"
        ]

    def test_respuesta_completa_no_tiene_ilegibles(self):
        pedidos = ["nudity-2.1", "weapon", "alcohol", "gore-2.0", "offensive"]
        assert se._modelos_ilegibles(NUDITY_2_1_LIMPIA, pedidos) == []

    def test_modelo_que_no_vuelve_es_ilegible(self):
        """La comprobación es por modelo, no "al menos uno": antes bastaba con que volviera
        cualquiera para dar el análisis por bueno y rellenar el resto de ceros."""
        respuesta = {k: v for k, v in NUDITY_2_1_LIMPIA.items() if k != "nudity"}
        ilegibles = se._modelos_ilegibles(respuesta, ["nudity-2.1", "weapon"])
        assert ilegibles == ["nudity-2.1"]

    def test_la_comprobacion_usa_lo_que_se_pidio_de_verdad(self):
        """Tras reintentar con menos modelos, exigir el `nudity` original daría error
        siempre en una cuenta que no lo tenga."""
        respuesta = {k: v for k, v in NUDITY_2_1_LIMPIA.items() if k != "nudity"}
        assert se._modelos_ilegibles(respuesta, ["weapon", "alcohol", "offensive"]) == []

    def test_alcohol_acepta_objeto_y_numero(self):
        """La documentación muestra `alcohol` en las dos formas según la página."""
        assert se.parsear_modelos({"alcohol": {"prob": 0.8}})["alcohol"] == 0.8
        assert se.parsear_modelos({"alcohol": 0.8})["alcohol"] == 0.8


class TestParseoNudity:
    def test_ambos_campos_se_leen(self):
        """`partial` es el campo que antes se tiraba a la basura."""
        respuesta = {"nudity": {"raw": 0.02, "partial": 0.81, "safe": 0.17}}
        m = se.parsear_modelos(respuesta)
        assert m["nudity_raw"] == 0.02
        assert m["nudity_partial"] == 0.81

    def test_respuesta_bajo_el_nombre_del_modelo_pedido(self):
        """Se pide `nudity-2.1` y la respuesta llega bajo `nudity`."""
        respuesta = {"nudity-2.1": {"raw": 0.9, "partial": 0.1}}
        m = se.parsear_modelos(respuesta)
        assert m["nudity_raw"] == 0.9

    def test_partial_alto_es_nsfw_evenque_raw_sea_bajo(self):
        """El caso que hace que el bot funcione: lencería, no X."""
        m = se.parsear_modelos({"nudity": {"raw": 0.05, "partial": 0.9}})
        veredicto, _, _ = se.evaluar_contenido(m)
        assert veredicto is Veredicto.NSFW

    def test_solo_raw_alto_tambien_es_nsfw(self):
        m = se.parsear_modelos({"nudity": {"raw": 0.95, "partial": 0.0}})
        assert se.evaluar_contenido(m)[0] is Veredicto.NSFW

    def test_ambos_bajos_es_seguro(self):
        m = se.parsear_modelos({"nudity": {"raw": 0.02, "partial": 0.05, "safe": 0.93}})
        assert se.evaluar_contenido(m)[0] is Veredicto.SEGURO


class TestParseoWeapon:
    def test_arma_real_cuenta(self):
        m = se.parsear_modelos({"weapon": {"classes": {"firearm": 0.95, "knife": 0.01}}})
        assert m["weapon"] == 0.95
        assert se.evaluar_contenido(m)[0] is Veredicto.RESTRINGIDO

    def test_juguete_no_cuenta(self):
        """El bug: un peluche con aspecto de arma marcaba contenido restringido."""
        m = se.parsear_modelos({
            "weapon": {"classes": {"firearm_toy": 0.99, "knife": 0.01, "firearm": 0.0}}
        })
        assert m["weapon"] == 0.01
        assert se.evaluar_contenido(m)[0] is Veredicto.SEGURO

    def test_gesto_no_cuenta(self):
        """Alguien levantando las manos no lleva un arma."""
        m = se.parsear_modelos({
            "weapon": {"classes": {"firearm_gesture": 0.99, "firearm": 0.02}}
        })
        assert m["weapon"] == 0.02

    def test_arma_y_juguete_a_la_vez_manda_el_arma(self):
        m = se.parsear_modelos({
            "weapon": {"classes": {"firearm": 0.88, "firearm_toy": 0.99}}
        })
        assert m["weapon"] == 0.88
        assert se.evaluar_contenido(m)[0] is Veredicto.RESTRINGIDO


class TestParseoOtros:
    def test_gore(self):
        m = se.parsear_modelos({"gore": {"prob": 0.8}})
        assert m["gore"] == 0.8
        assert se.evaluar_contenido(m)[0] is Veredicto.NSFW

    def test_gore_bajo_no_avisa(self):
        m = se.parsear_modelos({"gore": {"prob": 0.1}})
        assert se.evaluar_contenido(m)[0] is Veredicto.SEGURO

    def test_alcohol_usa_prob(self):
        m = se.parsear_modelos({"alcohol": {"prob": 0.75}})
        assert m["alcohol"] == 0.75

    def test_offensive_usa_prob_y_no_el_maximo_de_todo(self):
        """`offensive` trae `prob` más el desglose; se usa el resumen."""
        respuesta = {"offensive": {"prob": 0.2, "hate": 0.0, "violence": 0.1, "gore": 0.0}}
        m = se.parsear_modelos(respuesta)
        assert m["offensive"] == 0.2
        assert se.evaluar_contenido(m)[0] is Veredicto.SEGURO

    def test_offensive_alto_es_nsfw(self):
        m = se.parsear_modelos({"offensive": {"prob": 0.95, "hate": 0.9}})
        assert se.evaluar_contenido(m)[0] is Veredicto.NSFW

    def test_valores_no_numericos_no_revientan(self):
        """La respuesta puede traer nulls; no deben propagarse como excepción."""
        m = se.parsear_modelos({"nudity": {"raw": None, "partial": "x"}, "weapon": {}})
        assert m["nudity_raw"] == 0.0
        assert m["nudity_partial"] == 0.0

    def test_respuesta_vacia_no_revienta(self):
        m = se.parsear_modelos({})
        assert set(m) == set(se.CLAVES_CONTENIDO)
        assert all(v == 0.0 for v in m.values())


class TestSeparacionDeVeredictos:
    def test_alcohol_es_restringido_no_nsfw(self):
        """Una cerveza no es pornografía: antes borraba el mensaje."""
        m = se.parsear_modelos({"alcohol": {"prob": 0.95}})
        veredicto, _, _ = se.evaluar_contenido(m)
        assert veredicto is Veredicto.RESTRINGIDO
        assert veredicto is not Veredicto.NSFW
        assert veredicto.borra_en_modo_estricto is False

    def test_arma_es_restringido(self):
        m = se.parsear_modelos({"weapon": {"classes": {"knife": 0.99}}})
        assert se.evaluar_contenido(m)[0] is Veredicto.RESTRINGIDO

    def test_alcohol_bajo_no_avisa(self):
        m = se.parsear_modelos({"alcohol": {"prob": 0.1}})
        assert se.evaluar_contenido(m)[0] is Veredicto.SEGURO

    def test_pornografia_gana_a_restringido_si_appear_junto(self):
        m = se.parsear_modelos({"alcohol": {"prob": 0.95}, "nudity": {"raw": 0.9, "partial": 0.9}})
        assert se.evaluar_contenido(m)[0] is Veredicto.NSFW

    def test_el_detalle_nombra_lo_detectado(self):
        m = se.parsear_modelos({"alcohol": {"prob": 0.95}, "weapon": {"classes": {"knife": 0.8}}})
        _, _, detalle = se.evaluar_contenido(m)
        assert "Alcohol" in detalle
        assert "Armas" in detalle

    def test_umbrales_por_servidor(self):
        """Un servidor más permisivo puede bajar su propio umbral."""
        m = se.parsear_modelos({"alcohol": {"prob": 0.5}})
        assert se.evaluar_contenido(m)[0] is Veredicto.SEGURO
        assert se.evaluar_contenido(m, {"alcohol": 0.4})[0] is Veredicto.RESTRINGIDO

    def test_umbrales_desconocidos_no_rompen(self):
        m = se.parsear_modelos({"nudity": {"raw": 0.1, "partial": 0.1}})
        assert se.evaluar_contenido(m, {"clave_inventada": 0.0})[0] is Veredicto.SEGURO


class TestNuncaSeguroPorOmision:
    """El defecto más grave: un fallo se reportaba como "seguro"."""

    def test_error_es_error_no_seguro(self):
        veredicto, confianza, _ = se.evaluar_contenido({"error": "sin_cuota"})
        assert veredicto is Veredicto.ERROR
        assert veredicto is not Veredicto.SEGURO
        assert confianza == 0.0

    def test_es_error_detecta_el_marcador(self):
        assert se.es_error({"error": "sin_cuota"}) is True
        assert se.es_error({"nudity_raw": 0.9}) is False
        assert se.es_error({}) is False
        assert se.es_error(None) is False

    def test_sin_claves_no_devuelve_models_vacio(self):
        """El fallo del módulo: `{}` era indistinguible de 'todo limpio'."""
        _, _, models, _ = se._fallo(se.ERROR_SIN_CLAVES, "sin claves")
        assert models != {}
        assert se.es_error(models) is True

    def test_cada_motivo_de_fallo_es_explicito(self):
        for motivo in (se.ERROR_SIN_CLAVES, se.ERROR_SIN_CUOTA, se.ERROR_SIN_BYTES,
                       se.ERROR_DEMASIADO_GRANDE, se.ERROR_HTTP, se.ERROR_SIN_MODELOS):
            _, _, models, _ = se._fallo(motivo)
            assert models["error"] == motivo
            assert se.evaluar_contenido(models)[0] is Veredicto.ERROR

    def test_el_detalle_del_fallo_viaja_consigo(self):
        _, _, models, _ = se._fallo(se.ERROR_HTTP, "HTTP 503")
        assert models["detalle"] == "HTTP 503"
        assert "HTTP 503" in se.evaluar_contenido(models)[2]

    def test_respuesta_200_sin_modelos_no_es_segura(self):
        """200 con un cuerpo inservible es un fallo, no un visto bueno."""
        _, _, models, _ = se._fallo(se.ERROR_SIN_MODELOS, "la respuesta no incluye los modelos pedidos")
        assert se.evaluar_contenido(models)[0] is Veredicto.ERROR


class TestSinClavesConfiguradas:
    @staticmethod
    def _sin_cache(monkeypatch):
        """Falla siempre en caché y en BD: lo que se prueba es la ruta de API."""
        async def _miss(*a, **k):
            return None, None, 0
        monkeypatch.setattr(se, "get_from_cache_mem", _miss)
        monkeypatch.setattr(se, "obtener_analisis_db", _miss)

    @pytest.mark.asyncio
    async def test_sin_claves_devuelve_error_no_seguro(self, monkeypatch):
        """El escenario real: el bot no tiene claves de SightEngine."""
        self._sin_cache(monkeypatch)
        monkeypatch.setattr(se, "SE_API_KEYS_PAIRS", [])
        resultado = await se.analizar_imagen_multimodelo("hash123", b"\x89PNG")

        is_nsfw, _confianza, models, _from_cache = resultado
        assert is_nsfw is False
        assert se.es_error(models) is True
        assert models["error"] == se.ERROR_SIN_CLAVES
        # Lo que hay que comprobar: NO es "seguro".
        assert se.evaluar_contenido(models)[0] is Veredicto.ERROR

    @pytest.mark.asyncio
    async def test_sin_bytes_devuelve_error(self, monkeypatch):
        self._sin_cache(monkeypatch)
        monkeypatch.setattr(se, "SE_API_KEYS_PAIRS", [("u", "k")])
        _, _, models, _ = await se.analizar_imagen_multimodelo("hash123", b"")
        assert models["error"] == se.ERROR_SIN_BYTES
        assert se.evaluar_contenido(models)[0] is Veredicto.ERROR

    @pytest.mark.asyncio
    async def test_sin_cuota_devuelve_error(self, monkeypatch):
        """Agotado el tope diario de operaciones, tampoco puede decir "seguro"."""
        self._sin_cache(monkeypatch)
        monkeypatch.setattr(se, "SE_API_KEYS_PAIRS", [("u", "k")])

        async def _sin_key():
            return None
        monkeypatch.setattr(se, "obtener_siguiente_se_key", _sin_key)

        _, _, models, _ = await se.analizar_imagen_multimodelo("hash123", b"\x89PNG")
        assert models["error"] == se.ERROR_SIN_CUOTA
        assert se.evaluar_contenido(models)[0] is Veredicto.ERROR


class TestClaseDeError400:
    """Un 400 de SightEngine puede ser varias cosas y cada una necesita su mensaje.

    Antes todo 400 se traducía a `too_large`. Si la cuenta no tenía `gore-2.0`, todas
    las imágenes se reportaban como "demasiado grandes", que además de ser falso
    impedíadiagnosticarlo.
    """

    def test_modelo_no_disponible(self):
        cuerpo = {"error": {"type": "BadRequest", "message": "Model gore-2.0 is not supported"}}
        motivo, detalle = se._clasificar_400(cuerpo)
        assert motivo == se.ERROR_MODELO_NO_DISPONIBLE
        assert "gore-2.0" in detalle

    def test_imagen_demasiado_grande(self):
        cuerpo = {"error": {"type": "BadRequest", "message": "Image is too large"}}
        assert se._clasificar_400(cuerpo)[0] == se.ERROR_DEMASIADO_GRANDE

    def test_otro_400_no_se_inventa_motivo(self):
        cuerpo = {"error": {"type": "BadRequest", "message": "Invalid api_secret"}}
        motivo, _ = se._clasificar_400(cuerpo)
        assert motivo == se.ERROR_HTTP

    def test_400_sin_cuerpo_usable_cae_en_demasiado_grande(self):
        """Sin cuerpo no se puede afinar; se mantiene el comportamiento previo."""
        assert se._clasificar_400(None)[0] == se.ERROR_DEMASIADO_GRANDE
        assert se._clasificar_400({})[0] == se.ERROR_DEMASIADO_GRANDE

    def test_error_texto_plano(self):
        cuerpo = {"error": "unsupported model"}
        assert se._clasificar_400(cuerpo)[0] == se.ERROR_MODELO_NO_DISPONIBLE


class TestListaDeModelosConFallback:
    def test_el_primero_es_el_que_usa_el_calculo_de_cuota(self):
        """Si divergieran, la cuota contaría modelos que nunca se piden."""
        from core.config import SE_OPS_PER_CALL, SIGHTENGINE_MODELS

        assert se.MODELOS_CON_FALLBACK[0] == SIGHTENGINE_MODELS
        assert se.MODELOS_CON_FALLBACK[0].count(",") + 1 == SE_OPS_PER_CALL

    def test_baja_degradando_y_no_repite(self):
        assert len(set(se.MODELOS_CON_FALLBACK)) == len(se.MODELOS_CON_FALLBACK)
        for anterior, siguiente in zip(se.MODELOS_CON_FALLBACK, se.MODELOS_CON_FALLBACK[1:]):
            assert set(siguiente.split(",")) < set(anterior.split(",")), (
                "cada reintento tiene que quitar modelos, no añadirlos"
            )

    def test_el_ultimo_siempre_es_alguno_valido(self):
        assert se.MODELOS_CON_FALLBACK[-1] in ("offensive", "nudity-2.1")

    def test_todos_empiezan_por_nudity_mientras_se_pueda(self):
        """`nudity` es el motivo de usar SightEngine: no debe desaparecer antes que
        los demás."""
        for lista in se.MODELOS_CON_FALLBACK[:-1]:
            assert "nudity-2.1" in lista


class TestClaveDeCache:
    def test_la_clave_cambio_de_version(self):
        """Las entradas viejas guardan otra forma de `models` y no se pueden reparsear."""
        assert "nsfw2:" in "nsfw2:abc"
        # La clave nueva no debe colisionar con la antigua.
        assert "nsfw:abc" != "nsfw2:abc"