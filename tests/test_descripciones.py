"""Las descripciones del embed y del panel.

Tres defectos que este archivo fija:

1. `/settings` metía los mismos ajustes en la descripción **y** en los campos, así que
   cada línea salía dos veces en el mismo embed.
2. El embed del análisis reinterpretaba las tuplas con su propia lógica. Una imagen con
   alcohol salía con el título "Todos los elementos son seguros" en verde, el contador
   "Seguros: 1", el icono de error en su línea y la reacción de bandera: cuatro cosas
   distintas para el mismo elemento, porque ninguna compartía la tabla de veredictos.
3. Los detalles de SightEngine leían `models['nudity']`, clave que ya no existe, así que
   el embed siempre decía "contenido inapropiado" sin nombrar qué se había detectado.
"""

import re
import types

import discord
import pytest

from core.senales import Elemento, Senales, desde_tuplas
from core.veredictos import ORDEN_CONTADORES, PRECEDENCIA, Veredicto
from ui import embed as emb
from ui import panel as pan
from ui.message_handler import _construir_embed_unificado, _motivo_de_error, _resumen_breve


class _Msg:
    class _Autor:
        mention = "<@Autor>"

    author = _Autor()


def _senales(*elementos, **flags) -> Senales:
    s = Senales()
    for e in elementos:
        s.anadir(e)
    s.omitidos = flags.get("omitidos", 0)
    s.cooldown = flags.get("cooldown", False)
    s.whitelist_omitidos = flags.get("whitelist_omitidos", 0)
    return s


def _img(nombre, veredicto, **kw):
    return Elemento(nombre=nombre, tipo="image", veredicto=veredicto, **kw)


async def _construir(senales):
    return await _construir_embed_unificado(_Msg(), senales)


class TestContadoresCuadran:
    @pytest.mark.asyncio
    async def test_restringido_no_cuenta_como_seguro(self):
        """El bug: una foto con alcohol salía como "Seguros: 1"."""
        e = await _construir(_senales(_img("cerveza.png", Veredicto.RESTRINGIDO)))
        assert "Seguros: **0**" in e.description
        assert "Restringidos: **1**" in e.description

    @pytest.mark.asyncio
    async def test_phishing_no_cuenta_como_seguro(self):
        e = await _construir(_senales(Elemento(
            nombre="rnicrosoft.com", tipo="url", veredicto=Veredicto.PHISHING)))
        assert "Seguros: **0**" in e.description
        assert "Suplantaciones: **1**" in e.description

    @pytest.mark.asyncio
    async def test_la_suma_de_contadores_es_el_total(self):
        e = await _construir(_senales(
            _img("a.png", Veredicto.SEGURO),
            _img("b.png", Veredicto.RESTRINGIDO),
            _img("c.png", Veredicto.NSFW),
            Elemento(nombre="d", tipo="url", veredicto=Veredicto.MALICIOSO, mal=3),
            Elemento(nombre="e", tipo="file", veredicto=Veredicto.ERROR),
            Elemento(nombre="f", tipo="url", veredicto=Veredicto.SOSPECHOSO),
        ))
        numeros = [int(n) for n in re.findall(
            r"(?:Seguros|Sospechosos|Restringidos|Suplantaciones|NSFW|Maliciosos|Errores)"
            r": \*\*(\d+)\*\*", e.description)]
        assert sum(numeros) == 6, e.description

    def test_orden_contadores_cubre_todos_los_veredictos(self):
        """Si falta un veredicto en la tupla, su contador desaparece y no cuadra."""
        assert set(ORDEN_CONTADORES) == set(PRECEDENCIA)

    @pytest.mark.asyncio
    async def test_seguros_siempre_visible_a_cero(self):
        e = await _construir(_senales(_img("x.png", Veredicto.NSFW)))
        assert "Seguros: **0**" in e.description

    @pytest.mark.asyncio
    async def test_el_orden_es_fijo(self):
        e = await _construir(_senales(
            _img("a.png", Veredicto.NSFW),
            Elemento(nombre="b", tipo="url", veredicto=Veredicto.MALICIOSO),
            _img("c.png", Veredicto.RESTRINGIDO),
        ))
        esperados = [v.contador for v in ORDEN_CONTADORES if v.contador in e.description]
        assert esperados == ["Seguros", "Restringidos", "NSFW", "Maliciosos"]


class TestTituloYColor:
    @pytest.mark.asyncio
    async def test_restringido_no_dice_todo_seguro(self):
        """El bug más grave: título verde de "todo seguro" con una foto con alcohol."""
        e = await _construir(_senales(_img("cerveza.png", Veredicto.RESTRINGIDO)))
        assert "Todos los elementos son seguros" not in e.title
        assert "restringido" in e.title.lower()
        assert e.color == discord.Color(emb.COLOR_SOSPECHOSO)

    @pytest.mark.asyncio
    async def test_phishing_no_dice_todo_seguro(self):
        e = await _construir(_senales(Elemento(
            nombre="steamcommunnity.ru", tipo="url", veredicto=Veredicto.PHISHING)))
        assert "Todos los elementos son seguros" not in e.title
        assert e.color == discord.Color(emb.COLOR_SOSPECHOSO)

    @pytest.mark.asyncio
    async def test_limpio_si_dice_todo_seguro(self):
        e = await _construir(_senales(_img("bonita.png", Veredicto.SEGURO)))
        assert "Todos los elementos son seguros" in e.title
        assert e.color == discord.Color(emb.COLOR_SEGURO)

    @pytest.mark.asyncio
    async def test_error_no_dice_todo_seguro(self):
        e = await _construir(_senales(
            Elemento(nombre="x", tipo="file", veredicto=Veredicto.ERROR)))
        assert "Todos los elementos son seguros" not in e.title
        assert e.color == discord.Color(emb.COLOR_ERROR)

    @pytest.mark.asyncio
    async def test_manda_el_peor_veredicto(self):
        e = await _construir(_senales(
            _img("a.png", Veredicto.SEGURO),
            Elemento(nombre="b", tipo="url", veredicto=Veredicto.MALICIOSO)))
        assert "Amenazas detectadas" in e.title

    @pytest.mark.asyncio
    async def test_el_sospechoso_manda_al_error(self):
        """Un hallazgo accionable no se tapa porque otro elemento fallara."""
        e = await _construir(_senales(
            Elemento(nombre="a", tipo="url", veredicto=Veredicto.SOSPECHOSO),
            Elemento(nombre="b", tipo="url", veredicto=Veredicto.ERROR)))
        assert "Elementos sospechosos" in e.title
        assert e.color == discord.Color(emb.COLOR_SOSPECHOSO)
        assert "Errores: **1**" in e.description


class TestCoherenciaInterna:
    @pytest.mark.asyncio
    async def test_el_icono_de_la_linea_es_el_del_veredicto(self):
        """Antes caía en el fallback de ERROR y ponía el icono de error en un elemento
        que el título llamaba seguro."""
        from core import config

        e = await _construir(_senales(_img("cerveza.png", Veredicto.RESTRINGIDO)))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert linea.value.startswith(config.EMOJI_RESTRINGIDO)
        assert config.EMOJI_ERROR not in linea.value

    @pytest.mark.asyncio
    async def test_una_imagen_no_comprobada_en_vt_lo_dice(self):
        from core import config

        e = await _construir(_senales(
            _img("x.png", Veredicto.SEGURO, modelos={"vt_omitido": True})))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert config.EMOJI_REPLY in linea.value
        assert "Sin comprobar en VirusTotal" in linea.value


class TestDetallesDeSightEngine:
    @pytest.mark.asyncio
    async def test_nombra_lo_detectado(self):
        """El bug: leía `models['nudity']`, que ya no existe, y nunca nombraba nada."""
        e = await _construir(_senales(
            _img("x.png", Veredicto.RESTRINGIDO, detalle_contenido="Alcohol 95%")))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert "Alcohol 95%" in linea.value

    @pytest.mark.asyncio
    async def test_sin_detalle_usa_el_titulo_del_veredicto(self):
        e = await _construir(_senales(_img("x.png", Veredicto.NSFW)))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert Veredicto.NSFW.titulo in linea.value

    @pytest.mark.asyncio
    async def test_el_detalle_viene_del_models_al_bridge(self):
        tuplas = [("x.png", "restringido", {"detalle": "Alcohol 80%", "alcohol": 0.8}, "hash")]
        senales = desde_tuplas(img_results=tuplas)
        assert senales.elementos[0].detalle_contenido == "Alcohol 80%"
        assert senales.elementos[0].veredicto is Veredicto.RESTRINGIDO


class TestMotivosDeError:
    def test_cada_motivo_tiene_su_texto(self):
        casos = {
            "too_large": "demasiado grande",
            "sin_claves": "no configurado",
            "sin_cuota": "cuota",
            "modelo_no_disponible": "modelos no disponibles",
        }
        for motivo, esperado in casos.items():
            assert esperado in _motivo_de_error({"error": motivo}), motivo

    def test_error_desconocido_no_inventa_texto(self):
        assert "inventado" in _motivo_de_error({"error": "motivo_inventado"})

    def test_sin_modelos_no_dice_seguro(self):
        assert "seguro" not in _motivo_de_error({})


class TestDatosAdicionales:
    @pytest.mark.asyncio
    async def test_whitelist_en_el_embed(self):
        e = await _construir(_senales(_img("a.png", Veredicto.SEGURO), whitelist_omitidos=2))
        assert "whitelist" in e.description.lower()

    @pytest.mark.asyncio
    async def test_omitidos_reportados(self):
        e = await _construir(_senales(_img("a.png", Veredicto.SEGURO), omitidos=3))
        assert "omitido" in e.description.lower()

    @pytest.mark.asyncio
    async def test_cooldown_reportado(self):
        e = await _construir(_senales(_img("a.png", Veredicto.SEGURO), cooldown=True))
        assert "límite de análisis" in e.description.lower()

    @pytest.mark.asyncio
    async def test_redireccion_aparece(self):
        from ui.message_handler import UrlResult

        tuplas = [UrlResult("http://corto.io/x", "seguro", 0, None, "u1", False,
                            redireccion="https://destino.example/p")]
        e = await _construir(desde_tuplas(tuple(tuplas)))
        assert any("Redirecci" in f.name for f in e.fields)
        assert any("destino.example" in f.value for f in e.fields)

    @pytest.mark.asyncio
    async def test_lista_vacia_no_revienta(self):
        assert await _construir(Senales()) is not None


class TestTitulosYContadoresSonDistintos:
    def test_titulo_es_frase_y_contador_es_sustantivo(self):
        """Con un único campo, los contadores salían como frases largas."""
        for v in Veredicto:
            assert v.contador and v.contador != v.titulo, v
            assert len(v.contador) < 20, v

    def test_todos_los_veredictos_tienen_las_dos_etiquetas(self):
        for v in Veredicto:
            assert v.titulo and v.contador and v.emoji


class TestElLookupDeImagenNoEsConfigurable:
    """Un request de VT por imagen es cuota de quien mantiene el bot.

    Dejar que el administrador de un servidor active o desactive el lookup le da
    acceso a tu cuota mensual: activado, cada imagen gasta un request que pagas tú. El
    interruptor se quitó del esquema y ahora la decisión es del código.
    """

    def test_el_interruptor_no_existe(self):
        from core import config_schema as esq

        assert "vt_para_imagenes" not in esq.POR_NOMBRE

    def test_no_hay_seccion_de_cuota(self):
        from core import config_schema as esq

        assert "cuota" not in esq.secciones(), (
            "una sección que ofrece tocar la cuota es exactamente el riesgo"
        )

    def test_los_limites_son_constantes_fijas(self):
        """Nada por servidor puede ampliarlos."""
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "ui" / "message_handler.py").read_text(encoding="utf-8")
        assert "MAX_ADJUNTOS_POR_MENSAJE = 5" in texto
        assert "MAX_URLS_POR_MENSAJE = 5" in texto
        assert 'config.get("max_adjuntos")' not in texto
        assert 'config.get("max_urls")' not in texto

    @pytest.mark.asyncio
    async def test_el_lookup_sigue_funcionando(self):
        """Quitamos el interruptor, no la comprobación."""
        import types as _t

        from ui import message_handler as mh

        llamadas = []

        async def _fake(hash_):
            llamadas.append(hash_)
            return "malicioso", 3, None, None
        mh.reputacion_hash = _fake
        mh.VT_API_KEYS = ["clave"]      # sin esto sale antes: no hay claves

        async def _vacia(*a, **k):
            return None, None, 0
        mh.obtener_analisis_db = _vacia
        mh.guardar_analisis_db = _vacia

        async def _permitido(*a, **k):
            return True
        mh.check_vt_user_limit = _permitido
        mh.registrar_infraccion = _vacia

        bot = _t.SimpleNamespace()
        veredicto, mal, _link, _top = await mh._reputacion_de_imagen(bot, "h", 42, 7)
        assert llamadas == ["h"]
        assert veredicto == "malicioso" and mal == 3


class TestResumenBreve:
    def test_lista_lo_importante(self):
        s = Senales()
        s.anadir(Elemento(nombre="a", tipo="url", veredicto=Veredicto.MALICIOSO))
        s.anadir(Elemento(nombre="b", tipo="image", veredicto=Veredicto.RESTRINGIDO))
        resumen = _resumen_breve(s)
        assert "malicioso" in resumen and "restringido" in resumen

    def test_mensaje_limpio_no_produce_ruido(self):
        s = Senales()
        s.anadir(Elemento(nombre="a", tipo="url", veredicto=Veredicto.SEGURO))
        assert _resumen_breve(s) == ""

    def test_menciona_lo_no_comprobado(self):
        s = Senales()
        s.anadir(Elemento(nombre="a", tipo="file", veredicto=Veredicto.ERROR))
        assert "sin comprobar" in _resumen_breve(s)

    def test_menciona_la_whitelist(self):
        s = Senales()
        s.whitelist_omitidos = 3
        assert "3 en whitelist" in _resumen_breve(s)


class TestPanel:
    """El panel tiene que construirse sin petarse con cualquier configuración."""

    @pytest.fixture(autouse=True)
    def _bot_global(self, monkeypatch):
        import core.guild_config as gc
        import core.state as state
        from ui import panel as pan

        bot = types.SimpleNamespace(
            guilds_data={}, user_scan_history={}, antispam_scan={},
            vt_user_requests={}, vt_key_usage={}, se_key_usage={},
        )
        anterior = state.bot
        state.bot = bot
        self.guardado = {}

        async def _obtener(guild_id):
            return dict(self.config)

        async def _actualizar(guild_id, **campos):
            self.guardado.update(campos)
            self.config.update(campos)
            return self.config

        # `monkeypatch`, no asignación directa: esta última se quedaba puesta después
        # del test y contaminaba los ficheros que se ejecutaban detrás.
        monkeypatch.setattr(gc, "obtener_config_guild", _obtener)
        monkeypatch.setattr(gc, "actualizar_config", _actualizar)
        monkeypatch.setattr(pan, "obtener_config_guild", _obtener)
        monkeypatch.setattr(pan, "actualizar_config", _actualizar)
        yield
        state.bot = anterior

    async def _panel(self, seccion, config=None):
        from core import config_schema as esq

        self.config = dict(config if config is not None else esq.defaults())
        guild = types.SimpleNamespace(id=1, get_channel=lambda cid: None)
        return await pan.PanelConfig.crear(seccion, guild)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seccion", __import__("core.config_schema", fromlist=["x"]).secciones())
    async def test_cada_seccion_se_construye(self, seccion):
        assert len((await self._panel(seccion)).children) > 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seccion", __import__("core.config_schema", fromlist=["x"]).secciones())
    async def test_no_supera_los_limites_de_discord(self, seccion):
        """Discord admite 5 filas de 5. Construirse ya lo garantiza: si no cupiera,
        `discord.ui.View` lanzaría al añadir el último control."""
        vista = await self._panel(seccion)
        assert len(vista.children) <= 25
        filas, ocupada = 1, 0
        for hijo in vista.children:
            ancho = getattr(hijo, "width", 5)
            if ocupada + ancho > 5:
                filas, ocupada = filas + 1, 0
            ocupada += ancho
        assert filas <= pan.MAX_FILAS, f"{seccion} necesita {filas} filas"

    @pytest.mark.asyncio
    async def test_config_incompleta_no_rompe(self):
        """Un `data.json` viejo, con tres claves y nada más."""
        assert len((await self._panel("contenido", {"silent_mode": True})).children) > 0

    @pytest.mark.asyncio
    async def test_el_embed_no_rompe_con_config_incompleta(self):
        panel = await self._panel("contenido", {"silent_mode": True})
        assert (await panel.embed()).fields

    @pytest.mark.asyncio
    async def test_el_boton_muestra_el_estado_real(self):
        panel = await self._panel("moderacion", {"strict_mode": False})
        boton = next(c for c in panel.children
                     if getattr(c, "custom_id", "").endswith("strict_mode"))
        assert "no" in boton.label
        assert boton.style is discord.ButtonStyle.secondary

    @pytest.mark.asyncio
    async def test_las_etiquetas_caben_en_discord(self):
        panel = await self._panel("aviso")
        for hijo in panel.children:
            if isinstance(hijo, discord.ui.Button):
                assert len(hijo.label) <= 80


class TestElEnlaceAlInformeSeMuestra:
    """El enlace a VT se guardaba en `models` pero no se mostraba nunca.

    Consecuencia: el acierto de caché daba menos información que el camino fresco, que
    es justo al revés de lo que sirve una caché. El moderador veía "3 detecciones" sin
    forma de ir al informe a comprobarlo.
    """

    @pytest.mark.asyncio
    async def test_una_imagen_maliciosa_muestra_el_enlace(self):
        e = await _construir(_senales(
            Elemento(nombre="mala.png", tipo="image", veredicto=Veredicto.MALICIOSO, mal=3,
                     modelos={"vt_link": "https://vt/gui/file/abc"}),
        ))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert "vt/gui/file/abc" in linea.value
        assert "3 detecciones" in linea.value

    @pytest.mark.asyncio
    async def test_una_limpia_no_inventa_enlace(self):
        e = await _construir(_senales(
            Elemento(nombre="ok.png", tipo="image", veredicto=Veredicto.SEGURO, mal=0,
                     modelos={}),
        ))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert "vt/gui" not in linea.value

    @pytest.mark.asyncio
    async def test_sin_enlace_por_un_camino_malicioso_seguira_funcionando(self):
        """Que no haya enlace no puede romper la línea."""
        e = await _construir(_senales(
            Elemento(nombre="mala.png", tipo="image", veredicto=Veredicto.MALICIOSO, mal=2,
                     modelos={}),
        ))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert "2 detecciones" in linea.value

    @pytest.mark.asyncio
    async def test_una_no_comprobada_lo_dice_tambien_si_viene_de_cache(self):
        """La regresión: el acierto de caché devolvía "desconocido" y no ponía la marca."""
        e = await _construir(_senales(
            Elemento(nombre="nueva.png", tipo="image", veredicto=Veredicto.SEGURO,
                     modelos={"vt_omitido": True}),
        ))
        linea = next(f for f in e.fields if f.name.endswith("Imágenes (adjuntas)"))
        assert "Sin comprobar en VirusTotal" in linea.value
