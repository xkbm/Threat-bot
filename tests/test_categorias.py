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


class TestNingunControlDelPanelEstaMuerto:
    """Guarda que evita lo que pasó: el panel ofrecía "Acción ante malware",
    "Acción ante suplantación" y "Acción ante restringido", se podían cambiar, y **nadie
    los leía**. Tres controles que no hacen nada son peores que no tenerlos: el admin
    cree que ha configurado algo.

    Cualquier clave del esquema tiene que leerse en algún sitio del código que no sea el
    propio esquema ni los tests.
    """

    def _consumidores(self, clave: str) -> list[str]:
        """Dónde se leen de verdad.

        Cuenta como consumo cualquier aparición FUERA del bloque `ESQUEMA`, también
        dentro de `config_schema.py`: los umbrales se leen en `aplicar_config`, que traduce
        `umbral_partial` a la clave que espera SightEngine. Eso es uso, no declaración,
        aunque esté en el mismo fichero.
        """
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        propio = (raiz / "core" / "config_schema.py").read_text(encoding="utf-8")
        i = propio.index("ESQUEMA: tuple[Clave, ...] = (")
        j = propio.index("\n)\n", i)
        sin_declarar = propio[:i] + propio[j:]

        found = []
        if f'"{clave}"' in sin_declarar:
            found.append("core/config_schema.py")
        for sub in ("core", "ui", "cogs", "api"):
            for f in (raiz / sub).glob("*.py"):
                if f.name == "config_schema.py":
                    continue
                if f'"{clave}"' in f.read_text(encoding="utf-8"):
                    found.append(f"{sub}/{f.name}")
        return found

    def test_toda_clave_del_esquema_se_lee_en_alguna_pista(self):
        huerfanas = [
            c.nombre for c in esq.ESQUEMA
            if not self._consumidores(c.nombre)
        ]
        assert not huerfanas, (
            f"claves del panel que nadie lee: {huerfanas}. "
            f"O se conectan a algo, o se quitan del panel."
        )

    def test_las_acciones_por_categoria_no_vuelven(self):
        """Se quitaron porque no hacían nada. La moderación la lleva el modo estricto y
        los botones del log de amenazas, no un dial por categoría."""
        for clave in ("accion_restringido", "accion_phishing", "accion_malicious"):
            assert clave not in esq.POR_NOMBRE, f"vuelve el control muerto '{clave}'"


class TestLaRedaccionSeEntiende:
    """El usuario dijo que el panel no se entendía. Los textos son la interfaz."""

    def test_cada_seccion_explica_para_que_sirve(self):
        for seccion in esq.secciones():
            texto = esq.DESCRIPCION_SECCION[seccion]
            assert texto and texto.endswith((".", "…")), seccion
            # Que responda a "qué hago aquí", no a "qué hay aquí".
            assert any(p in texto.lower() for p in ("qué", "dónde", "para")), texto

    def test_ninguna_etiqueta_usa_el_nombre_interno_de_la_clave(self):
        for clave in esq.ESQUEMA:
            bruto = clave.nombre.replace("_", " ").lower()
            assert not clave.etiqueta.lower().startswith(bruto), clave.nombre

    def test_las_ayudas_no_empiezan_por_mayuscula_tras_coma(self):
        """Error tipográfico real: "no se avisa de nada, Botón de emergencia"."""
        import re

        for clave in esq.ESQUEMA:
            ayuda = clave.ayuda
            assert re.search(r",\s[A-ZÁÉÍÓÚÑ][a-záéíóúñ]", ayuda) is None, (
                f"{clave.nombre}: mayúscula tras coma en {ayuda!r}"
            )

    def test_todo_umbral_explica_para_que_sirve(self):
        """Cuatro de los seis no tenían ninguna explicación."""
        for clave in esq.claves_de(esq.CONTENIDO):
            if clave.tipo == "float":
                assert clave.ayuda, f"{clave.nombre} se muestra sin explicación"

    def test_las_etiquetas_caben_en_el_panel(self):
        for clave in esq.ESQUEMA:
            assert len(clave.etiqueta) <= 40, f"{clave.nombre}: {clave.etiqueta!r}"

    def test_la_seccion_de_avisos_no_depende_de_otras(self):
        """La lista de qué avisar estuvo en una sección llamada 'Fallos' que en realidad
        contenía también malware y NSFW. Ahora está con el resto de los avisos."""
        assert "Avisar de" in esq.POR_NOMBRE["notificar"].etiqueta
        assert esq.AVISO == "aviso"
        assert not hasattr(esq, "FALLOS"), "la sección 'Fallos' ya no existe"


class TestCadaSeccionMuestraSoloLoSuyo:
    """Los interruptores de General se repetían en las cinco secciones.

    Renderizado se veía que "Analizar los mensajes" salía en Contenido, en Moderación y
    en Exclusiones, donde no tiene nada que ver. Cuatro copias del mismo interruptor
    confunden en vez de ayudar, y era parte de lo que hacía el panel ilegible.
    """

    @staticmethod
    async def _seccion(nombre, monkeypatch):
        import types

        import core.config as cfg
        import core.guild_config as gc
        import core.state as state
        from ui import panel as pan

        emojis = {n: getattr(cfg, n) for n in dir(cfg) if n.startswith("EMOJI_")}
        state.bot = types.SimpleNamespace(
            **emojis, guilds_data={}, vt_key_total_requests={}, vt_key_daily_usage={},
            se_key_total_requests={}, se_key_daily_usage={}, user_scan_history={},
            antispam_scan={}, vt_key_usage={}, se_key_usage={}, vt_user_requests={},
        )

        async def _nada(*a, **k):
            return None

        async def _obtener(_gid):
            return dict(esq.defaults())

        # `monkeypatch` y no asignación directa: esta última se queda puesta al terminar
        # el test y rompe los ficheros que se ejecutan después.
        monkeypatch.setattr(state, "bot", state.bot)
        monkeypatch.setattr(state.bot, "guardar_datos", _nada, raising=False)
        monkeypatch.setattr(gc, "obtener_config_guild", _obtener)
        monkeypatch.setattr(pan, "obtener_config_guild", _obtener)
        monkeypatch.setattr(gc, "actualizar_config", lambda *a, **k: None)
        monkeypatch.setattr(pan, "actualizar_config", lambda *a, **k: None)

        class _Perm:
            send_messages = True

        class _Canal:
            def __init__(self, i, n):
                self.id, self.name, self.topic = i, n, ""

            def permissions_for(self, _m):
                return _Perm()

        guild = types.SimpleNamespace(
            id=1, text_channels=[_Canal(1, "general"), _Canal(2, "registros")],
            me=object(), get_channel=lambda c: None,
        )
        return await pan.PanelConfig.crear(nombre, guild)

    @pytest.mark.parametrize("seccion", [s for s in esq.secciones()])
    @pytest.mark.asyncio
    async def test_solo_aparecen_los_botones_de_esa_seccion(self, seccion, monkeypatch):
        vista = await self._seccion(seccion, monkeypatch)
        etiquetas = {getattr(h, "label", "").split(" \u00b7")[0].strip()
                     for h in vista.children if getattr(h, "label", None)}
        esperados = {c.etiqueta for c in esq.claves_de(seccion) if c.tipo == "bool"}
        for ajena in ("Analizar los mensajes", "Avisar en el canal de registro",
                      "Borrar los mensajes peligrosos", "No avisar de nada"):
            if ajena not in esperados:
                assert ajena not in etiquetas, (
                    f"'{ajena}' aparece en la sección '{seccion}' y no le toca"
                )

    @pytest.mark.asyncio
    async def test_cada_seccion_cabe_en_las_cinco_filas(self, monkeypatch):
        from ui import panel as pan

        for seccion in esq.secciones():
            vista = await self._seccion(seccion, monkeypatch)
            filas, ocupada = 1, 0
            for hijo in vista.children:
                ancho = getattr(hijo, "width", 5)
                if ocupada + ancho > 5:
                    filas, ocupada = filas + 1, 0
                ocupada += ancho
            assert filas <= pan.MAX_FILAS, f"{seccion} necesita {filas} filas"
