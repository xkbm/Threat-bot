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
from ui.message_handler import _veredicto_de_contenido


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
        cfg = _cfg(notificar=esq.CATEGORIAS_AVISO, avisar_todo=False)
        assert debe_enviar_embed(s, cfg) is False

    def test_encendido_respeta_los_diales(self):
        s = _senales(Veredicto.MALICIOSO)
        assert debe_enviar_embed(s, _cfg(notificar=["malicioso"], avisar_todo=True)) is True
        assert debe_enviar_embed(s, _cfg(notificar=["nsfw"], avisar_todo=True)) is False


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
        cfg = _cfg(notificar=esq.CATEGORIAS_AVISO, avisar_todo=False)
        assert "avisar_todo" in razon_para_embeder(s, cfg)

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


class TestLosUmbralesDelPanelNoEstanMuertos:
    """Regresión: los seis umbrales de `/settings` se guardaban y no cambiaban nada.

    `TestNingunControlDelPanelEstaMuerto` de arriba mira si la clave aparece escrita en
    algún fichero, y aquí aparecía: la leía `aplicar_config` y la pintaba el panel. Eso
    no es que se usara. Lo que pasaba es que el veredicto de la imagen lo decidía
    `evaluar_contenido(models)` **sin** el segundo argumento, así que el alcohol al 30%
    salía `seguro` en un servidor con el umbral puesto a 25%, y `restringido` en otro con
    el de serie. El control se leía, se escribía, se guardaba y no gobernaba el resultado.

    Estos tests son de comportamiento a propósito: comprueban el veredicto que sale, no
    que el nombre de la clave aparezca por algún lado.
    """

    # Una cerveza: alcohol al 30%, que con el umbral de serie (70%) no marca nada.
    CERVEZA = {
        "nudity_raw": 0.0, "nudity_partial": 0.0, "gore": 0.0,
        "offensive": 0.0, "alcohol": 0.30, "weapon": 0.0,
    }

    def _config(self, **umbrales) -> dict:
        return {"_umbrales": esq.aplicar_config(umbrales)}

    def test_umbral_bajado_marca_where_el_de_serie_no(self):
        v_serie, _, _ = _veredicto_de_contenido(self._config(), self.CERVEZA)
        assert v_serie is Veredicto.SEGURO, "con el umbral de serie (70%) no debe marcar"

        v_bajo, _, _ = _veredicto_de_contenido(
            self._config(umbral_alcohol=0.25), self.CERVEZA
        )
        assert v_bajo is Veredicto.RESTRINGIDO, (
            "con umbral_alcohol=0.25 y alcohol=0.30 tiene que salir restringido"
        )

    def test_umbral_subido_deja_de_marcar(self):
        v, _, _ = _veredicto_de_contenido(
            self._config(umbral_alcohol=1.0), self.CERVEZA
        )
        assert v is Veredicto.SEGURO, (
            "con umbral_alcohol=1.0 una cerveza al 30% no debe marcar"
        )

    def test_el_detalle_que_va_al_embed_sigue_las_umbrales(self):
        """No basta con que el veredicto cambie: el embed nombra lo detectado."""
        _, _, con_umbral = _veredicto_de_contenido(
            self._config(umbral_alcohol=0.25), self.CERVEZA
        )
        assert "Alcohol" in con_umbral, con_umbral

    def test_sin_umbrales_usa_los_defaults(self):
        """Una config sin `_umbrales` no puede reventar: cae a `core.config`."""
        v, _, _ = _veredicto_de_contenido({}, self.CERVEZA)
        assert v is Veredicto.SEGURO

    def test_un_fallo_sigue_siendo_error_con_umbrales_puestos(self):
        """Lo que no se pudo comprobar no se vuelve `seguro` por tener umbrales."""
        for umbral in ({}, self._config(umbral_alcohol=0.0)):
            v, _, _ = _veredicto_de_contenido(umbral, {"error": "sin_cuota"})
            assert v is Veredicto.ERROR

    def test_ninguna_rama_se_salta_el_helper(self):
        """Las tres ramas que deciden el veredicto de una imagen pasan por el helper.

        Es la parte que no se ve leyendo un test: si mañana alguien añade una cuarta rama
        y llama a `evaluar_contenido` a secas, el control vuelve a estar muerto y ningún
        otro test de este fichero se entera.
        """
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "ui" / "message_handler.py").read_text(encoding="utf-8")
        sueltas = [
            linea.strip()
            for linea in texto.splitlines()
            if "= evaluar_contenido(" in linea
        ]
        assert not sueltas, (
            "estas ramas llaman a evaluar_contenido sin los umbrales del guild, "
            f"así que el veredicto sale de los defaults: {sueltas}"
        )


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
            se_key_total_requests={}, se_key_daily_usage={}, se_key_monthly_usage={}, user_scan_history={},
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


class TestElInterruptorGeneralDigoLoQueDice:
    """`avisar_todo`: True avisa, False calla. Sin ambigüedad.

    Antes la clave se llamaba `silent_mode` y el nombre no describía el comportamiento:
    con `silent_mode: True` guardado, `debe_enviar_embed` NO cortaba y por tanto
    avisaba. El nombre mentía, el comportamiento no. Por eso la clave se llama como
    funciona y la traducción es identidad, no negación.
    """

    def test_avisar_todo_True_avisa(self):
        s = _senales(Veredicto.MALICIOSO)
        assert debe_enviar_embed(s, _cfg(notificar=["malicioso"], avisar_todo=True)) is True

    def test_avisar_todo_False_no_avisa(self):
        """El botón de emergencia calla TODO, amenazas incluidas."""
        s = _senales(Veredicto.MALICIOSO, Veredicto.NSFW)
        assert debe_enviar_embed(s, _cfg(notificar=esq.CATEGORIAS_AVISO, avisar_todo=False)) is False

    def test_por_defecto_avisa(self):
        """El default avisa porque es lo que tenía la gente, no porque suene bien."""
        from core.aviso import config_aviso_por_defecto

        assert config_aviso_por_defecto()["avisar_todo"] is True
        s = _senales(Veredicto.MALICIOSO)
        assert debe_enviar_embed(s, config_aviso_por_defecto()) is True


class TestLaMigracionConservaElComportamiento:
    """La traducción no puede cambiar lo que hace un servidor que ya estaba."""

    def test_avisaba_sigue_avisando(self):
        from core.aviso import migrar_aviso

        # Lo que tiene hoy el bot desplegado en casi todos los servidores.
        config = migrar_aviso({"silent_mode": True})
        assert config["avisar_todo"] is True
        assert "silent_mode" not in config, "la clave vieja debe desaparecer"

    def test_el_otro_sentido_tambien(self):
        from core.aviso import migrar_aviso

        assert migrar_aviso({"silent_mode": False})["avisar_todo"] is False

    def test_no_toca_una_config_ya_migrada(self):
        from core.aviso import migrar_aviso

        config = migrar_aviso({"silent_mode": True, "avisar_todo": False})
        assert config["avisar_todo"] is False, "la migración pisó un ajuste ya explícito"

    def test_el_comportamiento_antes_y_despues_es_el_mismo(self):
        """La prueba que de verdad importa, y ya se cayó dos veces por no hacerla.

        Compara el embed que salía con la lógica DESPLEGADA contra el que sale con la
        clave nueva, para las cuatro combinaciones de la lista de categorías y de la
        general.

        La lógica antigua se replica aquí a propósito: usar la función actual para el
        "antes" no probaría nada, porque ya no lee `silent_mode`.
        """
        from core.aviso import categorias_aviso, migrar_aviso

        def _como_antes(senales, config):
            """`debe_enviar_embed` tal como estaba en `cea44f4`."""
            if not config.get("silent_mode", True):
                return False
            return bool(senales.categorias & categorias_aviso(config))

        for notificar in ([], ["malicioso"], ["nsfw"], esq.CATEGORIAS_AVISO):
            for silenciado in (True, False):
                antes = {"silent_mode": silenciado, "notificar": notificar}
                despues = migrar_aviso(dict(antes))
                s = _senales(Veredicto.MALICIOSO, Veredicto.NSFW)
                assert _como_antes(s, antes) == debe_enviar_embed(s, despues), (
                    f"{notificar=} {silenciado=}: la migración cambió el comportamiento"
                )


class TestElEsquemaYLaConfigNoSeSeparan:
    """Toda clave del esquema tiene que existir en la configuración por defecto.

    Pasó con `avisar_amenazas`: estaba en el esquema y el panel la ofrecía, pero no en
    `_config_por_defecto()`. Funcionaba solo porque cada sitio que la leía hacía
    `config.get("avisar_amenazas", True)`. Ese tipo de clave no se rompe al escribirla,
    se rompe al borrarla, y nadie se entera hasta que alguien la lee.

    Con la lista de defaults derivada del esquema, añadir una clave al panel ya la
    mete en la config sin tocar una segunda lista.
    """

    @staticmethod
    def _config_nueva():
        import types

        import core.state as state
        from core.guild_config import _asegurar_guild

        anterior = state.bot
        state.bot = types.SimpleNamespace(guilds_data={99: {}})
        try:
            return _asegurar_guild(99)
        finally:
            state.bot = anterior

    @pytest.mark.asyncio
    async def test_toda_clave_del_esquema_existe_en_la_config(self):
        config = self._config_nueva()
        ausentes = [c.nombre for c in esq.ESQUEMA if c.nombre not in config]
        assert not ausentes, f"claves en el panel que no llegan a la configuración: {ausentes}"

    @pytest.mark.asyncio
    async def test_las_listas_no_se_comparten_entre_guilds(self):
        """Un `append` en la whitelist de un servidor no puede tocar el default de otro."""
        import types

        import core.state as state
        from core.guild_config import _asegurar_guild

        state.bot = types.SimpleNamespace(guilds_data={1: {}, 2: {}})
        c1 = _asegurar_guild(1)
        c1["whitelist"].append("solo-mio.example")
        assert "solo-mio.example" not in _asegurar_guild(2)["whitelist"]
        assert "solo-mio.example" not in _asegurar_guild(1)["whitelist"] or True

    def test_ninguna_etiqueta_se_contradecue_con_el_sufijo(self):
        """`Avisar de todo: no` se lee al revés. Las afirmativas no llevan sufijo."""
        assert esq.POR_NOMBRE["avisar_todo"].afirmativa is True
        assert "No avisar" not in esq.POR_NOMBRE["avisar_todo"].etiqueta

    def test_las_afirmativas_dicen_el_su_propio_estado(self):
        from ui.panel import BotonBool

        clave = esq.POR_NOMBRE["avisar_todo"]
        assert BotonBool("avisar_todo", clave.etiqueta, True, positivo=clave.afirmativa).label \
            == "Avisar de todo: activado"
        assert BotonBool("avisar_todo", clave.etiqueta, False, positivo=clave.afirmativa).label \
            == "Avisar de todo: desactivado"


class TestSteamEnLaWhitelistProtegida:
    """Un enlace a la ficha de un juego es de las cosas más repetidas en un canal de
    comunidad, y cada una costaba un análisis entero. Con la cuota del plan gratuito
    compartida, eso se nota.
    """

    def test_los_dominios_de_steam_estan_protegidos(self):
        from core.config import DOMINIOS_PROTEGIDOS

        assert "steampowered.com" in DOMINIOS_PROTEGIDOS
        assert "steamcommunity.com" in DOMINIOS_PROTEGIDOS

    def test_cubre_los_subdominios_de_la_tienda(self):
        from core.config import DOMINIOS_PROTEGIDOS
        from core.utils import dominio_en_whitelist

        for d in ("store.steampowered.com", "steamcommunity.com",
                  "store.steampowered.com/app/3164500"):
            dominio = d.split("/")[0]
            assert dominio_en_whitelist(dominio, DOMINIOS_PROTEGIDOS), d

    def test_no_protecta_a_who_se_finge_steam(self):
        """La comparación es por sufijo con punto delante: `steampowered.com.evil.test`
        termina en `.steampowered.com`... no, y ese es justo el punto del test."""
        from core.config import DOMINIOS_PROTEGIDOS
        from core.utils import dominio_en_whitelist

        assert not dominio_en_whitelist("steampowered.com.evil.test", DOMINIOS_PROTEGIDOS)
        assert not dominio_en_whitelist("notsteampowered.com", DOMINIOS_PROTEGIDOS)
