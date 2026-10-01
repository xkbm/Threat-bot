"""Defectos encontrados auditando el código, fijados como tests.

Cada clase de este archivo corresponde a un fallo real que la suite anterior no
detectaba. Están agrupados por gravedad.
"""

import ast
import inspect
import types

import pytest


class TestElPhishingNoPuedeBlindarElEscaneo:
    """CRÍTICO: un falso positivo aquí desactiva el escaneo de malware.

    En `ui/message_handler.py` las URLs marcadas como phishing se SACAN de la lista que
    se manda a `analizar_url`. Así que marcar de más no es "una alerta de más": es
    malware que deja de mirarse. Y los falsos positivos estaban en la infraestructura más
    usada: el CDN de Discord, S3 de Amazon, el login de Microsoft y la API de Dropbox.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "https://media.discordapp.net/attachments/1/2/a.png",
            "https://cdn.discordapp.com/avatars/1/a.png",
            "https://images-amazon.s3.amazonaws.com/x.png",
            "https://s3.amazonaws.com/bucket/x",
            "https://login.microsoftonline.com/common",
            "https://api.dropboxapi.com/2/files/x",
            "https://i.ytimg.com/vi/abc.jpg",
            "https://steamcdn-a.akamaihd.net/x.png",
            "https://fonts.gstatic.com/s/x",
            "https://cdn.discordapp.com/a?ex=1&is=2",
        ],
    )
    def test_infraestructura_legitima_no_se_marca(self, url):
        from core.phishing import detectar

        r = detectar(url)
        assert r.es_phishing is False, f"{url} → {r.razon}"

    @pytest.mark.parametrize(
        "url,marca",
        [
            ("https://rnicrosoft.com/gift", "microsoft"),
            ("https://paypa1-secure.tk/login", "paypal"),
            ("https://steamcomunnity.ru/trade", "steam"),
            ("https://discord.com.evil.io/n", "discord"),
            ("https://netfliix-to-free.club", "netflix"),
            ("https://notmicrosoft.com/", "microsoft"),
            ("https://discorcl.com/nitro", "discord"),
            ("https://roblox-gift-generator.tk", "roblox"),
        ],
    )
    def test_el_phishing_real_sigue_detectandose(self, url, marca):
        """Arreglar los falsos positivos no puede relajar la detección."""
        from core.phishing import detectar

        r = detectar(url)
        assert r.es_phishing is True, f"{url} dejo de detectarse"
        assert r.marca == marca

    def test_punycode_sigue_siendo_phishing(self):
        from core.phishing import detectar

        assert detectar("https://xn--discord-ypa.com/g").es_phishing is True


class TestElPrimerGetDeVirusTotalDebeEstarDentroDelTry:
    """CRÍTICO: una excepción aquí dejaba el mensaje sin nada.

    `analizar_url` hacía su primer GET a VirusTotal FUERA del bloque `try`. Cualquier
    timeout, error de DNS o JSON malformado escapaba, se saltaba `_finalizar_error` y
    subía por `vuelo()` hasta el `done_callback` del bot. Ese mensaje se quedaba sin
    embed, sin reacción, sin registro en `/history` y sin evento.
    """

    def test_el_get_inicial_esta_dentro_de_un_try(self):
        import ast as _ast

        import api.virustotal as vt

        arbol = _ast.parse(inspect.getsource(vt.analizar_url))
        # Busca el nodo que hace el GET inicial a /urls/ y comprueba que está dentro de
        # un Try, no a nivel de función.
        # La URL es un f-string, así que no se puede buscar una constante: se
        # descompila el argumento y se busca la subcadena.
        nodo_get = None
        for nodo in _ast.walk(arbol):
            if isinstance(nodo, _ast.Call) and getattr(nodo.func, "attr", "") == "get":
                if "/api/v3/urls/" in _ast.unparse(nodo.args[0]) if nodo.args else False:
                    nodo_get = nodo
                    break
        assert nodo_get is not None, "no se encuentra el GET inicial a /urls/"

        # El GET está dentro de un `async with`, así que cuelga de un With que a su
        # vez cuelga de un Try. Hay que subir por los ancestros: basta con que en
        # algún momento del camino aparezca un Try antes de llegar a la función.
        camino = []
        actual = nodo_get
        pila = [(nodo_get, None)]
        for nodo in _ast.walk(arbol):
            for hijo in _ast.iter_child_nodes(nodo):
                pila.append((hijo, nodo))
        mapa = dict((h, p_) for h, p_ in pila)
        while actual is not None:
            camino.append(type(actual).__name__)
            if isinstance(actual, _ast.Try):
                return          # está protegido
            if isinstance(actual, (_ast.AsyncFunctionDef, _ast.FunctionDef)):
                break
            actual = mapa.get(actual)
        raise AssertionError(
            f"el GET inicial no está dentro de ningún try; camino: {' -> '.join(camino)}"
        )

    def test_hay_una_salida_para_error_de_red(self):
        import api.virustotal as vt

        assert hasattr(vt, "_error_red"), "falta un embed propio para fallo de red"
        assert vt._error_red() is not None


class TestVueloNoSeEnvenenaConNone:
    """CRÍTICO: un usuario sin cuota rompía el análisis de los demás.

    `_resolver_url` y `_llamar_vt` devolvían `None` cuando el usuario agotaba su cupo.
    `vuelo()` trata `None` como resultado legítimo y lo reparte a **todos** los
    esperadores; solo `SIN_RESPUESTA` activa el reintento individual. Así que un usuario
    limitado hacía que todos los concurrentes analyzing el mismo enlace recibieran un
    error falso y se quedaran sin escanear.
    """

    def test_vuelo_trata_none_como_resultado_legitimo(self):
        """Documenta por qué `None` es peligroso aquí, para que no se reintroduzca."""
        import inspect as _i

        import core.utils as u

        fuente = _i.getsource(u.vuelo)
        assert "if valor is SIN_RESPUESTA" in fuente, (
            "vuelo solo distingue SIN_RESPUESTA: por eso los resolvers de URL tienen que "
            "devolver eso y nunca None"
        )

    def test_ningun_resolver_devuelve_none(self):
        """Guarda estática sobre el fichero: no puede volver a colarse un `return None`."""
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "ui" / "message_handler.py").read_text(encoding="utf-8")
        arbol = ast.parse(texto)

        # Localiza los dos resolvers de URL y comprueba que no devuelven None.
        malas = []
        for nodo in ast.walk(arbol):
            if not isinstance(nodo, (ast.AsyncFunctionDef,)):
                continue
            if nodo.name not in ("_resolver_url", "_llamar_vt", "_leer_cache"):
                continue
            for sub in ast.walk(nodo):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Constant):
                    if sub.value.value is None:
                        malas.append(f"{nodo.name}:{sub.lineno}")
        # `_leer_cache` no es un resolver de vuelo, se excluye arriba; el resto debe estar limpio.
        assert not malas, f"devuelven None dentro de un vuelo: {malas}"


class TestLasClavesViejasDeSightEngineNoVuelven:
    """ALTO: el refactor de `models` dejó dos ramas con la clave antigua.

    `models` pasó a tener `nudity_raw`, `nudity_partial`, `gore`, `weapon`, `alcohol` y
    `offensive`. `models['nudity']` ya no existe, así que las dos ramas que la leían
    devolvían 0.0 siempre: el detalle salía como "Contenido inapropiado" sin nombrar qué
    se había detectado, y alcohol o armas quedaban etiquetados como `nsfw`.
    """

    def test_ninguna_rama_usa_las_claves_antiguas(self):
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "ui" / "message_handler.py").read_text(encoding="utf-8")
        for clave in ("'nudity'", '"nudity"', "'offensive'", '"offensive"'):
            assert f"models.get({clave}" not in texto, (
                f"queda una lectura de la clave antigua models.get({clave})"
            )

    def test_ningun_umbral_esta_escrito_a_mano(self):
        """Los umbrales salen de `core.config`; repetidos aquí son una tercera fuente."""
        import pathlib
        import re

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "ui" / "message_handler.py").read_text(encoding="utf-8")
        # `>= 0.5` y `>= 0.7` sobre los modelos de SightEngine.
        assert not re.search(r"models\.get\([^)]*\)\s*>=\s*0\.[57]", texto), (
            "hay un umbral de SightEngine escrito a mano; debe salir de evaluar_contenido"
        )

    def test_las_tres_ramas_pasan_por_evaluar_contenido(self):
        """Acierto de caché, descarga y adjunto: los tres caminos, el mismo veredicto."""
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "ui" / "message_handler.py").read_text(encoding="utf-8")
        assert texto.count("evaluar_contenido(") >= 3, (
            "cada rama que decide el veredicto de una imagen debe usar evaluar_contenido"
        )


class TestElControladorDeReaccionesNoSeFuga:
    """ALTO: `_reaction_controllers` crecía sin cota.

    `_controlador_para` meteía un controlador por `message.id` y nada lo sacaba jamás. Se
    creaba al poner el emoji de progreso, así que cualquier excepción entre ahí y el final
    del análisis lo dejaba huérfano para siempre.
    """

    def test_se_libera_al_final_del_analisis(self):
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "ui" / "message_handler.py").read_text(encoding="utf-8")
        assert "_liberar_controlador" in texto
        # Al menos dos puntos de salida: el final y el retorno temprano.
        assert texto.count("_liberar_controlador(bot, message)") >= 2, (
            "hay que liberarlo también en el retorno temprano, que es por donde más fugaba"
        )

    def test_no_se_declara_una_lista_para_cosas_que_ya_no_existen(self):
        import cogs.configuracion as cfg_mod

        fuente = inspect.getsource(cfg_mod)
        assert "config[\"silent_mode\"] = estado" not in fuente, (
            "silent_mode ya no se lee en el handler: la decisión la toma debe_enviar_embed"
        )


class TestElEmbedNoDiceTodoLimpioCuandoNoSeMiroNada:
    """ALTO: un embed verde de "todo seguro" sobre un mensaje que no se分析了.

    `peor([])` devuelve SEGURO por diseño, así que un mensaje con solo enlaces en
    whitelist salía con el título "Todos los elementos son seguros" en verde junto a
    "0 elemento(s) analizado(s)" y "2 enlace(s) en whitelist". Se contradecía a sí mismo
    y contradecía la regla del propio módulo: lo no comprobado nunca es `seguro`.
    """

    def test_ignorado_no_es_seguro(self):
        from core.veredictos import Veredicto

        assert Veredicto.IGNORADO is not Veredicto.SEGURO
        assert Veredicto.IGNORADO.color != Veredicto.SEGURO.color
        assert Veredicto.IGNORADO.emoji == "<:SM_Whitelist:1496963945943269498>"

    def test_ignorado_entra_en_las_dos_tablas(self):
        from core.veredictos import ORDEN_CONTADORES, PRECEDENCIA, Veredicto

        assert set(PRECEDENCIA) == set(Veredicto), "falta en PRECEDENCIA"
        assert set(ORDEN_CONTADORES) == set(Veredicto), "falta en ORDEN_CONTADORES"

    def test_todo_veredicto_tiene_todas_sus_propiedades(self):
        from core.veredictos import Veredicto

        for v in Veredicto:
            assert isinstance(v.color, int), v
            assert v.emoji and v.titulo and v.contador, v

    @pytest.mark.asyncio
    async def test_el_embed_de_solo_whitelist_no_dice_todo_seguro(self):
        from core.senales import desde_tuplas
        from core.veredictos import Veredicto
        from ui.message_handler import _construir_embed_unificado

        class _Msg:
            class _A:
                mention = "<@u>"
            author = _A()

        senales = desde_tuplas([], [], [], [])
        senales.whitelist_omitidos = 2
        embed = await _construir_embed_unificado(_Msg(), senales)

        assert "Todos los elementos son seguros" not in embed.title
        assert Veredicto.IGNORADO.titulo in embed.title
        assert "whitelist" in embed.description.lower()


class TestNoSeDejanTemporalesNiFilas:
    """ALTO: dos fugas silenciosas de `on_guild_remove` y del volcado."""

    def test_el_volcado_limpia_el_temporal_si_falla(self):
        import inspect

        from core import database as db

        fuente = inspect.getsource(db._flush_datos)
        assert "os.remove(tmp)" in fuente, (
            "si json.dump falla, el temporal se queda en core/ para siempre"
        )

    def test_existe_borrar_guild_db(self):
        import inspect

        from core import database as db

        assert hasattr(db, "borrar_guild_db")
        fuente = inspect.getsource(db.borrar_guild_db)
        for tabla in ("guild_config", "infracciones", "eventos"):
            assert tabla in fuente, f"{tabla} no se borra al salir el bot"

    def test_existe_olvidar_guild(self):
        from core import guild_config as gc

        assert hasattr(gc, "olvidar_guild")

    def test_on_guild_remove_limpia_sqlite(self):
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        texto = (raiz / "bot.py").read_text(encoding="utf-8")
        bloque = texto[texto.index("async def on_guild_remove"):]
        bloque = bloque[:bloque.index("async def shutdown")]
        assert "borrar_guild_db" in bloque
        assert "olvidar_guild" in bloque


class TestElPanelNoTieneControlesMuertos:
    """Un control que no hace nada hace creer al admin que ha configurado algo.

    Once claves se declaraban en el esquema, se dibujaban en el panel y no las leía
    nadie: el admin ponía "Máximos adjuntos: 25" y el bot seguía con 5 sin decir nada.
    """

    @pytest.mark.parametrize(
        "clave",
        [
            "umbral_nudity", "umbral_partial", "umbral_gore", "umbral_offensive",
            "umbral_alcohol", "umbral_weapon", "detectar_phishing",
        ],
    )
    def test_toda_clave_util_se_lee_en_alguna_pista(self, clave):
        """Toda clave del panel tiene que tener un consumidor real.

        Los umbrales se consumen en `aplicar_config`, que vive en el propio esquema y
        traduce `umbral_partial` a la clave que espera SightEngine. Por eso aquí se mira
        también ese fichero, pero **fuera** del bloque `ESQUEMA`: declarar la clave ahí
        no es leerla, y si se contara sería un falso verde.
        """
        import pathlib
        import re

        raiz = pathlib.Path(__file__).resolve().parent.parent
        esquema = (raiz / "core" / "config_schema.py").read_text(encoding="utf-8")
        i = esquema.index("ESQUEMA: tuple[Clave, ...] = (")
        j = esquema.index("\n)\n", i)
        fuera_del_esquema = esquema[:i] + esquema[j:]

        leida = f'"{clave}"' in fuera_del_esquema
        if not leida:
            for sub in ("core", "ui", "cogs", "api"):
                for f in (raiz / sub).glob("*.py"):
                    if f.name == "config_schema.py":
                        continue
                    if f'"{clave}"' in f.read_text(encoding="utf-8"):
                        leida = True
                        break
                if leida:
                    break
        assert leida, f"la clave '{clave}' se ofrece en el panel pero nadie la lee"

    @pytest.mark.parametrize(
        "clave",
        [
            # Estas SÍ gastan cuota, y las claves de API las paga quien mantiene el bot
            # y las comparten todos los servidores. Que un admin de un servidor pueda
            # subirlas es darle acceso a tu cuota mensual.
            "max_adjuntos", "max_urls", "vt_para_imagenes",
        ],
    )
    def test_las_claves_de_cuota_no_son_configurables(self, clave):
        """Ni en el esquema, ni leídas de la config en ninguna parte."""
        import pathlib

        from core.config_schema import POR_NOMBRE

        assert clave not in POR_NOMBRE, (
            f"'{clave}' vuelve a ser configurable por servidor: eso gasta la cuota de "
            f"quien mantiene el bot, no la del admin que lo cambia"
        )

        raiz = pathlib.Path(__file__).resolve().parent.parent
        for sub in ("core", "ui", "cogs", "api"):
            for f in (raiz / sub).glob("*.py"):
                if f.name == "config_schema.py":
                    continue
                assert f'"{clave}"' not in f.read_text(encoding="utf-8"), (
                    f"{f} lee '{clave}' de la config del servidor"
                )

    def test_no_vuelven_las_claves_muerto(self):
        import core.config_schema as esq

        for muerta in ("prefijo_log", "canales_exentos", "roles_exentos",
                       "antispam_por_hora", "antispam_cooldown", "avisar_ignorados",
                       "max_adjuntos", "max_urls", "vt_para_imagenes"):
            assert muerta not in esq.POR_NOMBRE, (
                f"'{muerta}' se quitó: no la leía nadie y era un control muerto"
            )

    def test_el_default_de_la_whitelist_es_el_real(self):
        """Dos defaults distintos en el módulo que existe para que no los haya.

        `claves_de("exclusiones")` devolvía una whitelist vacía mientras el default de
        verdad eran los 15 dominios protegidos. Código nuevo que usara la fuente
        "declarativa" habría dejado de proteger youtube, github y discord sin decirlo.
        """
        from core.config import DOMINIOS_PROTEGIDOS
        from core.config_schema import defaults

        assert defaults()["whitelist"] == list(DOMINIOS_PROTEGIDOS)

    def test_el_rango_de_texto_se_respeta(self):
        """`minimo`/`maximo` se declaraban y no se usaban en las claves de texto."""
        from core.config_schema import POR_NOMBRE

        for clave in POR_NOMBRE.values():
            if clave.tipo == "str" and clave.maximo is not None:
                corto = clave.valida("x" * (clave.maximo + 50))
                assert len(corto) == clave.maximo, clave.nombre


class TestLaCacheNoSeRompeConPuertos:
    """`normalizar_url` es la fuente de la clave de caché y de la clave de `vuelo`."""

    @pytest.mark.parametrize(
        "url,esperado",
        [
            # El bug: recorte de 3 caracteres fijos sobre una subcadena.
            ("http://example.com:8080/x", "http://example.com:8080/x"),
            ("https://example.com:8080/x", "https://example.com:8080/x"),
            ("https://a.com:8443/b", "https://a.com:8443/b"),
            # El puerto por defecto sí se quita.
            ("https://discord.com:443/a", "https://discord.com/a"),
            ("http://a.com:80/b", "http://a.com/b"),
            # Y no debe romper lo de siempre.
            ("https://a.com/", "https://a.com/"),
            ("https://a.com", "https://a.com/"),
            ("http://u:p8080@h.com/", "http://u:p8080@h.com/"),
        ],
    )
    def test_puertos(self, url, esperado):
        from core.utils import normalizar_url

        assert normalizar_url(url) == esperado

    def test_la_forma_con_puerto_no_colisiona_con_la_sin_puerto(self):
        """Si colisionaran, dos enlaces distintos entrarían en la misma clave."""
        from core.utils import clave_analisis, normalizar_url

        assert normalizar_url("http://a.com:8080/x") != normalizar_url("http://a.com/x")
        assert clave_analisis("url", "http://a.com:8080/x") != clave_analisis("url", "http://a.com/x")


class TestUnaImagenLimpiaNoSeReportaComoError:
    """`not any(models.get(c))` era FALSO para una imagen limpia.

    Todos los valores a 0.0 es el caso NORMAL de una imagen sin nada, así que cada
    imagen limpia se reportaba como error y, como los fallos no se cacheaban, se
    volvía a subir a SightEngine en cada reaparición: 5 operaciones del plan gratis,
    indefinidamente.
    """

    def test_respuesta_limpia_se_reconoce(self):
        from api.sightengine import _llego_alguna_clave

        limpia = {
            "nudity": {"raw": 0.0, "partial": 0.0}, "weapon": {"classes": {}},
            "alcohol": {"prob": 0.0}, "gore": {"prob": 0.0}, "offensive": {"prob": 0.0},
        }
        assert _llego_alguna_clave(limpia) is True

    def test_respuesta_sin_claves_sigue_siendo_fallo(self):
        from api.sightengine import _llego_alguna_clave

        assert _llego_alguna_clave({"status": "success", "id": "x"}) is False

    def test_evaluar_contenido_tolera_none(self):
        """La firma acepta Dict pero el guardián `es_error` sugiere que acepta None."""
        from api.sightengine import evaluar_contenido
        from core.veredictos import Veredicto

        assert evaluar_contenido(None)[0] is Veredicto.ERROR


class TestVueloNoPropagaCancelacion:
    """Cancelación ≠ error de análisis.

    `except BaseException` capturaba el `CancelledError` del líder y lo difundía como
    resultado. `CancelledError` es `BaseException`, así que se saltaba todos los
    `except Exception` del llamante: los esperadores no analizaban, no reaccionaban, no
    registraban evento y no limpiaban.
    """

    @pytest.mark.asyncio
    async def test_el_esperador_no_recibe_cancellederror(self):
        import asyncio

        import core.state as state
        import core.utils as u

        anterior = state.bot
        state.bot = types.SimpleNamespace()
        try:
            async def lento():
                await asyncio.sleep(5)
                return ("x", None, 0)

            async def otro():
                return None

            t1 = asyncio.create_task(u.vuelo("clave-test", lento))
            await asyncio.sleep(0.02)
            t2 = asyncio.create_task(u.vuelo("clave-test", otro))
            await asyncio.sleep(0.02)
            t1.cancel()
            resultado = await t2
            assert resultado is None       # cerrado limpio, no excepción
        finally:
            state.bot = anterior


class TestLasEstadisticasCuentanTodasLasCategorias:
    def test_existen_todas_las_categorias(self):
        from core.guild_config import _stats_vacias

        stats = _stats_vacias()
        for clave in ("total_analisis", "seguros", "sospechosos", "maliciosos",
                      "nsfw", "restringidos", "phishing", "ignorados", "errores"):
            assert clave in stats, clave
