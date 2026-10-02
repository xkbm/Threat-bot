"""Arranque y flujo completo del bot, sin red ni token.

Los tests de `test_e2e_defectos.py` comprueban piezas. Estos comprueban que **el
montaje entero** encaja:

- que `bot.py` se ejecute de verdad hasta el punto de arranque, y que sus exportaciones
  a los cogs estén montadas. Un cog con un error en `setup()`, o un atributo que `bot.py`
  dejó de exportar, no lo detecta ni `import` — y rompe en producción.
- que los 10 cogs carguen y que el árbol de comandos slash se construya entero, que es
  lo que Discord recibe al desplegar los comandos.
- que `procesar_analisis` recorra el camino completo con un mensaje simulado: URLs,
  caché, embed, reacción, log de amenaza e infracción.

Sin token ni red: es integración, no end-to-end.
"""

import asyncio
import os
import sys
import tempfile
import types

import aiohttp
import discord
import pytest
import pytest_asyncio
from discord.ext import commands

from core import database as db
from core import state


class _Autor:
    def __init__(self, id=42):
        self.id = id
        self.mention = f"<@{id}>"

    def __getattr__(self, _):
        return None


class _Mensaje:
    """Lo mínimo de `discord.Message` para que `procesar_analisis` llegue al final."""

    def __init__(self, content, id=1000, autor_id=42):
        self.id = id
        self.content = content
        self.author = _Autor(autor_id)
        self.guild = types.SimpleNamespace(id=1)
        self.attachments = []
        self.reacciones = []
        self.enviados = []
        self.analizadas = []
        self.borrado = False
        self.channel = types.SimpleNamespace(id=10, send=self._enviar)

    async def _enviar(self, embed=None, reference=None, **k):
        self.enviados.append(embed)

    async def add_reaction(self, emoji, user=None):
        self.reacciones.append(emoji)

    async def remove_reaction(self, emoji, user=None):
        if emoji in self.reacciones:
            self.reacciones.remove(emoji)

    async def reply(self, **k):
        self.enviados.append(k.get("embed"))

    async def delete(self):
        self.borrado = True


def _embed_malicioso():
    from ui import embed as emb
    return emb.resultado("url", {"valor": "https://ejemplo.com/malo", "vt_link": None,
                                 "top_text": None, "veredicto": "malicioso", "susp": 0}, 3)


@pytest.fixture(scope="module")
def _bot_cargado():
    """Ejecuta `bot.py` de verdad, cortado justo antes de arrancar.

    Se ejecuta el fichero entero en vez de replicar sus exportaciones a mano: si esta
    copia se desincronizara del arranque real, la comprobación dejaría de servir.

    `scope="module"`: `bot.py` construye el bot una sola vez y todos los tests lo
    comparten. Si se re-ejecutara por test, cada uno tendría un bot distinto y las
    aserciones sobre el árbol de comandos no probarían nada.

    Solo construye el bot; la sesión HTTP se crea en `bot_arrancado`, que sí corre
    dentro del event loop (una `ClientSession` nace atada al loop activo).
    """
    import importlib

    if "threat_bot_test" in sys.modules:
        return sys.modules["threat_bot_test"]

    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fuente = open(os.path.join(raiz, "bot.py")).read()
    corte = fuente.find("bot.start(")
    if corte == -1:
        corte = fuente.find("asyncio.run(")
    if corte == -1:
        corte = fuente.rfind('if __name__ == "__main__"')
    assert corte != -1, "no se encontró el punto de corte en bot.py"

    cuerpo = fuente[:corte]
    # Se sustituye la construcción del bot real por uno local, sin intents ni token.
    cuerpo = cuerpo.replace(
        'commands.Bot(command_prefix="!", intents=intents, help_command=None)',
        "bot = commands.Bot(command_prefix='!', help_command=None)")
    entorno = {"__name__": "threat_bot_test", "commands": commands,
               "asyncio": asyncio, "os": os, "discord": discord,
               "dotenv": importlib.import_module("dotenv")}
    try:
        exec(compile(cuerpo, "bot.py", "exec"), entorno)
    except SystemExit:
        pass
    sys.modules["threat_bot_test"] = entorno["bot"]
    return entorno["bot"]


@pytest_asyncio.fixture
async def bot_arrancado(_bot_cargado):
    """El bot de `bot.py` con la sesión y los semáforos que monta `setup_hook`.

    `setup_hook` no corre sin conectar a Discord, pero `procesar_analisis` los necesita.
    El fixture es async porque una `ClientSession` nace atada al loop activo.
    """
    bot = _bot_cargado
    original = state.bot
    state.bot = bot
    bot.session = aiohttp.ClientSession()
    bot.ANALYSIS_SEMAPHORE = asyncio.Semaphore(5)
    bot._user = types.SimpleNamespace(id=1)  # `user` es de solo lectura
    yield bot
    state.bot = original
    await bot.session.close()


COGS = ["about", "analisis", "configuracion", "eval", "help", "historial",
        "reboot", "rep", "stats"]


async def _cargar_cogs(bot):
    """Carga los cogs que falten. El bot es de scope module, así que entre tests ya
    pueden estar cargados y `load_extension` falla si se repite.

    `bot.extensions` lleva el nombre completo del módulo; `bot.cogs` lleva el nombre de
    la clase y no sirve para esto.
    """
    for cog in COGS:
        if f"cogs.{cog}" not in bot.extensions:
            await bot.load_extension(f"cogs.{cog}")


class TestArranque:
    def test_bot_py_construye_el_bot(self, bot_arrancado):
        assert isinstance(bot_arrancado, commands.Bot)

    def test_las_exportaciones_a_cogs_estan_montadas(self, bot_arrancado):
        """Si `bot.py` deja de exportar algo, el fallo aparece en el cog y en
        producción, no aquí."""
        for atributo in ("analizar_url", "analizar_hash", "analizar_ip", "analizar_archivo",
                         "obtener_config_guild", "obtener_stats_globales", "update_stats_guild",
                         "get_from_cache_mem", "set_cache_mem", "obtener_analisis_db",
                         "guardar_analisis_db", "guardar_datos", "expandir_url",
                         "tiene_doble_extension", "dominio_en_whitelist", "barra_porcentaje",
                         "safe_send", "analizar_imagen_nsfw"):
            assert hasattr(bot_arrancado, atributo), f"falta la exportación '{atributo}'"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("cog", COGS)
    async def test_cada_cog_carga(self, bot_arrancado, cog):
        await _cargar_cogs(bot_arrancado)
        assert f"cogs.{cog}" in bot_arrancado.extensions, f"el cog '{cog}' no se registró"

    @pytest.mark.asyncio
    async def test_el_arbol_de_comandos_se_construye(self, bot_arrancado):
        await _cargar_cogs(bot_arrancado)
        comandos = {c.name for c in bot_arrancado.tree.get_commands()}
        # La configuración ya no tiene comandos propios: todo pasa por el panel. Estos
        # sequitaron a propósito, y que un test los exigiera los habría vuelto a poner.
        esperados = {"scan", "usercheck", "stats", "settings", "help", "about", "history"}
        assert esperados <= comandos, f"faltan: {esperados - comandos}"

        eliminados = {"silentmode", "strictmode", "autoscan", "setlogchannel",
                      "disablelogchannel", "whitelist"}
        assert not (eliminados & comandos), (
            f"vuelven comandos de configuración que ya no existen: {eliminados & comandos}"
        )

    @pytest.mark.asyncio
    async def test_usercheck_exige_permisos(self, bot_arrancado):
        """El expediente de seguridad de una persona no es público."""
        await _cargar_cogs(bot_arrancado)
        uc = next(c for c in bot_arrancado.tree.get_commands() if c.name == "usercheck")
        assert uc.default_permissions is not None
        assert uc.default_permissions.manage_messages

    @pytest.mark.asyncio
    async def test_los_comandos_de_configuracion_exigen_permiso(self, bot_arrancado):
        await _cargar_cogs(bot_arrancado)
        de_config = {"silentmode", "strictmode", "autoscan", "setlogchannel",
                     "disablelogchannel", "settings", "whitelist"}
        sin_permiso = [c.name for c in bot_arrancado.tree.get_commands()
                       if c.name in de_config and not c.default_permissions]
        assert not sin_permiso, f"sin permiso: {sin_permiso}"


class TestVistas:
    def test_la_vista_de_amenaza_es_persistente(self):
        """`timeout=None` es lo que hace que los botones sobrevivan a un reinicio."""
        from ui.views import LogActionView
        v = LogActionView(1, 42, "url:https://x.example")
        assert v.timeout is None
        assert len(v.children) > 0
        assert (v.guild_id, v.user_id) == (1, 42)
        assert v.elemento_id == "url:https://x.example"

    def test_el_paginador_de_whitelist_construye(self):
        from ui.views import WhitelistPaginatorView
        pag = WhitelistPaginatorView("Servidor", ["a.com", "b.com"], "<:escudo:1>")
        assert len(pag.children) > 0

    def test_el_modal_de_razon_construye(self):
        from ui.views import LogActionView, RazonModal
        v = LogActionView(1, 42, "url:x")
        assert RazonModal("ban", v, None) is not None


@pytest_asyncio.fixture
async def bot_analisis(bot_arrancado, tmp_path):
    """Bot con base de datos temporal y la API sustituida."""
    from core import guild_config as gc

    pool_original = db.POOL
    # Un pool nuevo por test: el anterior queda cerrado y `DatabasePool` no se puede
    # volver a arrancar, así que reutilizarlo daría IndexError en `_read_conn`.
    db.POOL = db.DatabasePool(str(tmp_path / "flow.db"))
    await db.init_db()  # abre las conexiones y cuelga el pool en state.bot
    guardar_original = gc.guardar_datos
    gc.guardar_datos = lambda *a, **k: asyncio.sleep(0)
    state.bot.guilds_data = {}
    state.bot.cache_mem = {}
    state.bot.user_scan_history = {}
    state.bot.antispam_scan = {}
    state.bot.vt_user_requests = {}
    yield bot_arrancado
    gc.guardar_datos = guardar_original
    await db.POOL.stop()
    db.POOL = pool_original
    bot_arrancado.db_pool = pool_original
    # `_procesados` es un dict a nivel de módulo: sin limpiarlo, el siguiente test
    # vería estos mensajes como ya procesados y los omitiría.
    import ui.message_handler as mh
    mh.limpiar_cache_procesados()


class TestFlujoCompleto:
    @pytest.mark.asyncio
    async def test_mensaje_con_amenaza(self, bot_analisis):
        from core import cache as cache_mod
        from core.utils import clave_analisis
        import ui.message_handler as mh

        msg = _Mensaje("mira esto https://ejemplo.com/malo y https://ejemplo.com/limpio")

        async def _analizar_falso(url, *a, **k):
            """Sustituye a la API. Guarda en caché como haría la de verdad: sin esto
            el cache-hit de la ronda siguiente no se puede comprobar."""
            msg.analizadas.append(url)
            await cache_mod.set_cache_mem(
                clave_analisis("url", url), "malicioso", mal=3,
                datos={"valor": url, "vt_link": None, "top_text": None,
                       "veredicto": "malicioso", "susp": 0})
            return "malicioso", _embed_malicioso(), 3

        mh.analizar_url = _analizar_falso
        mh.expandir_url = lambda bot, url: asyncio.sleep(0, result=url)

        await mh.procesar_analisis(bot_analisis, msg)
        await asyncio.sleep(0.05)

        assert len(msg.analizadas) == 2, msg.analizadas
        # Modo estricto: el mensaje se borra, así que NO lleva reacción. Reaccionar a un
        # mensaje que el `delete` de después se lleva era una llamada a la API inútil, y
        # en un canal con mucho contenido peligroso esas llamadas se suman justo cuando
        # Discord está más cerca de devolver 429. Antes este test exigía el ⚠️ aquí, o
        # sea fijaba el desperdicio.
        assert msg.borrado, "el modo estricto tenía que borrar el mensaje"
        assert not any("Warning" in r for r in msg.reacciones), msg.reacciones
        # El embed sí se manda, y es lo que avisa al canal de que hubo una amenaza.
        assert len(msg.enviados) == 1
        assert "Amenazas" in msg.enviados[0].title
        assert len(msg.enviados[0].fields) > 0

    @pytest.mark.asyncio
    async def test_si_no_se_puede_borrar_la_reaccion_sigue_puesta(self, bot_analisis):
        """El caso revés, que es el que evita que el arreglo se lleve por delante la
        señal.

        Si al bot le falta permiso de borrar, el mensaje sigue ahí y visible: la reacción
        pasa a ser lo único que dice "esto se ha mirado y es malo". Quitar la reacción
        siempre, sin mirar si el borrado funcionó, dejaría los mensajes Dangerous a la
        vista sin ninguna marca. Por eso la reacción se decide con el resultado real del
        `delete` y no con la intención de borrar.
        """
        from core.utils import clave_analisis
        import ui.message_handler as mh

        msg = _Mensaje("https://ejemplo-noborrable.test/malo")

        async def _analizar_falso(url, *a, **k):
            from core import cache as cache_mod
            await cache_mod.set_cache_mem(
                clave_analisis("url", url), "malicioso", mal=3,
                datos={"valor": url, "vt_link": None, "top_text": None,
                       "veredicto": "malicioso", "susp": 0})
            return "malicioso", _embed_malicioso(), 3

        async def _borrar_fallido():
            class _Resp:
                status = 403
                reason = "Forbidden"
                text = "Missing Permissions"
            raise discord.errors.Forbidden(_Resp(), "Missing Permissions")

        mh.analizar_url = _analizar_falso
        mh.expandir_url = lambda bot, url: asyncio.sleep(0, result=url)
        msg.delete = _borrar_fallido

        await mh.procesar_analisis(bot_analisis, msg)
        await asyncio.sleep(0.05)

        assert not msg.borrado
        assert any("Warning" in r for r in msg.reacciones), (
            "sin borrar, la reacción es la única señal y no puede desaparecer: "
            f"{msg.reacciones}"
        )

    @pytest.mark.asyncio
    async def test_la_cache_hace_acierto_de_verdad(self, bot_analisis):
        """F1 comprobado en el flujo real: la segunda vez el resultado sale de la
        caché y no se vuelve a llamar a la API."""
        from core import cache as cache_mod
        from core.utils import clave_analisis
        import ui.message_handler as mh

        llamadas = []
        # Un texto propio de este test: la deduplicación de `procesar_analisis` es
        # por huella de contenido, así que reutilizar el de otro test lo omitiría.
        url = "https://ejemplo-cache.test/malo"
        msg = _Mensaje(f"otro mensaje con {url}")

        async def _analizar_falso(url, *a, **k):
            llamadas.append(url)
            await cache_mod.set_cache_mem(
                clave_analisis("url", url), "malicioso", mal=3,
                datos={"valor": url, "vt_link": None, "top_text": None,
                       "veredicto": "malicioso", "susp": 0})
            return "malicioso", _embed_malicioso(), 3

        mh.analizar_url = _analizar_falso
        mh.expandir_url = lambda bot, url: asyncio.sleep(0, result=url)

        await mh.procesar_analisis(bot_analisis, msg)
        await asyncio.sleep(0.05)
        segundo = _Mensaje(f"otra persona con {url}", id=1001, autor_id=43)
        await mh.procesar_analisis(bot_analisis, segundo)
        await asyncio.sleep(0.05)

        assert len(llamadas) == 1, f"la API se llamó {len(llamadas)} veces: {llamadas}"

    @pytest.mark.asyncio
    async def test_el_mismo_mensaje_no_se_reprocesa(self, bot_analisis):
        import ui.message_handler as mh

        msg = _Mensaje("sin nada sospechoso aqui")

        async def _analizar_falso(url, *a, **k):
            raise AssertionError("no debería analizar: el mensaje va vacío")

        mh.analizar_url = _analizar_falso
        await mh.procesar_analisis(bot_analisis, msg)
        await asyncio.sleep(0.05)
        antes = len(msg.enviados)
        await mh.procesar_analisis(bot_analisis, msg)
        await asyncio.sleep(0.05)
        assert len(msg.enviados) == antes

    @pytest.mark.asyncio
    async def test_la_ronda_final_manda_el_log_de_la_cache(self, bot_analisis):
        """Cuando el resultado sale de la caché, la API no mandó ningún log: quien
        tiene que mandarlo es la ronda final de `procesar_analisis`."""
        from core import cache as cache_mod
        from core import guild_config as gc
        from core.utils import clave_analisis
        import ui.message_handler as mh

        logs = []
        infracciones = []
        gc._asegurar_guild(1)["log_channel_id"] = 555

        async def _analizar_falso(url, *a, **k):
            await cache_mod.set_cache_mem(
                clave_analisis("url", url), "malicioso", mal=3,
                datos={"valor": url, "vt_link": None, "top_text": None,
                       "veredicto": "malicioso", "susp": 0})
            return "malicioso", _embed_malicioso(), 3

        # Los parches van en el namespace de `message_handler`: hizo `from ... import`,
        # así que cambiar el módulo de origen no surte efecto aquí.
        mh.analizar_url = _analizar_falso
        mh.expandir_url = lambda bot, url: asyncio.sleep(0, result=url)
        mh.enviar_log_guild = lambda *a, **k: asyncio.sleep(0, result=logs.append(a))
        mh.registrar_infraccion = lambda *a, **k: asyncio.sleep(0, result=infracciones.append(a))

        primero = _Mensaje("https://ejemplo.com/malo", id=2000, autor_id=42)
        await mh.procesar_analisis(bot_analisis, primero)
        await asyncio.sleep(0.05)
        logs.clear()
        infracciones.clear()

        # Misma URL, otro autor: cae en caché y la ronda final actúa.
        segundo = _Mensaje("https://ejemplo.com/malo", id=2001, autor_id=43)
        await mh.procesar_analisis(bot_analisis, segundo)
        await asyncio.sleep(0.05)

        assert len(logs) == 1, f"la ronda final no mandó el log: {logs}"
        assert len(infracciones) == 1
        # La infracción es del autor del SEGUNDO mensaje, no del que escaneó primero.
        assert infracciones[0][1] == 43
