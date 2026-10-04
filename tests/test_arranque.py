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
    async def test_el_log_lleva_el_enlace_al_mensaje_si_no_se_borro(self, bot_analisis):
        """El log lleva el enlace al mensaje mientras siga existiendo, y no si no.

        El enlace es lo que convierte el log en un registro: sin él hay que buscar el
        mensaje a mano. Y si el mensaje ya se borró, un enlace a él manda al moderador a
        una pantalla de "mensaje no encontrado" justo cuando está leyendo una amenaza.

        Antes lo decidía `_on_threat_found`, en plena carrera con el borrado del handler:
        una ruta ganaba el `delete` y la otra recibía `NotFound`, así que con dos URLs en
        un mensaje solo uno de los dos logs llevaba el enlace. Ahora lo decide un único
        sitio, después de borrar, y sale igual en todos.

        Este test antes llamaba a `_on_threat_found` directamente y esperaba un log. Ya no
        lo hace: el log agrupado lo manda el handler. Un test que sigue probando el sitio
        viejo pasa o falla por casualidad y además tapa que el nuevo pueda estar roto.
        """
        from core import guild_config as gc
        await gc.actualizar_config(1, log_channel_id=555, strict_mode=False)
        enviados = self._captura_log()

        msg = _Mensaje("https://ejemplo-enlace-vivo.test/malo", id=9101)
        await self._amenaza_sin_borrar(bot_analisis, msg)

        amenazas = [e for e in enviados if "detecc" in (e.title or "").lower()]
        assert amenazas, f"no llegó el log de amenaza: {[e.title for e in enviados]}"
        origen = next((f for f in amenazas[0].fields if "Origen" in f.name), None)
        assert origen is not None, "con el mensaje vivo, el log tiene que traer el enlace"
        assert "9101" in origen.value, origen.value

    @pytest.mark.asyncio
    async def test_sin_mensaje_el_log_no_inventa_enlace(self):
        """Un escaneo manual no tiene mensaje: tampoco hay enlace que poner."""
        import api.virustotal as vt
        from core import state

        enviados = []

        class _Canal:
            id = 777

            async def send(self, embed=None, view=None, **k):
                enviados.append(embed)
                return types.SimpleNamespace(id=1)

        original = state.bot
        state.bot = types.SimpleNamespace(
            guilds_data={1: {"log_channel_id": 777, "avisar_amenazas": True,
                             "strict_mode": False}},
            get_channel=lambda cid: _Canal(),
        )
        try:
            await vt._on_threat_found(
                "URL", "http://z", 1, 1, None,
                registrar_para=types.SimpleNamespace(id=99, mention="<@99>"),
            )
            await asyncio.sleep(0.05)
            assert enviados
            assert not any("Origen" in f.name for f in enviados[0].fields)
        finally:
            state.bot = original

    @pytest.mark.asyncio
    async def test_restringido_no_sale_como_malware_en_el_log(self):
        """El bug de la captura: "CONTENIDO RESTRINGIDO resultó malicioso" con botón de banear.

        Se prueba contra `enviar_log_guild` y no contra el handler porque un URL nunca es
        `restringido`: solo lo son las imágenes. Lo que decide mal es el embed, que
        escribía "resultó malicioso" en el texto y se usaba para todo veredicto que no
        fuera NSFW.
        """
        import api.virustotal as vt
        from core import state

        enviados = []

        class _Canal:
            id = 777
            async def send(self, embed=None, view=None, **k):
                enviados.append(embed)
                return types.SimpleNamespace(id=1)

        original = state.bot
        state.bot = types.SimpleNamespace(
            guilds_data={1: {"log_channel_id": 777, "avisar_amenazas": True}},
            get_channel=lambda cid: _Canal(),
        )
        try:
            await vt.enviar_log_guild(
                1, "Contenido restringido", "image.png", "Alcohol 82%",
                types.SimpleNamespace(id=42, mention="<@42>"),
                veredicto="restringido", mensaje="",
            )
        finally:
            state.bot = original

        assert enviados, "no se envió el embed"
        desc = (enviados[0].description or "").lower()
        assert "malicioso" not in desc, enviados[0].description
        assert "restringido" in desc, enviados[0].description

    @pytest.mark.asyncio
    async def test_el_malicious_sigue_diciendose_malicioso(self):
        """El camino bueno no se ha roto al cambiar el parámetro."""
        import api.virustotal as vt
        from core import state

        enviados = []

        class _Canal:
            id = 777
            async def send(self, embed=None, view=None, **k):
                enviados.append(embed)
                return types.SimpleNamespace(id=1)

        original = state.bot
        state.bot = types.SimpleNamespace(
            guilds_data={1: {"log_channel_id": 777, "avisar_amenazas": True}},
            get_channel=lambda cid: _Canal(),
        )
        try:
            await vt.enviar_log_guild(
                1, "URL", "http://x", "3 detecciones",
                types.SimpleNamespace(id=42, mention="<@42>"), veredicto="malicioso",
            )
        finally:
            state.bot = original

        assert enviados
        assert "malicioso" in (enviados[0].description or "").lower(), enviados[0].description

    @pytest.mark.asyncio
    async def test_un_mensaje_con_amenaza(self, bot_analisis):
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

    @staticmethod
    def _captura_log():
        """Canal de log falso que guarda los embeds que le mandan."""
        from core import state as state_mod

        enviados = []

        class _CanalLog:
            name = "registro"
            async def send(self, embed=None, **k):
                enviados.append(embed)
                return types.SimpleNamespace(id=1)

        state_mod.bot.get_channel = lambda cid: _CanalLog()
        return enviados

    async def _amenaza_sin_borrar(self, bot_analisis, msg):
        """Deja el análisis listo y hace que borrar falle con Forbidden."""
        from core.utils import clave_analisis
        import ui.message_handler as mh

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

    @pytest.mark.asyncio
    async def test_el_fallo_de_borrado_avisa_en_el_log_y_no_en_el_canal(self, bot_analisis):
        """El aviso va al log de amenazas, no al embed del canal.

        Es un dato de infraestructura —permisos del bot en un canal—, le interesa al que
        administra el bot y no a quien está en el canal viendo un aviso de contenido. En el
        embed solo añadía ruido.
        """
        from core import guild_config as gc
        gc._asegurar_guild(1)["log_channel_id"] = 555
        enviados = self._captura_log()

        msg = _Mensaje("https://ejemplo-aviso.test/malo")
        await self._amenaza_sin_borrar(bot_analisis, msg)

        texto = (msg.enviados[0].description or "").lower()
        assert "no se pudo borrar" not in texto, (
            f"el aviso de permisos es ruido en el canal de contenido: {texto}"
        )
        assert enviados, "no se envió nada al log de amenazas"
        # El título dice qué pasó y la descripción por qué.
        assert "no ha podido" in (enviados[0].title or "").lower(), enviados[0].title
        assert (enviados[0].description or "").strip(), "sin motivo no sirve de nada"

    @pytest.mark.asyncio
    async def test_el_motivo_se_pregunta_no_se_inventa(self, bot_analisis):
        """Si `Manage Messages` ya está puesto y aun así falla, decirlo.

        Antes el aviso afirmaba siempre que faltaba ese permiso. `Forbidden` también
        salta por una sobrescritura de permisos, un hilo archivado o un foro, así que un
        administrador podía cambiar un permiso que ya tenía y seguir viendo lo mismo.
        """
        import discord as _d
        from core import guild_config as gc
        gc._asegurar_guild(1)["log_channel_id"] = 555
        enviados = self._captura_log()

        msg = _Mensaje("https://ejemplo-permiso-ok.test/malo")
        msg.channel.permissions_for = lambda member: _d.Permissions(
            manage_messages=True, read_message_history=True)
        await self._amenaza_sin_borrar(bot_analisis, msg)

        assert enviados, "no se envió nada al log"
        motivo = (enviados[0].description or "").lower()
        assert "le falta" not in motivo, (
            f"el bot sí tiene ese permiso, así que no puede ser la causa: {motivo}"
        )
        assert "sí tiene" in motivo, motivo

    @pytest.mark.asyncio
    async def test_sin_permiso_si_se_la_causa_real(self, bot_analisis):
        """La otra mitad: si de verdad falta, se dice cuál, con nombre y canal."""
        import discord as _d
        from core import guild_config as gc
        gc._asegurar_guild(1)["log_channel_id"] = 555
        enviados = self._captura_log()

        msg = _Mensaje("https://ejemplo-sin-permiso.test/malo")
        msg.channel.permissions_for = lambda member: _d.Permissions(
            manage_messages=False, read_message_history=True)
        await self._amenaza_sin_borrar(bot_analisis, msg)

        assert enviados, "no se envió nada al log"
        motivo = (enviados[0].description or "").lower()
        assert "manage messages" in motivo, motivo

    @pytest.mark.asyncio
    async def test_el_embed_no_se_queja_cuando_si_se_borro(self, bot_analisis):
        """El aviso se quite cuando el borrado funcionó, o acaba siendo ruido."""
        from core.utils import clave_analisis
        import ui.message_handler as mh

        msg = _Mensaje("https://ejemplo-sinaviso.test/malo")

        async def _analizar_falso(url, *a, **k):
            from core import cache as cache_mod
            await cache_mod.set_cache_mem(
                clave_analisis("url", url), "malicioso", mal=3,
                datos={"valor": url, "vt_link": None, "top_text": None,
                       "veredicto": "malicioso", "susp": 0})
            return "malicioso", _embed_malicioso(), 3

        mh.analizar_url = _analizar_falso
        mh.expandir_url = lambda bot, url: asyncio.sleep(0, result=url)

        await mh.procesar_analisis(bot_analisis, msg)
        await asyncio.sleep(0.05)

        assert msg.borrado
        texto = (msg.enviados[0].description or "").lower()
        assert "no se pudo borrar" not in texto, texto

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
        mh.enviar_log_agrupado = lambda *a, **k: asyncio.sleep(0, result=logs.append(a))
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


class TestUnMensajeSoloTieneUnAnalisisEnVuelo:
    """Editar un mensaje mientras se analiza lanzaba un segundo análisis en paralelo.

    `_marcar_procesado` solo bloquea el re-análisis si el contenido NO cambió. Al editar,
    la huella cambia, el guard deja pasar el segundo, y los dos analizan a la vez —el
    primero tarda segundos—. Los dos llegaban al borrado del modo estricto: el primero lo
    hacía bien y el segundo recibía `NotFound`.

    Con eso, un `NotFound` acabó报告中 como "al bot le falta `Manage Messages`" en el
    canal del contenido, que era mentira y mandaba a un administrador a tocar un permiso
    que ya tenía. Es el aviso que se veía, y la causa era esto y no los permisos.
    """

    @pytest.mark.asyncio
    async def test_el_guard_deja_pasar_una_edicion(self):
        """Precondición del fallo: si esto no pasara, la carrera no podría ocurrir."""
        import ui.message_handler as mh
        mh._procesados.clear()

        def _msg(texto):
            return types.SimpleNamespace(
                id=999999, content=texto, attachments=[],
                guild=types.SimpleNamespace(id=1), author="u")

        assert mh._marcar_procesado(_msg("https://a.test")) is True
        assert mh._marcar_procesado(_msg("https://a.test")) is False
        # Editar: la huella cambia y vuelve a pasar, aunque el primero siga corriendo.
        assert mh._marcar_procesado(_msg("https://a.test https://b.test")) is True

    def test_la_generacion_invalida_al_anterior(self):
        import ui.message_handler as mh
        mh._generaciones.clear()

        primera = mh._abrir_generacion(500)
        assert mh._sigue_siendo_el_actual(500, primera) is True

        segunda = mh._abrir_generacion(500)
        assert segunda > primera
        assert mh._sigue_siendo_el_actual(500, primera) is False, (
            "el análisis viejo tiene que saber que ya no manda"
        )
        assert mh._sigue_siendo_el_actual(500, segunda) is True

    def test_mensajes_distintos_no_se_pisan(self):
        import ui.message_handler as mh
        mh._generaciones.clear()
        a = mh._abrir_generacion(1)
        b = mh._abrir_generacion(2)
        assert mh._sigue_siendo_el_actual(1, a) is True
        assert mh._sigue_siendo_el_actual(2, b) is True

    @pytest.mark.asyncio
    async def test_un_analisis_desfasado_no_borra(self, bot_analisis):
        """El flujo viejo no toca el mensaje: solo lo hace el más reciente."""
        from core.utils import clave_analisis
        import ui.message_handler as mh

        msg = _Mensaje("https://ejemplo-carrera.test/malo", id=7001)
        borrados = []

        async def _delete():
            borrados.append(msg.id)
        msg.delete = _delete

        async def _analizar_falso(url, *a, **k):
            from core import cache as cache_mod
            await cache_mod.set_cache_mem(
                clave_analisis("url", url), "malicioso", mal=3,
                datos={"valor": url, "vt_link": None, "top_text": None,
                       "veredicto": "malicioso", "susp": 0})
            # Justo mientras este análisis pide el veredicto, entra el del contenido
            # editado. Es la carrera: `on_message_edit` arranca su propio análisis del
            # mismo mensaje mientras el primero sigue esperando a la API.
            mh._abrir_generacion(msg.id)
            return "malicioso", _embed_malicioso(), 3

        mh.analizar_url = _analizar_falso
        mh.expandir_url = lambda bot, url: asyncio.sleep(0, result=url)

        await mh.procesar_analisis(bot_analisis, msg)
        await asyncio.sleep(0.05)

        assert not borrados, (
            f"un análisis ya superado no debe borrar: {borrados}"
        )
