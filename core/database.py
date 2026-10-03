import json
import os
import time
import tempfile
from typing import Optional
import aiosqlite
import discord
import asyncio
import logging
from core import state
from core.cache import set_cache_mem
from core.config import DB_FILE, DATA_FILE, EXPIRACION, DOMINIOS_PROTEGIDOS, stats_vacias

log = logging.getLogger("db")

POOL_SIZE = 4


class DatabasePool:
    def __init__(self, path: str, size: int = POOL_SIZE) -> None:
        self._path = path
        self._size = size
        self._conns: list[aiosqlite.Connection] = []
        self._write_lock = asyncio.Lock()
        self._rr = 0

    async def start(self) -> None:
        for _ in range(self._size):
            conn = await aiosqlite.connect(self._path)
            await conn.execute('PRAGMA journal_mode=WAL')
            await conn.execute('''CREATE TABLE IF NOT EXISTS analisis (
                clave TEXT PRIMARY KEY, tipo TEXT, resultado TEXT, embed_json TEXT, timestamp REAL, expira REAL, datos TEXT
            )''')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_expira ON analisis(expira)')
            await self._asegurar_columna_datos(conn)
            await self._asegurar_tablas_config(conn)
            await conn.commit()
            self._conns.append(conn)

    async def _asegurar_tablas_config(self, conn: aiosqlite.Connection) -> None:
        """Crea las tablas de configuración, infracciones y eventos, y migra `data.json`.

        Por qué: la configuración de cada servidor y las infracciones vivían en un único
        `data.json` reescrito entero en cada cambio. Eso no escala, y cada escritura
        tocaba todo el fichero, así que un solo análisis reescribía la config de todos los
        servidores a la vez.

        `guild_config` guarda la config como un blob JSON por guild: así
        `core.config_schema` sigue siendo la fuente de verdad sin una columna por opción.
        `infracciones` sí es relacional porque hay que consultar y purgar por fecha.

        Es **additive y con salida**: si algo falla, `data.json` sigue intacto y el bot
        arranca con él. Perder la configuración de un servidor es inaceptable, así que
        nada de esto borra el fichero original.
        """
        try:
            await conn.execute('''CREATE TABLE IF NOT EXISTS guild_config (
                guild_id INTEGER PRIMARY KEY, data TEXT NOT NULL, updated_at REAL
            )''')
            await conn.execute('''CREATE TABLE IF NOT EXISTS infracciones (
                guild_id INTEGER, user_id TEXT, elemento_id TEXT, created_at REAL,
                PRIMARY KEY (guild_id, user_id, elemento_id)
            )''')
            await conn.execute('''CREATE TABLE IF NOT EXISTS runtime (
                key TEXT PRIMARY KEY, value TEXT
            )''')
            await conn.execute('''CREATE TABLE IF NOT EXISTS eventos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER, channel_id INTEGER, message_id INTEGER,
                author_id INTEGER, total INTEGER, peor_veredicto TEXT,
                detalle TEXT, created_at REAL
            )''')
            # La purga de infracciones y la consulta de /history filtran por fecha.
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_infrac_fecha ON infracciones(created_at)')
            await conn.execute('''CREATE INDEX IF NOT EXISTS idx_eventos_canal
                ON eventos(guild_id, channel_id, created_at)''')
        except Exception as e:
            log.error(f"No se pudieron crear las tablas de configuración: {e}. "
                      f"Se seguirá usando data.json.")
            self.config_migrada = False
            return

        await self._migrar_data_json(conn)

    async def _migrar_data_json(self, conn: aiosqlite.Connection) -> None:
        """Importa `data.json` una sola vez. Idempotente por diseño.

        Solo migra si `guild_config` está vacía. Si ya tiene filas, el proceso ya corrió y
        volver a lanzarse sobrescribiría los cambios hechos en SQLite con el estado viejo
        del JSON, que es justo lo que se quiere evitar. `data.json` no se borra: se deja
        como respaldo.
        """
        if getattr(self, "config_migrada", False):
            return
        try:
            async with conn.execute('SELECT COUNT(*) FROM guild_config') as cur:
                fila = await cur.fetchone()
            if fila and fila[0] > 0:
                self.config_migrada = True
                return

            if not os.path.exists(DATA_FILE):
                self.config_migrada = True
                return

            with open(DATA_FILE, "r", encoding="utf-8") as f:
                datos = json.loads(f.read())

            guilds = infrac = runtime = 0
            ahora = time.time()
            for gid, val in datos.items():
                if gid in ("__api_usage__", "__antispam__", "__global__"):
                    continue
                try:
                    guild_id = int(gid)
                except ValueError:
                    continue
                if not isinstance(val, dict):
                    continue
                # `infracciones_registradas` sale del blob y pasa a la tabla, donde se
                # puede purgar por fecha. Dejarlo dentro sería duplicar la verdad.
                registros = val.pop("infracciones_registradas", {}) or {}
                await conn.execute(
                    'INSERT OR REPLACE INTO guild_config (guild_id, data, updated_at) VALUES (?, ?, ?)',
                    (guild_id, json.dumps(val, ensure_ascii=False), ahora),
                )
                guilds += 1
                for uid, elementos in registros.items():
                    for elemento in elementos or []:
                        await conn.execute(
                            'INSERT OR IGNORE INTO infracciones '
                            '(guild_id, user_id, elemento_id, created_at) VALUES (?, ?, ?, ?)',
                            (guild_id, str(uid), elemento, ahora),
                        )
                        infrac += 1

            for clave in ("__api_usage__", "__antispam__"):
                if clave in datos:
                    await conn.execute(
                        'INSERT OR REPLACE INTO runtime (key, value) VALUES (?, ?)',
                        (clave, json.dumps(datos[clave], ensure_ascii=False)),
                    )
                    runtime += 1

            await conn.commit()
            self.config_migrada = True
            log.info(
                f"Migración data.json → SQLite: {guilds} servidores, {infrac} infracciones, "
                f"{runtime} bloques de estado. data.json se conserva como respaldo."
            )
        except Exception as e:
            # Un `rollback` no es opcional aquí. Sin él, una migración que falla a
            # medias deja una transacción de escritura abierta en esta conexión: el
            # bloqueo de escritura de SQLite se queda retenido y las escrituras
            # posteriores desde la misma conexión se encolan sin llegar a commitearse.
            # # es exactamente lo que hace que la caché "deje de funcionar" sin que
            # salte ninguna excepción.
            try:
                await conn.rollback()
            except Exception:
                pass
            self.config_migrada = False
            log.error(f"La migración de data.json falló ({e}). "
                      f"El bot seguirá funcionando con data.json.")

    async def _asegurar_columna_datos(self, conn: aiosqlite.Connection) -> None:
        """Añade la columna `datos` a una base creada antes del sistema de embeds.

        CREATE TABLE IF NOT EXISTS no altera una tabla existente, así que un
        analisis.db de una versión anterior se quedaría sin la columna y el render-on-read
        no tendría de dónde leer. Si la migración falla, el bot arranca igualmente y
        todo cae al comportamiento legacy (devolver el embed almacenado).
        """
        try:
            async with conn.execute('PRAGMA table_info(analisis)') as cur:
                columnas = {fila[1] for fila in await cur.fetchall()}
            if 'datos' not in columnas:
                await conn.execute('ALTER TABLE analisis ADD COLUMN datos TEXT')
                log.info("Migración aplicada: columna 'datos' añadida a la tabla analisis")
        except Exception as e:
            log.error(f"No se pudo añadir la columna 'datos' a analisis: {e}. "
                      f"Los embeds en caché pueden conservar el diseño anterior.")

    async def stop(self) -> None:
        for conn in self._conns:
            await conn.close()
        self._conns.clear()

    def _read_conn(self) -> aiosqlite.Connection:
        """Una conexión para leer, round-robin.

        El módulo de arriba usaba `self._size` (la constante) para el índice sobre
        `self._conns`, que solo crece dentro de `start()`. Si `start()` fallaba en la
        segunda conexión, `_conns` tenía menos elementos que `_size` y toda lectura era
        `IndexError`. Y los llamadores que lo tragan devolvían `[]`, es decir, "este
        usuario no tiene infracciones" cuando la verdad era "no se pudo consultar".

        Ahora se usa el tamaño real de la lista.
        """
        if not self._conns:
            raise RuntimeError("el pool de base de datos no está inicializado")
        conn = self._conns[self._rr % len(self._conns)]
        self._rr += 1
        return conn

    async def fetchone(self, sql: str, params: tuple = ()) -> Optional[tuple]:
        conn = self._read_conn()
        async with conn.execute(sql, params) as cursor:
            return await cursor.fetchone()

    async def execute(self, sql: str, params: tuple = ()) -> None:
        if not self._conns:
            raise RuntimeError("el pool de base de datos no está inicializado")
        async with self._write_lock:
            await self._conns[0].execute(sql, params)
            await self._conns[0].commit()


POOL = DatabasePool(DB_FILE)


async def init_db() -> None:
    await POOL.start()
    state.bot.db_pool = POOL


async def guardar_analisis_db(clave: str, tipo_analisis: str, resultado: str, *, embed: Optional[discord.Embed] = None, mal: int = 0, datos: Optional[dict] = None) -> None:
    """Guarda un análisis en SQLite.

    Si se pasan `datos` (lo mínimo para re-renderizar el embed) NO se guarda
    `embed_json`: el embed se reconstruye al leer con el diseño vigente, así que un
    cambio futuro de estilo no requiere reanalizar nada. Si no se pasan `datos` se
    guarda `embed` (comportamiento legacy, y lo que usan las entradas de metadatos).
    """
    now = time.time()
    expira = now + EXPIRACION.get(tipo_analisis, 7 * 24 * 3600)
    resultado_json = json.dumps({"tipo": resultado, "mal": mal})
    datos_json = json.dumps(datos, ensure_ascii=False) if datos is not None else None
    if datos is None and embed is not None:
        embed_json = json.dumps(embed.to_dict(), ensure_ascii=False)
    else:
        embed_json = None
    await POOL.execute(
        'INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira, datos) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (clave, tipo_analisis, resultado_json, embed_json, now, expira, datos_json)
    )
    log.debug(f"SQLITE SAVE → clave={clave} tipo={tipo_analisis} resultado={resultado} mal={mal} "
              f"render={'datos' if datos is not None else 'embed'} expira={expira-now:.0f}s")


async def obtener_analisis_db(clave: str) -> tuple[Optional[str], Optional[discord.Embed], int]:
    """Lee un análisis. El embed se RENDERIZA AL LEER desde `datos`, de modo que
    siempre sale con el diseño actual aunque el análisis se cacheara hace meses.

    Las filas antiguas (sin `datos`) siguen devolviendo su `embed_json` tal cual, con
    el diseño anterior. No se reanalizan: la transición no gasta cuota.
    """
    now = time.time()
    row = await POOL.fetchone(
        'SELECT tipo, resultado, embed_json, expira, datos FROM analisis WHERE clave = ?', (clave,)
    )
    if not row:
        log.debug(f"SQLITE MISS → clave={clave}")
        return None, None, 0

    tipo_analisis, resultado_json, embed_json, expira, datos_json = row
    if now >= expira:
        log.debug(f"SQLITE EXPIRED → clave={clave}")
        return None, None, 0

    tipo: Optional[str] = None
    mal = 0
    try:
        parsed = json.loads(resultado_json)
        tipo = parsed.get("tipo")
        mal = parsed.get("mal", 0)
    except Exception:
        tipo = resultado_json

    embed: Optional[discord.Embed] = None
    origen = "legacy"
    if datos_json:
        try:
            embed = renderizar_embed(tipo_analisis, json.loads(datos_json), mal)
            origen = "render"
        except Exception as e:
            log.error(f"Error renderizando el embed de {clave}: {e}")
    if embed is None and embed_json:
        try:
            embed = discord.Embed.from_dict(json.loads(embed_json))
        except Exception:
            pass
    log.debug(f"SQLITE HIT → clave={clave} tipo={tipo} mal={mal} origen={origen}")
    return tipo, embed, mal


async def obtener_datos_analisis(clave: str) -> Optional[dict]:
    """El `datos` crudo de una entrada, sin renderizar.

    `obtener_analisis_db` devuelve `(tipo, embed, mal)` y descarta el diccionario, así que
    quien necesite un dato que el embed no lleva (el enlace al informe de VT, los nombres
    de los antivirus) no lo puede recuperar. Aquí sí.

    Se recorre el `expira` igual que allí: una entrada caducada se trata como ausente.
    """
    row = await POOL.fetchone(
        'SELECT expira, datos FROM analisis WHERE clave = ?', (clave,)
    )
    if not row:
        return None
    expira, datos_json = row
    if time.time() >= expira or not datos_json:
        return None
    try:
        return json.loads(datos_json)
    except (TypeError, ValueError):
        return None


def renderizar_embed(tipo_analisis: str, datos: dict, mal: int) -> Optional[discord.Embed]:
    """Construye el embed de un análisis cacheado. Import diferido a propósito:
    ui.embed no depende de la capa de datos, pero importarlo arriba cargaría el
    módulo de presentación en el arranque del bot."""
    from ui.embed import resultado
    return resultado(tipo_analisis, datos, mal)


async def limpiar_db_expirados() -> None:
    ahora = time.time()
    while True:
        await POOL.execute(
            'DELETE FROM analisis WHERE clave IN (SELECT clave FROM analisis WHERE expira < ? LIMIT 1000)',
            (ahora,)
        )
        row = await POOL.fetchone(
            'SELECT COUNT(*) FROM analisis WHERE expira < ?', (ahora,)
        )
        if not row or row[0] == 0:
            break


async def obtener_hash_desde_metadatos(clave_metadatos: str) -> Optional[str]:
    now = time.time()
    row = await POOL.fetchone(
        'SELECT resultado, expira FROM analisis WHERE clave = ?', (clave_metadatos,)
    )
    if row:
        resultado, expira = row
        if now < expira:
            try:
                data = json.loads(resultado)
                hash_val = data.get("hash")
                if hash_val:
                    await set_cache_mem(clave_metadatos, json.dumps({"hash": hash_val}), datos={"hash": hash_val})
                    return hash_val
            except Exception:
                pass
    return None


async def guardar_metadatos_hash(clave_metadatos: str, file_hash: str) -> None:
    data = json.dumps({"hash": file_hash})
    now = time.time()
    expira = now + EXPIRACION.get("file", 30 * 24 * 3600)
    await POOL.execute(
        'INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira, datos) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (clave_metadatos, "metadata", data, None, now, expira, data)
    )

DATA_LOCK = asyncio.Lock()
_guardar_datos_pendiente: bool = False
_guardar_datos_task: Optional[asyncio.Task] = None
_GUARDAR_DEBOUNCE: float = 3.0


def _serializar_clave_antispam(k: object) -> str:
    """Clave de antispam a string JSON. Las tuplas (guild_id, user_id) se guardan como lista."""
    return json.dumps(list(k)) if isinstance(k, tuple) else str(k)


def _restaurar_claves_antispam(datos: dict) -> dict:
    """Invierte _serializar_clave_antispam.

    json.loads devuelve una LISTA, pero las claves en memoria son tuplas: sin volver a
    envolverlas en tuple, `(1, 2)` y `[1, 2]` serían claves distintas del dict y todo el
    historial de antispam se perdería al reiniciar el bot.
    """
    resultado = {}
    for k, v in datos.items():
        try:
            if k.startswith("["):
                partes = json.loads(k)
                clave = tuple(partes) if isinstance(partes, list) else partes
            else:
                clave = int(k)
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
        resultado[clave] = v
    return resultado


async def _flush_datos(incluir_guilds: bool = False) -> None:
    """Vuelca a `data.json`.

    **Ya no es la fuente de verdad.** La configuración de cada servidor vive en la tabla
    `guild_config` de SQLite y se escribe con `guardar_config_db`; este volcado deja de
    incluir los servidores salvo que se pida explícitamente.

    Qué queda aquí y por qué: los contadores de cuota, el historial de antispam y las
    estadísticas globales. Son estado de ejecución, se pierden sin más y son baratos de
    reescribir. Un respaldo, no un almacén.

    El parámetro `incluir_guilds` existe para poder generar un volcado de emergencia
    (`/settings` no lo usa). Por defecto es False porque incluirlo convertía cada
    guardado en una reescritura completa de la configuración de todos los servidores.

    El `include_runtime` que hubo antes ya no existe: los llamantes no lo pasaban y
    acababan borrando los contadores que el guardado horario acababa de escribir.
    """
    async with DATA_LOCK:
        data_to_save: dict = {}
        if incluir_guilds:
            data_to_save = {str(gid): val for gid, val in state.bot.guilds_data.items()
                            if gid not in ("__api_usage__", "__antispam__")}
        data_to_save["__api_usage__"] = {
            "total_requests": state.bot.vt_key_total_requests,
            "daily_usage": state.bot.vt_key_daily_usage,
            "sightengine": {
                "total_requests": state.bot.se_key_total_requests,
                "daily_usage": state.bot.se_key_daily_usage,
                "monthly_usage": state.bot.se_key_monthly_usage,
            }
        }
        data_to_save["__antispam__"] = {
            "user_scan_history": {_serializar_clave_antispam(k): v for k, v in state.bot.user_scan_history.items()},
            "antispam_scan": {_serializar_clave_antispam(k): v for k, v in state.bot.antispam_scan.items()},
        }
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(DATA_FILE) or ".")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data_to_save, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.replace(tmp, DATA_FILE)
            except OSError:
                if os.path.exists(DATA_FILE):
                    os.remove(DATA_FILE)
                os.rename(tmp, DATA_FILE)
        except Exception as e:
            # El temporal se queda en disco si el volcado falla a medias. Cada
            # `guardar_datos` que falle deja un fichero de 0 bytes en `core/`, y como
            # `json.dump` serializa `guilds_data` mientras otros tasks lo mutan, el
            # "dictionary changed size during iteration" no es hipotético.
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            log.error(f"Error al guardar datos: {e}")

async def guardar_datos(inmediato: bool = False, incluir_guilds: bool = False) -> None:
    global _guardar_datos_pendiente, _guardar_datos_task
    if inmediato:
        if _guardar_datos_task and not _guardar_datos_task.done():
            _guardar_datos_task.cancel()
            try:
                await _guardar_datos_task
            except asyncio.CancelledError:
                pass
        _guardar_datos_pendiente = False
        await _flush_datos(incluir_guilds=incluir_guilds)
        return
    if not _guardar_datos_pendiente:
        _guardar_datos_pendiente = True
        async def _debounced() -> None:
            global _guardar_datos_pendiente, _guardar_datos_task
            await asyncio.sleep(_GUARDAR_DEBOUNCE)
            if _guardar_datos_pendiente:
                _guardar_datos_pendiente = False
                await _flush_datos(incluir_guilds=incluir_guilds)
        _guardar_datos_task = asyncio.create_task(_debounced())

async def sincronizar_config_sqlite() -> int:
    """Vuelca en SQLite los guilds que solo estaban en `data.json`.

    Sin esto, un guild nuevo se creaba en memoria al usarse por primera vez y su
    config solo llegaba a SQLite cuando alguien cambiaba un ajuste. En SQLite, ese
    `data.json` es un volcado, no una fuente: si se perdiera, ese guild se perdía con él.
    Best effort: si la base no está lista, se salta sin romper el arranque.
    """
    volcados = 0
    try:
        existentes = set(await listar_guilds_db())
    except Exception:
        return 0
    for guild_id, config in list(state.bot.guilds_data.items()):
        if guild_id in existentes or guild_id == "__global__" or not isinstance(config, dict):
            continue
        try:
            await guardar_config_db(guild_id, config)
            volcados += 1
        except Exception as e:
            log.debug(f"No se pudo volcar el guild {guild_id} a SQLite: {type(e).__name__}")
    if volcados:
        log.info(f"{volcados} configuracion(es) volcadas de data.json a SQLite")
    return volcados


async def cargar_datos() -> None:
    def _read_json():
        if not os.path.exists(DATA_FILE):
            return {}
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.loads(f.read())
    try:
        data = await asyncio.to_thread(_read_json)
        api_usage = data.get("__api_usage__", {})
        state.bot.guilds_data = {}
        antispam_data = data.get("__antispam__", {})

        # La configuración se lee de SQLite, que es la fuente de verdad. `data.json`
        # solo se usa si la tabla está vacía, es decir, la primera vez tras migrar.
        #
        # Antes esto leía siempre del JSON. Con la base caída o corrupta, `cargar_datos`
        # capturaba la excepción, `guilds_data` quedaba vacío y **cada servidor volvía
        # a los defaults en silencio**, teniendo la configuración intacta a un fichero
        # de distancia.
        desde_sqlite = await _cargar_guilds_desde_sqlite()
        origen = "SQLite" if desde_sqlite else "data.json"
        if not desde_sqlite:
            log.info("Sin configuración en SQLite; se usa data.json como origen.")
        for gid, val in data.items():
            if gid == "__global__":
                state.bot.guilds_data["__global__"] = val
            elif gid in ("__api_usage__", "__antispam__"):
                continue
            else:
                try:
                    guild_id = int(gid)
                except ValueError:
                    continue
                if isinstance(val, dict):
                    defaults = {
                        "silent_mode": True,
                        "strict_mode": True,
                        "auto_scan_enabled": True,
                        "log_channel_id": None,
                        "whitelist": list(DOMINIOS_PROTEGIDOS),
                        "infracciones": {},
                        "infracciones_registradas": {},
                    }
                    for key, default_val in defaults.items():
                        val.setdefault(key, default_val)
                    val.pop("stats", None)
                    state.bot.guilds_data[guild_id] = val
        state.bot.vt_key_total_requests = api_usage.get("total_requests", {})
        state.bot.vt_key_daily_usage = api_usage.get("daily_usage", {})
        if not hasattr(state.bot, 'vt_key_usage') or not state.bot.vt_key_usage:
            state.bot.vt_key_usage = {}
        se_data = api_usage.get("sightengine", {})
        state.bot.se_key_total_requests = se_data.get("total_requests", {})
        state.bot.se_key_daily_usage = se_data.get("daily_usage", {})
        # El mensual es el que manda en el plan gratuito. Antes no se guardaba porque no se
        # comprobaba: un reinicio del bot lo ponía a cero y el mes se reiniciaba solo.
        state.bot.se_key_monthly_usage = se_data.get("monthly_usage", {})
        if not hasattr(state.bot, 'se_key_usage') or not state.bot.se_key_usage:
            state.bot.se_key_usage = {}
        state.bot.user_scan_history = _restaurar_claves_antispam(antispam_data.get("user_scan_history", {}))
        antispam_scan = _restaurar_claves_antispam(antispam_data.get("antispam_scan", {}))
        state.bot.antispam_scan = antispam_scan
        if "__global__" not in state.bot.guilds_data:
            # Antes esta línea traía su propio dict de 6 claves, mientras `guild_config`
            # usaba uno de 9. Las que faltaban eran `restringidos`, `phishing` e
            # `ignorados`, así que un arranque limpio producía unas estadísticas sin
            # esas tres categorías: el bot las contaba y `/stats` no las enseñaba nunca.
            #
            # Dos definiciones de lo mismo en dos sitios, y el ciclo de imports impide
            # importarlas entre sí (`guild_config` importa a este módulo). La fuente
            # única vive en `core.config`.
            state.bot.guilds_data["__global__"] = stats_vacias()
            await guardar_datos(inmediato=True)
        # Si la configuración vino del JSON, se vuelca a SQLite para que la siguiente
        # arranque ya lea de la tabla. Si vino de SQLite no hay nada que hacer.
        if not desde_sqlite:
            await sincronizar_config_sqlite()
        log.info(f"Configuración de {len(state.bot.guilds_data) - 1} servidor(es) desde {origen}.")
    except Exception as e:
        log.error(f"Error al cargar datos: {e}")


# --- Configuración e infracciones en SQLite --------------------------------
#
# La escritura de `guild_config` es deliberadamente poco fina: un `INSERT OR REPLACE`
# por guild. Reescribir un blob de unos pocos cientos de bytes es más barato y simple que
# diffing columna a columna, y evita que dos escrituras simultáneas se entrelacen dejando
# campos a medias. El JSON se guarda entero.

async def guardar_config_db(guild_id: int, config: dict) -> None:
    """Persiste la configuración de un guild. Lanza si falla: aquí sí es crítico.

    A diferencia del registro de eventos, perder esta escritura significa perder ajustes
    que un administrador acaba de hacer, así que no se traga la excepción.
    """
    # Las infracciones viven en su tabla; meterlas en el blob las duplicaría y dejaría
    # dos fuentes de verdad para lo mismo.
    limpio = {k: v for k, v in config.items() if k != "infracciones_registradas"}
    await POOL.execute(
        'INSERT OR REPLACE INTO guild_config (guild_id, data, updated_at) VALUES (?, ?, ?)',
        (guild_id, json.dumps(limpio, ensure_ascii=False), time.time()),
    )


async def obtener_config_db(guild_id: int) -> Optional[dict]:
    """Config de un guild, o None si no está en SQLite (aún no migrada, o no existe)."""
    row = await POOL.fetchone('SELECT data FROM guild_config WHERE guild_id = ?', (guild_id,))
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        log.error(f"Config ilegible en SQLite para el guild {guild_id}; se ignora.")
        return None


async def listar_guilds_db() -> list[int]:
    try:
        async with POOL._read_conn().execute('SELECT guild_id FROM guild_config') as cur:
            return [f[0] for f in await cur.fetchall()]
    except Exception as e:
        log.debug(f"No se pudieron listar los guilds: {type(e).__name__}")
        return []


async def registrar_infraccion_db(
    guild_id: int, user_id: int, elemento_id: str, creada: Optional[float] = None
) -> bool:
    """Registra una infracción. Devuelve True si es nueva, False si ya estaba.

    La clave primaria compuesta hace la deduplicación en la base, no en memoria: con el
    modelo anterior la lista vivía en el JSON y crecía sin límite en cada guild.

    `INSERT OR IGNORE` no lanza si la fila existe, así que el éxito no se deduce del
    hecho de que no haya error: hay que mirar `rowcount`. Devolver True siempre hacía que
    cada reaparición de un elemento contara como infracción nueva.
    """
    try:
        async with POOL._write_lock:
            cur = await POOL._conns[0].execute(
                'INSERT OR IGNORE INTO infracciones (guild_id, user_id, elemento_id, created_at) '
                'VALUES (?, ?, ?, ?)',
                (guild_id, str(user_id), elemento_id, creada or time.time()),
            )
            await POOL._conns[0].commit()
            return bool(cur.rowcount)
    except Exception as e:
        # Se relanza en forma de resultado, no se traga: quien llama lo usa para caer al
        # respaldo en memoria. Tragarse el error aquí hacía que un INSERT fallido con un
        # COUNT funcionando devolviera el recuento sin cambios, y nadie viera nada en el
        # log más allá de una línea: la infracción se perdía en silencio.
        log.error(f"No se pudo registrar la infracción: {e}")
        raise


async def contar_infracciones_db(guild_id: int, user_id: int) -> int:
    row = await POOL.fetchone(
        'SELECT COUNT(*) FROM infracciones WHERE guild_id = ? AND user_id = ?',
        (guild_id, str(user_id)),
    )
    return int(row[0]) if row else 0


async def infracciones_de_db(guild_id: int, user_id: int) -> list[str]:
    """Elementos ya registrados por un usuario. Sirve para no volver a contar."""
    try:
        async with POOL._read_conn().execute(
            'SELECT elemento_id FROM infracciones WHERE guild_id = ? AND user_id = ?',
            (guild_id, str(user_id)),
        ) as cur:
            return [f[0] for f in await cur.fetchall()]
    except Exception as e:
        log.debug(f"No se pudieron leer las infracciones: {type(e).__name__}")
        return []


async def borrar_infraccion_db(guild_id: int, user_id: int, elemento_id: str) -> bool:
    """Descuenta una infracción. Es lo que hace el botón "Ignorar" del log de amenazas.

    Antes restaba un número de una lista en el JSON, lo que dejaba el contador y la lista
    permanentemente desincronizados. Aquí es un `DELETE` real.
    """
    try:
        async with POOL._write_lock:
            await POOL._conns[0].execute(
                'DELETE FROM infracciones WHERE guild_id = ? AND user_id = ? AND elemento_id = ?',
                (guild_id, str(user_id), elemento_id),
            )
            await POOL._conns[0].commit()
        return True
    except Exception as e:
        log.error(f"No se pudo borrar la infracción: {e}")
        return False


async def purgar_infracciones(dias: int = 90) -> int:
    """Borra infracciones más antiguas que `dias`. Lo llama el cron de limpieza.

    Sin esto la tabla crece para siempre: cada elemento distinto que alguien publica
    añade una fila, y nadie las borra.
    """
    try:
        async with POOL._write_lock:
            cur = await POOL._conns[0].execute(
                'DELETE FROM infracciones WHERE created_at < ?', (time.time() - dias * 86400,)
            )
            await POOL._conns[0].commit()
            borradas = cur.rowcount or 0
        if borradas:
            log.info(f"Purgadas {borradas} infracciones de más de {dias} días")
        return borradas
    except Exception as e:
        log.debug(f"No se pudieron purgar las infracciones: {type(e).__name__}")
        return 0


# --- Eventos para /history ---------------------------------------------------

async def registrar_evento(
    guild_id: int,
    channel_id: int,
    message_id: int,
    author_id: int,
    total: int,
    peor_veredicto: str,
    detalle: str = "",
) -> None:
    """Guarda un análisis para `/history`. Nunca lanza.

    El análisis del mensaje ya se ha hecho y publicado cuando esto corre: perder un
    registro informativo no puede justificar tumbar ese resultado.
    """
    try:
        await POOL.execute(
            """INSERT INTO eventos
               (guild_id, channel_id, message_id, author_id, total, peor_veredicto, detalle, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (guild_id, channel_id, message_id, author_id, total, peor_veredicto, detalle, time.time()),
        )
    except Exception as e:
        log.debug(f"No se pudo registrar el evento para /history: {type(e).__name__}")


async def obtener_eventos(
    guild_id: int,
    channel_id: Optional[int] = None,
    author_id: Optional[int] = None,
    limite: int = 10,
) -> list[dict]:
    """Últimos análisis de un canal (o de todo el servidor). Para `/history`."""
    condiciones = ["guild_id = ?"]
    params: list = [guild_id]
    if channel_id:
        condiciones.append("channel_id = ?")
        params.append(channel_id)
    if author_id:
        condiciones.append("author_id = ?")
        params.append(author_id)
    params.append(max(1, min(limite, 25)))
    try:
        async with POOL._read_conn().execute(
            f"""SELECT channel_id, message_id, author_id, total, peor_veredicto, detalle, created_at
                FROM eventos WHERE {" AND ".join(condiciones)}
                ORDER BY created_at DESC LIMIT ?""",
            tuple(params),
        ) as cur:
            filas = await cur.fetchall()
    except Exception as e:
        log.debug(f"No se pudieron leer los eventos: {type(e).__name__}")
        return []
    return [
        {
            "channel_id": f[0], "message_id": f[1], "author_id": f[2], "total": f[3],
            "veredicto": f[4], "detalle": f[5] or "", "created_at": f[6],
        }
        for f in filas
    ]


async def purgar_eventos(dias: int = 30) -> int:
    """Borra eventos más antiguos que `dias`. Lo llama el cron de limpieza."""
    try:
        async with POOL._write_lock:
            cur = await POOL._conns[0].execute(
                'DELETE FROM eventos WHERE created_at < ?', (time.time() - dias * 86400,)
            )
            await POOL._conns[0].commit()
            return cur.rowcount or 0
    except Exception as e:
        log.debug(f"No se pudieron purgar los eventos: {type(e).__name__}")
        return 0


async def borrar_guild_db(guild_id: int) -> None:
    """Borra todo lo que SQLite guardaba de un servidor del que el bot salió.

    Sin esto, config, whitelist e infracciones (hasta 90 días) y eventos (hasta 30)
    siguen en la base. Si alguien re-invita al bot, `/usercheck` muestra infracciones del
    periodo en que estuvo fuera y la whitelist borrada revive. Mejor impedirlo aquí que
    confiar en que la purga por fecha lo cubra: 90 días es mucho.
    """
    try:
        async with POOL._write_lock:
            for tabla in ("guild_config", "infracciones", "eventos"):
                await POOL._conns[0].execute(f"DELETE FROM {tabla} WHERE guild_id = ?", (guild_id,))
            await POOL._conns[0].commit()
    except Exception as e:
        log.debug(f"No se pudo limpiar SQLite del guild {guild_id}: {type(e).__name__}")


async def _cargar_guilds_desde_sqlite() -> int:
    """Rellena `state.bot.guilds_data` con la tabla `guild_config`. Devuelve cuántos.

    Si la tabla no existe, está vacía o la base falla, devuelve 0 y quien llama usa
    `data.json`. Que la base no esté disponible se traduzca en "uso el respaldo", no en
    "este usuario no tiene infracciones": convertir un fallo de infraestructura en un
    dato vacío es el peor error posible en un sistema de moderación, porque parece que
    todo funciona.
    """
    try:
        async with POOL._read_conn().execute('SELECT guild_id, data FROM guild_config') as cur:
            filas = await cur.fetchall()
    except Exception as e:
        log.warning(
            f"No se pudo leer la configuración de SQLite ({type(e).__name__}: {e}). "
            f"Se usará data.json como respaldo."
        )
        return 0

    cargados = 0
    for guild_id, bruto in filas:
        try:
            val = json.loads(bruto)
        except (TypeError, ValueError):
            log.error(f"Config ilegible en SQLite para el guild {guild_id}; se omite.")
            continue
        if isinstance(val, dict):
            state.bot.guilds_data[guild_id] = val
            cargados += 1
    return cargados
