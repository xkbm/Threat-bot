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
from core.config import DB_FILE, DATA_FILE, EXPIRACION, DOMINIOS_PROTEGIDOS
from discord.ext import commands

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
                clave TEXT PRIMARY KEY, tipo TEXT, resultado TEXT, embed_json TEXT, timestamp REAL, expira REAL
            )''')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_expira ON analisis(expira)')
            await conn.commit()
            self._conns.append(conn)

    async def stop(self) -> None:
        for conn in self._conns:
            await conn.close()
        self._conns.clear()

    def _read_conn(self) -> aiosqlite.Connection:
        conn = self._conns[self._rr % self._size]
        self._rr += 1
        return conn

    async def fetchone(self, sql: str, params: tuple = ()) -> Optional[tuple]:
        conn = self._read_conn()
        async with conn.execute(sql, params) as cursor:
            return await cursor.fetchone()

    async def execute(self, sql: str, params: tuple = ()) -> None:
        async with self._write_lock:
            await self._conns[0].execute(sql, params)
            await self._conns[0].commit()


POOL = DatabasePool(DB_FILE)


async def init_db() -> None:
    await POOL.start()
    state.bot.db_pool = POOL


async def guardar_analisis_db(clave: str, tipo_analisis: str, resultado: str, embed: Optional[discord.Embed], mal: int = 0) -> None:
    now = time.time()
    expira = now + EXPIRACION.get(tipo_analisis, 7 * 24 * 3600)
    embed_dict = embed.to_dict() if embed else None
    embed_json = json.dumps(embed_dict) if embed_dict else None
    resultado_json = json.dumps({"tipo": resultado, "mal": mal})
    await POOL.execute(
        'INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira) VALUES (?, ?, ?, ?, ?, ?)',
        (clave, tipo_analisis, resultado_json, embed_json, now, expira)
    )
    log.debug(f"SQLITE SAVE → clave={clave} tipo={tipo_analisis} resultado={resultado} mal={mal} expira={expira-now:.0f}s")


async def obtener_analisis_db(clave: str) -> tuple[Optional[str], Optional[discord.Embed], int]:
    now = time.time()
    row = await POOL.fetchone(
        'SELECT resultado, embed_json, expira FROM analisis WHERE clave = ?', (clave,)
    )
    if row:
        resultado_json, embed_json, expira = row
        if now < expira:
            embed: Optional[discord.Embed] = None
            if embed_json:
                try:
                    embed_dict = json.loads(embed_json)
                    embed = discord.Embed.from_dict(embed_dict)
                except Exception:
                    pass
            try:
                data = json.loads(resultado_json)
                tipo = data.get("tipo")
                mal = data.get("mal", 0)
            except Exception:
                tipo = resultado_json
                mal = 0
            log.debug(f"SQLITE HIT → clave={clave} tipo={tipo} mal={mal}")
            return tipo, embed, mal
        log.debug(f"SQLITE EXPIRED → clave={clave}")
    log.debug(f"SQLITE MISS → clave={clave}")
    return None, None, 0


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
                    dummy = discord.Embed(title="Meta")
                    await set_cache_mem(clave_metadatos, json.dumps({"hash": hash_val}), dummy, 0)
                return hash_val
            except Exception:
                pass
    return None


async def guardar_metadatos_hash(clave_metadatos: str, file_hash: str) -> None:
    data = json.dumps({"hash": file_hash})
    now = time.time()
    expira = now + EXPIRACION.get("file", 30 * 24 * 3600)
    await POOL.execute(
        'INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira) VALUES (?, ?, ?, ?, ?, ?)',
        (clave_metadatos, "metadata", data, None, now, expira)
    )

DATA_LOCK = asyncio.Lock()
_guardar_datos_pendiente: bool = False
_guardar_datos_task: Optional[asyncio.Task] = None
_GUARDAR_DEBOUNCE: float = 3.0

async def _flush_datos(include_runtime: bool = False) -> None:
    async with DATA_LOCK:
        data_to_save = {str(gid): val for gid, val in state.bot.guilds_data.items()
                        if gid not in ("__api_usage__", "__antispam__")}
        if include_runtime:
            data_to_save["__api_usage__"] = {
                "total_requests": state.bot.vt_key_total_requests,
                "daily_usage": state.bot.vt_key_daily_usage,
                "sightengine": {
                    "total_requests": state.bot.se_key_total_requests,
                    "daily_usage": state.bot.se_key_daily_usage,
                }
            }
            data_to_save["__antispam__"] = {
                "user_scan_history": {json.dumps(k) if isinstance(k, tuple) else str(k): v for k, v in state.bot.user_scan_history.items()},
                "antispam_scan": {json.dumps(k) if isinstance(k, tuple) else str(k): v for k, v in state.bot.antispam_scan.items()},
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
            log.error(f"Error al guardar datos: {e}")

async def guardar_datos(inmediato: bool = False, include_runtime: bool = False) -> None:
    global _guardar_datos_pendiente, _guardar_datos_task
    if inmediato:
        if _guardar_datos_task and not _guardar_datos_task.done():
            _guardar_datos_task.cancel()
            try:
                await _guardar_datos_task
            except asyncio.CancelledError:
                pass
        _guardar_datos_pendiente = False
        await _flush_datos(include_runtime=include_runtime)
        return
    if not _guardar_datos_pendiente:
        _guardar_datos_pendiente = True
        async def _debounced() -> None:
            global _guardar_datos_pendiente, _guardar_datos_task
            await asyncio.sleep(_GUARDAR_DEBOUNCE)
            if _guardar_datos_pendiente:
                _guardar_datos_pendiente = False
                await _flush_datos()
        _guardar_datos_task = asyncio.create_task(_debounced())

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
                        "silent_mode": False,
                        "strict_mode": False,
                        "auto_scan_enabled": True,
                        "log_channel_id": None,
                        "whitelist": list(DOMINIOS_PROTEGIDOS),
                        "infracciones": {},
                        "infracciones_registradas": {},
                    }
                    for key, default_val in defaults.items():
                        val.setdefault(key, default_val)
                    state.bot.guilds_data[guild_id] = val
        state.bot.vt_key_total_requests = api_usage.get("total_requests", {})
        state.bot.vt_key_daily_usage = api_usage.get("daily_usage", {})
        if not hasattr(state.bot, 'vt_key_usage') or not state.bot.vt_key_usage:
            state.bot.vt_key_usage = {}
        se_data = api_usage.get("sightengine", {})
        state.bot.se_key_total_requests = se_data.get("total_requests", {})
        state.bot.se_key_daily_usage = se_data.get("daily_usage", {})
        if not hasattr(state.bot, 'se_key_usage') or not state.bot.se_key_usage:
            state.bot.se_key_usage = {}
        user_scan_history = {}
        for k, v in antispam_data.get("user_scan_history", {}).items():
            try:
                parsed = json.loads(k) if k.startswith("[") else int(k)
                user_scan_history[parsed] = v
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
        state.bot.user_scan_history = user_scan_history
        antispam_scan = {}
        for k, v in antispam_data.get("antispam_scan", {}).items():
            try:
                parsed = json.loads(k) if k.startswith("[") else int(k)
                antispam_scan[parsed] = v
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
        state.bot.antispam_scan = antispam_scan
    except Exception as e:
        log.error(f"Error al cargar datos: {e}")
