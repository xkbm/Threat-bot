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
from core.config import DB_FILE, DATA_FILE, EXPIRACION
from discord.ext import commands

log = logging.getLogger("db")

DB_LOCK = asyncio.Lock()

async def init_db() -> None:
    if state.bot is None:
        return
    state.bot.db = await aiosqlite.connect(DB_FILE)
    state.bot.db_lock = DB_LOCK
    await state.bot.db.execute('''CREATE TABLE IF NOT EXISTS analisis (
        clave TEXT PRIMARY KEY, tipo TEXT, resultado TEXT, embed_json TEXT, timestamp REAL, expira REAL
    )''')
    await state.bot.db.execute('CREATE INDEX IF NOT EXISTS idx_expira ON analisis(expira)')
    await state.bot.db.commit()

async def close_db() -> None:
    if state.bot and state.bot.db:
        await state.bot.db.close()

async def guardar_analisis_db(clave: str, tipo_analisis: str, resultado: str, embed: Optional[discord.Embed], mal: int = 0) -> None:
    async with state.bot.db_lock:
        now = time.time()
        expira = now + EXPIRACION.get(tipo_analisis, 7 * 24 * 3600)
        embed_dict = embed.to_dict() if embed else None
        embed_json = json.dumps(embed_dict) if embed_dict else None
        resultado_json = json.dumps({"tipo": resultado, "mal": mal})
        await state.bot.db.execute(
            'INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira) VALUES (?, ?, ?, ?, ?, ?)',
            (clave, tipo_analisis, resultado_json, embed_json, now, expira)
        )
        await state.bot.db.commit()
        log.debug(f"SQLITE SAVE → clave={clave} tipo={tipo_analisis} resultado={resultado} mal={mal} expira={expira-now:.0f}s")

async def obtener_analisis_db(clave: str) -> tuple[Optional[str], Optional[discord.Embed], int]:
    async with state.bot.db_lock:
        now = time.time()
        async with state.bot.db.execute(
            'SELECT resultado, embed_json, expira FROM analisis WHERE clave = ?', (clave,)
        ) as cursor:
            row = await cursor.fetchone()
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
    async with state.bot.db_lock:
        await state.bot.db.execute('DELETE FROM analisis WHERE expira < ?', (time.time(),))
        await state.bot.db.commit()

async def obtener_hash_desde_metadatos(clave_metadatos: str) -> Optional[str]:
    async with state.bot.db_lock:
        now = time.time()
        async with state.bot.db.execute(
            'SELECT resultado, expira FROM analisis WHERE clave = ?', (clave_metadatos,)
        ) as cursor:
            row = await cursor.fetchone()
    if row:
        resultado, expira = row
        if now < expira:
            try:
                data = json.loads(resultado)
                return data.get("hash")
            except Exception:
                pass
    return None

async def guardar_metadatos_hash(clave_metadatos: str, file_hash: str) -> None:
    data = json.dumps({"hash": file_hash})
    async with state.bot.db_lock:
        now = time.time()
        expira = now + EXPIRACION.get("file", 30 * 24 * 3600)
        await state.bot.db.execute(
            'INSERT OR REPLACE INTO analisis (clave, tipo, resultado, embed_json, timestamp, expira) VALUES (?, ?, ?, ?, ?, ?)',
            (clave_metadatos, "metadata", data, None, now, expira)
        )
        await state.bot.db.commit()

DATA_LOCK = asyncio.Lock()
_guardar_datos_pendiente: bool = False
_guardar_datos_task: Optional[asyncio.Task] = None
_GUARDAR_DEBOUNCE: float = 3.0

async def _flush_datos() -> None:
    async with DATA_LOCK:
        state.bot.guilds_data["__api_usage__"] = {
            "total_requests": state.bot.vt_key_total_requests,
            "daily_usage": state.bot.vt_key_daily_usage,
            "sightengine": {
                "total_requests": state.bot.se_key_total_requests,
                "daily_usage": state.bot.se_key_daily_usage,
            }
        }
        state.bot.guilds_data["__antispam__"] = {
            "user_scan_history": {str(k): v for k, v in state.bot.user_scan_history.items()},
            "antispam_scan": {str(k): v for k, v in state.bot.antispam_scan.items()},
        }
        data_to_save = {str(gid): val for gid, val in state.bot.guilds_data.items()}
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(DATA_FILE) or ".")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data_to_save, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, DATA_FILE)
        except Exception as e:
            log.error(f"Error al guardar datos: {e}")

async def guardar_datos(inmediato: bool = False) -> None:
    global _guardar_datos_pendiente, _guardar_datos_task
    if inmediato:
        if _guardar_datos_task and not _guardar_datos_task.done():
            _guardar_datos_task.cancel()
        _guardar_datos_pendiente = False
        await _flush_datos()
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
    _read_json = lambda: json.loads(open(DATA_FILE, "r", encoding="utf-8").read()) if os.path.exists(DATA_FILE) else {}
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
                state.bot.guilds_data[int(gid)] = val
        state.bot.vt_key_total_requests = api_usage.get("total_requests", {})
        state.bot.vt_key_daily_usage = api_usage.get("daily_usage", {})
        if not hasattr(state.bot, 'vt_key_usage') or not state.bot.vt_key_usage:
            state.bot.vt_key_usage = {}
        se_data = api_usage.get("sightengine", {})
        state.bot.se_key_total_requests = se_data.get("total_requests", {})
        state.bot.se_key_daily_usage = se_data.get("daily_usage", {})
        if not hasattr(state.bot, 'se_key_usage') or not state.bot.se_key_usage:
            state.bot.se_key_usage = {}
        state.bot.user_scan_history = {int(k): v for k, v in antispam_data.get("user_scan_history", {}).items()}
        state.bot.antispam_scan = {int(k): v for k, v in antispam_data.get("antispam_scan", {}).items()}
    except Exception as e:
        log.error(f"Error al cargar datos: {e}")
        state.bot.guilds_data = {}
