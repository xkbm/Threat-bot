import json
import os
import time
import aiosqlite
import discord
import asyncio
from core import state
from core.config import DB_FILE, DATA_FILE, EXPIRACION

DB_LOCK = asyncio.Lock()

async def init_db():
    state.bot.db = await aiosqlite.connect(DB_FILE)
    state.bot.db_lock = DB_LOCK
    await state.bot.db.execute('''CREATE TABLE IF NOT EXISTS analisis (
        clave TEXT PRIMARY KEY, tipo TEXT, resultado TEXT, embed_json TEXT, timestamp REAL, expira REAL
    )''')
    await state.bot.db.execute('CREATE INDEX IF NOT EXISTS idx_expira ON analisis(expira)')
    await state.bot.db.commit()

async def close_db():
    if state.bot.db:
        await state.bot.db.close()

async def guardar_analisis_db(clave, tipo_analisis, resultado, embed, mal=0):
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

async def obtener_analisis_db(clave):
    async with state.bot.db_lock:
        now = time.time()
        async with state.bot.db.execute(
            'SELECT resultado, embed_json, expira FROM analisis WHERE clave = ?', (clave,)
        ) as cursor:
            row = await cursor.fetchone()
    if row:
        resultado_json, embed_json, expira = row
        if now < expira:
            embed = None
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
            return tipo, embed, mal
    return None, None, 0

async def limpiar_db_expirados():
    async with state.bot.db_lock:
        await state.bot.db.execute('DELETE FROM analisis WHERE expira < ?', (time.time(),))
        await state.bot.db.commit()

async def obtener_hash_desde_metadatos(clave_metadatos):
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

async def guardar_metadatos_hash(clave_metadatos, file_hash):
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

def cargar_datos():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            api_usage = data.get("__api_usage__", {})
            state.bot.guilds_data = {}
            for gid, val in data.items():
                if gid == "__global__":
                    state.bot.guilds_data["__global__"] = val
                elif gid == "__api_usage__":
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
        except Exception as e:
            print(f"Error al cargar datos: {e}")
            state.bot.guilds_data = {}

async def guardar_datos():
    async with DATA_LOCK:
        state.bot.guilds_data["__api_usage__"] = {
            "total_requests": state.bot.vt_key_total_requests,
            "daily_usage": state.bot.vt_key_daily_usage,
            "sightengine": {
                "total_requests": state.bot.se_key_total_requests,
                "daily_usage": state.bot.se_key_daily_usage,
            }
        }
        data_to_save = {str(gid): val for gid, val in state.bot.guilds_data.items()}
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(data_to_save, f, indent=4)
        except Exception as e:
            print(f"Error al guardar datos: {e}")
