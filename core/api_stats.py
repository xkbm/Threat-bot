import asyncio
import os
import time
import logging
from typing import Optional

from core import state
from core.guild_config import obtener_stats_globales

log = logging.getLogger("api_stats")

STATS_API_URL: str = os.getenv("STATS_API_URL", "https://threat-bot-discord.vercel.app")
STATS_TOKEN: Optional[str] = os.getenv("STATS_TOKEN")


def _calcular_uso_vt_minuto() -> float:
    ahora = time.time()
    total = 0
    for key in state.bot.vt_key_total_requests:
        total += len([t for t in state.bot.vt_key_usage.get(key, []) if ahora - t <= 60])
    limit = state.bot.vt_key_count * 4
    if limit == 0:
        return 0.0
    return min((total / limit) * 100, 100)


def _calcular_uso_vt_diario() -> float:
    hoy = time.strftime("%Y-%m-%d", time.gmtime())
    total = 0
    for key in state.bot.vt_key_daily_usage:
        data = state.bot.vt_key_daily_usage.get(key, {"count": 0, "date": ""})
        if data["date"] == hoy:
            total += data["count"]
    limit = state.bot.vt_key_count * 500
    if limit == 0:
        return 0.0
    return min((total / limit) * 100, 100)


def _calcular_uso_se_diario() -> float:
    hoy = time.strftime("%Y-%m-%d", time.gmtime())
    total = 0
    for key in state.bot.se_key_daily_usage:
        data = state.bot.se_key_daily_usage.get(key, {"count": 0, "date": ""})
        if data["date"] == hoy:
            total += data["count"]
    limit = state.bot.se_key_count * 500
    if limit == 0:
        return 0.0
    return min((total / limit) * 100, 100)


async def enviar_stats_a_web() -> None:
    if not STATS_TOKEN:
        log.debug("STATS_TOKEN no configurado — push de stats deshabilitado")
        return

    while True:
        await asyncio.sleep(300)
        try:
            stats = obtener_stats_globales()
            payload = {
                "total": stats.get("total_analisis", 0),
                "seguros": stats.get("seguros", 0),
                "maliciosos": stats.get("maliciosos", 0),
                "errores": stats.get("errores", 0),
                "nsfw": stats.get("nsfw", 0),
                "vt_usage_minuto": round(_calcular_uso_vt_minuto(), 1),
                "vt_usage_diario": round(_calcular_uso_vt_diario(), 1),
                "se_usage_diario": round(_calcular_uso_se_diario(), 1),
                "timestamp": time.time(),
            }
            async with state.bot.session.post(
                f"{STATS_API_URL}/api/stats",
                json=payload,
                headers={"Authorization": f"Bearer {STATS_TOKEN}"},
                timeout=10,
            ) as resp:
                if resp.status == 200:
                    log.debug("Stats push OK")
                else:
                    log.warning(f"Stats push falló: status={resp.status}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.warning(f"Stats push error: {e}")
