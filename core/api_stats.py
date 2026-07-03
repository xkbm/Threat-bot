import asyncio
import os
import time
import logging
from typing import Optional

from core import state
from core.guild_config import obtener_stats_globales

log = logging.getLogger("api_stats")

STATS_API_URL: str = os.getenv("STATS_API_URL", "https://tbot-dc.vercel.app")
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
    token_ok = bool(STATS_TOKEN and STATS_TOKEN.strip())
    log.info(f"[STATS] Iniciando push task | STATS_TOKEN={'configurado' if token_ok else 'NO CONFIGURADO'} | URL={STATS_API_URL}")
    if not token_ok:
        log.warning("[STATS] STATS_TOKEN no configurado — push de stats deshabilitado")
        return

    while True:
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
            log.info(f"[STATS] Push → total={payload['total']} seguros={payload['seguros']} maliciosos={payload['maliciosos']} nsfw={payload['nsfw']} errores={payload['errores']}")
            async with state.bot.session.post(
                f"{STATS_API_URL}/api/stats",
                json=payload,
                headers={"Authorization": f"Bearer {STATS_TOKEN}"},
                timeout=10,
            ) as resp:
                body = await resp.text()
                if resp.status == 200:
                    log.info(f"[STATS] Push OK (status 200)")
                else:
                    log.warning(f"[STATS] Push falló: status={resp.status} body={body}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.warning(f"[STATS] Push error: {type(e).__name__}: {e}")
        await asyncio.sleep(10)  # testing: cada 10s
