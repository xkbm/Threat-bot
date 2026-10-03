#!/usr/bin/env python3
"""Reconstruye las estadísticas de `/stats` desde la tabla `eventos` de SQLite.

POR QUÉ EXISTE
--------------
`guilds_data["__global__"]` no se guardaba en ningún volcado: el `data.json` se
reescribía entero sin él, así que las estadísticas se borraban del disco en cada guardado
—el cron horario lo hace cada hora— y al reiniciar `/stats` volvía a cero. Ya está
corregido en `core/database.py`, pero **los contadores perdidos no se recuperan solos**.

QUÉ SE RECUPERA Y QUÉ NO
-------------------------
Cada fila de `eventos` es un MENSAJE analizado, con `total` = cuántos elementos tenía y
`peor_veredicto` = el veredicto más grave. Las estadísticas, en cambio, suman **un
incremento por elemento**. Por eso esto es una aproximación y no la cifra histórica:

- `total_analisis` se reconstruye sumando `total`. Queda algo por encima porque `total`
  cuenta también los ARCHIVOS, y los archivos nunca llamaron a `update_stats`.
- Los contadores por veredicto cuentan MENSAJES, no elementos. Un mensaje con un enlace
  limpio y uno malicioso contaba 1 limpio y 1 malicioso; aquí solo sale 1 malicioso, así
  que los "seguros" quedan claramente infrarepresentados.
- `ignorados` NO es recuperable: los mensajes que solo cayeron en whitelist ni siquiera
  llegaban a `eventos`.

Solo cubre lo que quede en `eventos`: el cron llama a `purgar_eventos(30)`, así que como
mucho los últimos 30 días.

USO
---
    python3 recuperar_stats.py            # simulación, no toca nada
    python3 recuperar_stats.py --aplicar  # escribe data.json (CON EL BOT PARADO)

El bot DEBE estar parado al aplicarlo: si está corriendo tiene las estadísticas en
memoria y las volvería a escribir encima en el siguiente volcado, perdiendo lo inserted.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import DATA_FILE, DB_FILE
from core.database import POOL
from core.guild_config import _stats_vacias

# Veredicto guardado en `eventos` -> contador de `/stats` que representa.
_VEREDICTO_A_CONTADOR = {
    "seguro": "seguros",
    "sospechoso": "sospechosos",
    "malicioso": "maliciosos",
    "nsfw": "nsfw",
    "restringido": "restringidos",
    "phishing": "phishing",
    "ignorado": "ignorados",
    "error": "errores",
}


async def _leer_resumen() -> tuple[dict, dict]:
    """Devuelve (`stats` reconstruidas, detalle) leyendo `eventos`."""
    cur = await POOL._conns[0].execute(
        "SELECT peor_veredicto, COUNT(*), SUM(total), MIN(created_at) FROM eventos "
        "GROUP BY peor_veredicto"
    )
    filas = await cur.fetchall()

    por_veredicto = {}
    total_elementos = 0
    total_mensajes = 0
    mas_viejo = None
    for veredicto, mensajes, suma, antiguo in filas:
        veredicto = veredicto or "desconocido"
        mensajes = mensajes or 0
        suma = suma or 0
        por_veredicto[veredicto] = {"mensajes": mensajes, "elementos": suma}
        total_mensajes += mensajes
        total_elementos += suma
        if antiguo is not None and (mas_viejo is None or antiguo < mas_viejo):
            mas_viejo = antiguo

    stats = _stats_vacias()
    for veredicto, datos in por_veredicto.items():
        contador = _VEREDICTO_A_CONTADOR.get(veredicto)
        if contador:
            # Se cuentan MENSAJES, no elementos. Ver la nota de la cabecera.
            stats[contador] = datos["mensajes"]
    stats["total_analisis"] = total_elementos
    return stats, {"por_veredicto": por_veredicto, "mensajes": total_mensajes,
                   "mas_viejo": mas_viejo}


def _mostrar(stats: dict, detalle: dict) -> None:
    print()
    print(f"Eventos en la base: {detalle['mensajes']} mensajes")
    print()
    print(f"{'contador':<18}{'valor':>10}")
    print("-" * 28)
    for clave, valor in stats.items():
        print(f"{clave:<18}{valor:>10}")
    print()
    print("Detalle por veredicto guardado:")
    for veredicto, datos in sorted(detalle["por_veredicto"].items()):
        print(f"  {veredicto:<14} {datos['mensajes']:>6} mensajes  {datos['elementos']:>7} elementos")
    print()


async def main() -> int:
    ap = argparse.ArgumentParser(
        description="Reconstruye las estadísticas de /stats desde la tabla eventos.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Simula por defecto. Con --aplicar escribe en data.json: para el bot parado.",
    )
    ap.add_argument("--aplicar", action="store_true",
                    help="escribe el resultado en data.json (por defecto simula)")
    args = ap.parse_args()

    if not os.path.exists(DB_FILE):
        print(f"No encuentro la base de datos en {DB_FILE}")
        return 1

    await POOL.start()
    try:
        stats, detalle = await _leer_resumen()

        if detalle["mas_viejo"]:
            dias = (time.time() - detalle["mas_viejo"]) / 86400
            print(f"Los eventos más antiguos tienen {dias:.0f} días.")
            if dias >= 29.5:
                print("Ojo: están a punto de caer en `purgar_eventos(30)`.")

        _mostrar(stats, detalle)

        if detalle["mensajes"] == 0:
            print("No hay eventos: no hay nada que reconstruir.")
            return 1

        if not args.aplicar:
            print("Simulación. No se ha escrito nada.")
            print("Si encaja: python3 recuperar_stats.py --aplicar  (con el bot PARADO)")
            return 0

        print("APLICANDO sobre", DATA_FILE)
        print("Comprueba que el bot está parado antes de seguir.")
        if input("Escribe SI para escribir: ").strip() != "SI":
            print("Cancelado. No se ha escrito nada.")
            return 1

        datos = {}
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                datos = json.load(f)
            shutil.copyfile(DATA_FILE, DATA_FILE + ".bak")
            print(f"Copia de seguridad en {DATA_FILE}.bak")
        else:
            print(f"Aviso: {DATA_FILE} no existía. Se creará solo con las estadísticas.")

        # SIN envoltorio "stats". `update_stats` escribe las claves directamente en
        # `guilds_data["__global__"]` y `obtener_stats_globales()` devuelve ese dict tal
        # cual, así que `/stats` lee `__global__["total_analisis"]`. Envolverlo en
        # `{"stats": {...}}` haría que `/stats` no encontrara nada y saltara al error.
        datos["__global__"] = dict(stats)

        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(datos, f, indent=4)
        os.replace(tmp, DATA_FILE)
        print("Escrito. Arranca el bot y comprueba /stats.")
        return 0
    finally:
        for conn in POOL._conns:
            try:
                await conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
