import asyncio
from typing import Optional, Any
import logging
from core import state
from core.config import DOMINIOS_PROTEGIDOS
from core.aviso import config_aviso_por_defecto
from core.config_schema import validar
from core.database import (
    guardar_datos, guardar_config_db, registrar_infraccion_db,
    contar_infracciones_db, infracciones_de_db,
)

log = logging.getLogger("guild_config")
_guild_locks: dict[int, asyncio.Lock] = {}
_guild_locks_lock = asyncio.Lock()
_global_lock = asyncio.Lock()
# Respaldo en memoria de infracciones para cuando SQLite no está disponible.
# No se persiste: es solo para no perder la cuenta si la base falla.
_infracciones_memoria: dict[int, dict[str, list[str]]] = {}

async def _get_guild_lock(guild_id: int) -> asyncio.Lock:
    async with _guild_locks_lock:
        if guild_id not in _guild_locks:
            _guild_locks[guild_id] = asyncio.Lock()
        return _guild_locks[guild_id]

async def remove_guild_lock(guild_id: int) -> None:
    async with _guild_locks_lock:
        _guild_locks.pop(guild_id, None)

def _config_por_defecto() -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "silent_mode": True,
        "strict_mode": True,
        "auto_scan_enabled": True,
        "log_channel_id": None,
        "whitelist": list(DOMINIOS_PROTEGIDOS),
        "infracciones": {},
        "infracciones_registradas": {},
    }
    # Los interruptores de aviso no son una decisión del usuario todavía: se derivan
    # de su `silent_mode` actual para que un servidor que actualice el bot no vea
    # ningún cambio en lo que recibe. En cuanto los toque desde el panel se guardan
    # explícitos y esta derivación ya no vuelve a aplicarse.
    cfg.update(config_aviso_por_defecto(cfg["silent_mode"]))
    return cfg


def _asegurar_guild(guild_id: int) -> dict[str, Any]:
    """Devuelve la config del guild creándola con los defaults si no existe.

    NO adquirir el lock del guild: el llamador ya lo tiene.
    """
    if guild_id not in state.bot.guilds_data:
        state.bot.guilds_data[guild_id] = _config_por_defecto()
    config = state.bot.guilds_data[guild_id]

    # El orden importa y es la razón de que esta función exista. Los interruptores de
    # aviso se derivan del `silent_mode` **de este** guild, y tienen que fijarse ANTES
    # del `setdefault` genérico: si se pusieran después, el genérico ya habría metido
    # `avisar_limpios` derivado del `silent_mode` por defecto (True), y una guild que
    # tuviera `silent_mode: False` en su data.json se quedaría con `avisar_limpios:
    # False` y dejaría de recibir los embeds de mensajes limpios al actualizar el bot.
    for clave, valor in config_aviso_por_defecto(config.get("silent_mode", True)).items():
        if clave == "silent_mode":
            continue
        config.setdefault(clave, valor)

    for key, default_val in _config_por_defecto().items():
        config.setdefault(key, default_val)

    return config


async def obtener_config_guild(guild_id: int) -> dict[str, Any]:
    """Devuelve la config del guild. **El dict es la referencia viva**, no una copia.

    El panel y los comandos dependen de eso: `_asegurar_guild` rellena las claves nuevas
    la primera vez y quien llama ve ese relleno. Pero significa que mutarlo fuera del
    lock es una carrera, y por eso `actualizar_config` es la vía correcta para escribir.
    """
    async with await _get_guild_lock(guild_id):
        return _asegurar_guild(guild_id)


async def actualizar_config(
    guild_id: int,
    inmediato: bool = False,
    **campos: Any,
) -> dict[str, Any]:
    """Escribe campos de configuración bajo el lock del guild y persiste.

    Todo el camino de escritura pasa por aquí: los siete comandos de configuración, el
    panel y lo que se añada. Antes cada uno mutaba el dict y llamaba a `guardar_datos` por
    su cuenta, que además solía mutar fuera del lock.

    `inmediato=True` fuerza la escritura en vez de esperar al debounce. Lo usan los
    comandos de administración: si un moderador activa el modo estricto y el bot se cae
    dos segundos después, el ajuste debería estar aplicado.

    Los valores se validan con el esquema antes de guardar, y un valor imposible se
    sustituye por su default. Un umbral fuera de rango se recorta, no se rechaza: es
    mucho más probable que un 0.99 tecleado por error rompa el panel si se rechaza a
    medias que si se recorta.
    """
    async with await _get_guild_lock(guild_id):
        config = _asegurar_guild(guild_id)
        config.update(validar(campos))
    await _persistir_config(guild_id, config, inmediato)
    log.debug(f"CONFIG UPDATE → guild={guild_id} claves={sorted(campos)}")
    return config


async def _persistir_config(guild_id: int, config: dict[str, Any], inmediato: bool) -> None:
    """Guarda la config en SQLite, y en `data.json` como respaldo.

    SQLite es la fuente de verdad. El volcado a `data.json` se mantiene porque es lo que
    permite volver atrás leyendo el fichero si algo va mal con la base, y porque
    `cargar_datos` sigue siendo la vía de arranque. No es un segundo sitio donde
    configurar: nada lee de ahí en caliente.
    """
    try:
        await guardar_config_db(guild_id, config)
    except Exception as e:
        # La base puede no existir todavía (tests, arranque temprano). No es motivo para
        # tumbar un cambio de configuración: el volcado al JSON lo conserva.
        log.debug(f"No se pudo guardar la config en SQLite (guild={guild_id}): {type(e).__name__}")
    await guardar_datos(inmediato=inmediato)


async def agregar_dominio(guild_id: int, dominio: str) -> bool:
    """Añade un dominio a la whitelist del guild. Devuelve True si se añadió."""
    async with await _get_guild_lock(guild_id):
        config = _asegurar_guild(guild_id)
        if dominio in config["whitelist"]:
            return False
        config["whitelist"].append(dominio)
    await _persistir_config(guild_id, config, True)
    log.debug(f"WHITELIST ADD → guild={guild_id} dominio={dominio}")
    return True


async def quitar_dominio(guild_id: int, dominio: str) -> bool:
    """Quita un dominio de la whitelist del guild. Devuelve True si se quitó."""
    async with await _get_guild_lock(guild_id):
        config = _asegurar_guild(guild_id)
        if dominio not in config["whitelist"]:
            return False
        config["whitelist"].remove(dominio)
    await _persistir_config(guild_id, config, True)
    log.debug(f"WHITELIST REMOVE → guild={guild_id} dominio={dominio}")
    return True

def _stats_vacias() -> dict[str, int]:
    return {"total_analisis": 0, "seguros": 0, "sospechosos": 0, "maliciosos": 0, "nsfw": 0, "errores": 0}


def obtener_stats_globales() -> dict[str, int]:
    if "__global__" not in state.bot.guilds_data:
        state.bot.guilds_data["__global__"] = _stats_vacias()
    return state.bot.guilds_data["__global__"]


async def update_stats(guild_id: Optional[int], tipo: str) -> None:
    async with _global_lock:
        if "__global__" not in state.bot.guilds_data:
            state.bot.guilds_data["__global__"] = _stats_vacias()
        global_stats = state.bot.guilds_data["__global__"]
        # Un `data.json` escrito antes de que existiera el veredicto "sospechoso" no
        # trae la clave. Sin este default, el primer análisis sospechoso lo guardaría
        # pero `/stats` no lo vería hasta que un "seguro" la recreara.
        for key, valor in _stats_vacias().items():
            global_stats.setdefault(key, valor)
        global_stats["total_analisis"] += 1
        if tipo == "seguro":
            global_stats["seguros"] += 1
        elif tipo == "sospechoso":
            global_stats["sospechosos"] += 1
        elif tipo == "malicioso":
            global_stats["maliciosos"] += 1
        elif tipo == "nsfw":
            global_stats["nsfw"] += 1
        else:
            global_stats["errores"] += 1
    await guardar_datos()
    log.debug(f"STATS UPDATE → guild={guild_id} tipo={tipo} total={global_stats['total_analisis']}")

async def registrar_infraccion(guild_id: int, user_id: int, elemento_id: str) -> int:
    """Suma una infracción y devuelve el total del usuario.

    La deduplicación la hace la clave primaria de la tabla, no una lista en memoria.
    Antes `infracciones_registradas` era una lista por usuario que **nunca se purgaba**:
    crecía sin límite y `data.json` se reescribía entero en cada infracción, con cada
    elemento distinto que alguien publica añadía una entrada más.

    Si SQLite no está disponible (arranque temprano, base caída) cae a un mapa en
    memoria. Perder el registro de una infracción en ese instante es aceptable; perder
    el contador entero del guild no lo sería, así que el respaldo mantiene la cuenta.
    """
    async with await _get_guild_lock(guild_id):
        _asegurar_guild(guild_id)          # asegura que el guild existe
        try:
            if elemento_id in await infracciones_de_db(guild_id, user_id):
                return await contar_infracciones_db(guild_id, user_id)
            await registrar_infraccion_db(guild_id, user_id, elemento_id)
            total = await contar_infracciones_db(guild_id, user_id)
        except Exception as e:
            log.warning(
                f"Infracciones en memoria para el guild {guild_id} (SQLite no disponible: "
                f"{type(e).__name__}). No se persistirán hasta el próximo reinicio."
            )
            elementos = _infracciones_memoria.setdefault(guild_id, {}).setdefault(str(user_id), [])
            if elemento_id in elementos:
                return len(elementos)
            elementos.append(elemento_id)
            return len(elementos)
    log.debug(f"INFRACCION → guild={guild_id} user={user_id} elemento={elemento_id} total={total}")
    return total


async def contar_infracciones(guild_id: int, user_id: int) -> int:
    """Total de infracciones de un usuario. Lo que usa `/usercheck`."""
    try:
        return await contar_infracciones_db(guild_id, user_id)
    except Exception:
        return len(_infracciones_memoria.get(guild_id, {}).get(str(user_id), []))


async def ignorar_infraccion(guild_id: int, user_id: int, elemento_id: str) -> int:
    """Descuenta una infracción. Es lo que hace el botón "Ignorar" del log.

    Antes restaba un número de una lista, lo que dejaba el contador y la lista
    permanentemente desincronizados. Aquí es un `DELETE` real sobre la fila.
    """
    from core.database import borrar_infraccion_db

    async with await _get_guild_lock(guild_id):
        try:
            await borrar_infraccion_db(guild_id, user_id, elemento_id)
            return await contar_infracciones_db(guild_id, user_id)
        except Exception:
            elementos = _infracciones_memoria.get(guild_id, {}).get(str(user_id), [])
            if elemento_id in elementos:
                elementos.remove(elemento_id)
            return len(elementos)
