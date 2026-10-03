import asyncio
from typing import Optional, Any
import logging
from core import state
from core.config import DOMINIOS_PROTEGIDOS
from core.config import stats_vacias as _stats_vacias
from core.aviso import config_aviso_por_defecto, migrar_aviso
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
    # `silent_mode` NO va aquí. Si estuviera, la migración no haría nada —vería
    # `avisar_todo` ya presente— y la clave vieja se quedaría en la configuración junto a
    # la nueva, con el mismo nombre y sentidos distintos. Para una guild nueva no hace
    # falta: `config_aviso_por_defecto` ya trae `avisar_todo`. Para una que venga de un
    # `data.json` viejo, la traduce `migrar_aviso` en `_asegurar_guild`.
    cfg: dict[str, Any] = {
        "strict_mode": True,
        "auto_scan_enabled": True,
        "log_channel_id": None,
        "whitelist": list(DOMINIOS_PROTEGIDOS),
        "infracciones": {},
        "infracciones_registradas": {},
    }
    # La lista de qué avisa no es una decisión del usuario todavía: se rellena con el
    # catálogo por defecto para que un servidor que actualice el bot no vea ningún cambio
    # en lo que recibe. En cuanto se toque desde el panel se guarda explícita.
    cfg.update(config_aviso_por_defecto())
    return cfg


def _asegurar_guild(guild_id: int) -> dict[str, Any]:
    """Devuelve la config del guild creándola con los defaults si no existe.

    NO adquirir el lock del guild: el llamador ya lo tiene.
    """
    if guild_id not in state.bot.guilds_data:
        state.bot.guilds_data[guild_id] = _config_por_defecto()
    config = state.bot.guilds_data[guild_id]
    # `silent_mode` → `avisar_todo`, una sola vez y antes de nada. Si se hiciese después
    # de rellenar los defaults, un servidor con la clave antigua se quedaría con
    # `avisar_todo` en su default y su interruptor se movería solo.
    migrar_aviso(config)

    # La lista de qué avisa se rellena ANTES del `setdefault` genérico, con el catálogo
    # por defecto y no con lo que haya en la configuración. Un `data.json` anterior no
    # tiene la clave y es justo lo que se quiere completar aquí.
    for clave, valor in config_aviso_por_defecto().items():
        config.setdefault(clave, valor)

    # Y después, los defaults del ESQUEMA.
    #
    # Se recorre el esquema y no una lista escrita a mano, porque las dos se separaron
    # ya: `avisar_amenazas` estaba en el esquema y no en la config, así que solo
    # funcionaba por el `get(..., True)` de cada sitio que la leía. Con dos listas
    # siempre acaba faltando una.
    from core.config_schema import ESQUEMA

    for clave in ESQUEMA:
        if clave.nombre not in config:
            config[clave.nombre] = _default_de(clave)

    for key, default_val in _config_por_defecto().items():
        config.setdefault(key, default_val)

    return config


def _default_de(clave) -> Any:
    """El default declarado en el esquema para una `Clave`.

    Para listas se devuelve una copia: devolver la del esquema dejaría que un `append` en
    la configuración de un guild contaminara el default de todos los demás.
    """
    valor = clave.default
    return list(valor) if isinstance(valor, list) else valor


def _con_umbrales(config: dict[str, Any]) -> dict[str, Any]:
    """Añade `_umbrales`: los del guild traducidos al formato que espera SightEngine.

    Sin esto el panel ofrecía seis umbrales que nadie leía, y `evaluar_contenido` usaba
    siempre los de `core.config`. Traducir aquí evita que cada call site tenga que
    acordarse del mapeo, que es donde se colarían divergencias.
    """
    from core.config_schema import aplicar_config

    config["_umbrales"] = aplicar_config(config)
    return config


async def obtener_config_guild(guild_id: int) -> dict[str, Any]:
    """Devuelve la config del guild. **El dict es la referencia viva**, no una copia.

    El panel y los comandos dependen de eso: `_asegurar_guild` rellena las claves nuevas
    la primera vez y quien llama ve ese relleno. Pero significa que mutarlo fuera del
    lock es una carrera, y por eso `actualizar_config` es la vía correcta para escribir.
    """
    async with await _get_guild_lock(guild_id):
        return _con_umbrales(_asegurar_guild(guild_id))


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
    """Guarda la configuración de un guild en SQLite.

    SQLite es la fuente de verdad: `cargar_datos` lee de ahí al arrancar. `data.json` ya
    no lleva configuraciones, así que no hay dos sitios donde alguien pueda cambiar algo.

    Si SQLite falla, se hace una copia de emergencia con las configs incluidas y se avisa
    por log. El motivo de esa copia es que un cambio de configuración hecho por un
    administrador no se puede perder porque la base esté momentarily caída, y es
    JUSTAMENTE en ese escenario cuando `cargar_datos` cairía de vuelta al JSON. Sin la
    copia, ese cambio se perdía en silencio.
    """
    try:
        await guardar_config_db(guild_id, config)
    except Exception as e:
        log.warning(
            f"No se pudo guardar la config de {guild_id} en SQLite ({type(e).__name__}). "
            f"Se hace copia de emergencia en data.json para no perderla."
        )
        await guardar_datos(inmediato=True, incluir_guilds=True)


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
        elif tipo == "restringido":
            global_stats["restringidos"] += 1
        elif tipo == "phishing":
            global_stats["phishing"] += 1
        elif tipo == "ignorado":
            global_stats["ignorados"] += 1
        elif tipo == "error":
            global_stats["errores"] += 1
        else:
            # Veredicto desconocido: se cuenta como error en vez de inventar una
            # categoría. Antes el `else` genérico hacía que cualquier valor raro
            # inflase "errores".
            log.warning(f"Tipo de análisis desconocido en update_stats: {tipo!r}")
            global_stats["errores"] += 1
    # Aquí NO se guarda. Antes este `await guardar_datos()` reescribía el `data.json`
    # entero (con `indent=4` y `fsync`) en CADA análisis, y las estadísticas son lo
    # único que cambia en cada mensaje: un servidor activoDirectories un fichero
    # stat_json entero por mensaje sin que la configuración haya cambiado nada.
    # Las estadísticas son estado de ejecución: las persiste el cron horario y el
    # apagado, que es donde de verdad importa no perderlas.
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


async def tiene_infraccion(guild_id: int, user_id: int, elemento_id: str) -> bool:
    """¿Está ESTE elemento registrado para este usuario?

    El botón "Ignorar" comprobaba el total de infracciones del usuario en vez de este
    elemento: con un usuario que tenía otras infracciones,Responder "Infracción
    eliminada" sin haber borrado nada, porque el `DELETE` es idempotente y no delata el
    fallo.
    """
    try:
        return elemento_id in await infracciones_de_db(guild_id, user_id)
    except Exception:
        elementos = _infracciones_memoria.get(guild_id, {}).get(str(user_id), [])
        return elemento_id in elementos


async def ignorar_infraccion(guild_id: int, user_id: int, elemento_id: str) -> int:
    """Descuenta una infracción. Es lo que hace el botón "Ignorar" del log.

    Antes restaba un número de una lista, lo que dejaba el contador y la lista
    permanentemente desincronizados. Aquí es un `DELETE` real sobre la fila.

    Devuelve el total resultante. Lanza si no se pudo borrar, para que quien llama no
    le diga al moderador que se aplicó la regla cuando no se aplicó.
    """
    from core.database import borrar_infraccion_db

    async with await _get_guild_lock(guild_id):
        await borrar_infraccion_db(guild_id, user_id, elemento_id)
        return await contar_infracciones(guild_id, user_id)


async def olvidar_guild(guild_id: int) -> None:
    """Limpia lo que queda en RAM de un servidor del que el bot salió.

    `state.bot.guilds_data` lo quita `bot.on_guild_remove`, pero `_infracciones_memoria` es
    un mapa a parte y sin cota: con la base caída, cada guild del que sale dejaba su
    diccionario de infracciones en memoria para el resto de la vida del proceso.
    """
    _infracciones_memoria.pop(guild_id, None)
