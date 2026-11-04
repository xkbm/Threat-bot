"""Modo beta: funciones nuevas visibles solo en servidores autorizados.

Una sola instancia del bot (misma token, misma DB, misma cuota de API); lo que
cambia es el comportamiento según el guild. No hay comando de gestión: la
allowlist vive solo en variables de entorno (`BETA_MODE`, `BETA_GUILD_IDS`),
porque exponer un comando para editarla sería superficie de ataque.

Leer `core.config` al importar es intencional: las variables se capturan una vez
en el arranque, igual que `TOKEN` o `VT_API_KEYS`.
"""

from core import config


def es_beta_global() -> bool:
    """¿Está activado el modo beta globalmente?

    Útil para comandos del owner que no pertenecen a un guild concreto.
    """
    return config.BETA_MODE


def es_beta(guild_id: int | None) -> bool:
    """¿Este servidor puede ver funciones beta?

    Solo servidores (no DMs), solo si `BETA_MODE` está activo y el `guild_id`
    está en `BETA_GUILD_IDS`.
    """
    if not config.BETA_MODE:
        return False
    if guild_id is None:
        return False
    return guild_id in config.BETA_GUILD_IDS
