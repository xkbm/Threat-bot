import discord
from discord.ext import commands
from discord import app_commands
from typing import Any, Optional
import logging

from core import config_schema as esq
from core.guild_config import actualizar_config
from ui import embed as emb
from ui.panel import panel_por_guild

log = logging.getLogger("configuracion")

class ConfiguracionCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def _safe_followup(self, interaction: discord.Interaction, *args: Any, **kwargs: Any) -> None:
        try:
            await interaction.followup.send(*args, **kwargs)
        except discord.errors.NotFound:
            pass

    @app_commands.command(name="silentmode", description="Activa/desactiva el modo silencioso (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(estado="True = silencioso, False = normal")
    async def silentmode(self, interaction: discord.Interaction, estado: bool) -> None:
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        await actualizar_config(interaction.guild.id, inmediato=True, silent_mode=estado)
        log.debug(f"SILENTMODE → guild={interaction.guild.id} estado={estado} admin={interaction.user.id}")
        await self._safe_followup(interaction, f"{self.bot.EMOJI_CORRECTO} Modo silencioso {'activado' if estado else 'desactivado'}.", ephemeral=True)

    @app_commands.command(name="strictmode", description="Activa/desactiva el modo estricto (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(estado="True = estricto, False = normal")
    async def strictmode(self, interaction: discord.Interaction, estado: bool) -> None:
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        await actualizar_config(interaction.guild.id, inmediato=True, strict_mode=estado)
        log.debug(f"STRICTMODE → guild={interaction.guild.id} estado={estado} admin={interaction.user.id}")
        await self._safe_followup(interaction, f"{self.bot.EMOJI_CORRECTO} Modo estricto {'activado' if estado else 'desactivado'}.", ephemeral=True)

    @app_commands.command(name="autoscan", description="Activa/desactiva el escaneo automático (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(estado="True = activo, False = desactivado")
    async def autoscan(self, interaction: discord.Interaction, estado: bool) -> None:
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        await actualizar_config(interaction.guild.id, inmediato=True, auto_scan_enabled=estado)
        log.debug(f"AUTOSCAN → guild={interaction.guild.id} estado={estado} admin={interaction.user.id}")
        await self._safe_followup(interaction, f"{self.bot.EMOJI_CORRECTO} Auto-scan {'activado' if estado else 'desactivado'}.", ephemeral=True)

    @app_commands.command(name="setlogchannel", description="Establece el canal para logs de amenazas (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(canal="Canal donde se enviarán los logs")
    async def setlogchannel(self, interaction: discord.Interaction, canal: discord.TextChannel) -> None:
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        await actualizar_config(interaction.guild.id, inmediato=True, log_channel_id=canal.id)
        log.debug(f"SETLOGCHANNEL → guild={interaction.guild.id} canal={canal.id} admin={interaction.user.id}")
        await self._safe_followup(interaction, f"{self.bot.EMOJI_CORRECTO} Canal de logs establecido a {canal.mention}.", ephemeral=True)

    @app_commands.command(name="disablelogchannel", description="Desactiva el envío de logs (solo admins)")
    @app_commands.default_permissions(administrator=True)
    async def disablelogchannel(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        await actualizar_config(interaction.guild.id, inmediato=True, log_channel_id=None)
        log.debug(f"DISABLELOGCHANNEL → guild={interaction.guild.id} admin={interaction.user.id}")
        await self._safe_followup(interaction, f"{self.bot.EMOJI_CORRECTO} Logs desactivados.", ephemeral=True)

    @app_commands.command(
        name="settings",
        description="Abre los ajustes del bot en este servidor (solo admins)",
    )
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(seccion="Sección a la que abrir el panel. Por defecto, Aviso.")
    async def settings(
        self,
        interaction: discord.Interaction,
        seccion: Optional[str] = None,
    ) -> None:
        """Abre el panel de configuración.

        Antes esto imprimía los ajustes y no dejaba cambiar nada: cada opción exigía su
        propio comando. Ahora abre el panel, y el panel se construye recorriendo
        `core.config_schema`, así que no puede mostrar una clave inexistente ni dejar
        fuera una nueva.
        """
        if not interaction.guild:
            await self._safe_followup(
                interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.",
                ephemeral=True)
            return

        elegida = seccion if seccion in esq.secciones() else esq.AVISO
        embed, vista = await panel_por_guild(interaction.guild, elegida)
        log.debug(f"SETTINGS → guild={interaction.guild.id} seccion={elegida}")
        await self._safe_followup(interaction, embed=embed, view=vista, ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ConfiguracionCog(bot))
