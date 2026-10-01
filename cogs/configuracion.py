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
        """Envía un followup.

        Un 400 aquí significa que la interaction no se respondió ni se difirió antes, y
        que el usuario no va a ver nada. Se relanza para que quede traza en el log: antes
        se silenciaba y el fallo solo se manifesting como "el comando no hace nada".
        """
        try:
            await interaction.followup.send(*args, **kwargs)
        except discord.errors.NotFound:
            pass
        except discord.HTTPException:
            log.error(
                "Fallo al enviar el followup: HTTP de Discord. La interaction probablemente "
                "no se difirió antes de enviar. Comando fallido en silencio.",
                exc_info=True,
            )
            raise

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

        El `defer` no es opcional. Todo lo que se envía aquí va por `followup.send`, y
        Discord rechaza un followup si la interaction no se ha respondido o diferido
        antes: devuelve 400 "This interaction has not been sent yet" y el comando no
        muestra nada. Es lo que pasaba aquí, y en los tests no se veía porque la suite
        fake no reproducía el contrato de la interacción.
        """
        await interaction.response.defer(ephemeral=True)
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
