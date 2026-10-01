import discord
from discord.ext import commands
from discord import app_commands
import logging
from ui import embed as emb

log = logging.getLogger("rep")

class ReputacionCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="usercheck", description="Muestra las infracciones de seguridad de un usuario")
    @app_commands.describe(usuario="Usuario a consultar")
    @app_commands.default_permissions(manage_messages=True)
    async def usercheck(self, interaction: discord.Interaction, usuario: discord.Member) -> None:
        # Sin guild no hay config que leer, y antes de esto se reventaba al leer
        # interaction.guild.id. Se comprueba ANTES del defer para poder responder con
        # la forma correcta.
        if interaction.guild is None:
            await interaction.response.send_message("Este comando solo funciona dentro de un servidor.", ephemeral=True)
            return

        # `default_permissions` solo oculta el comando en el cliente: no impide que se
        # invoque. El expediente de seguridad de una persona no es público.
        if not interaction.permissions.moderator:
            await interaction.response.send_message("Necesitas ser moderador para usar este comando.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        guild_id = interaction.guild.id
        # Las infracciones viven en su tabla, no dentro del JSON de configuración: así
        # se pueden purgar por fecha y el contador nunca se desincroniza de las filas.
        from core.guild_config import contar_infracciones
        count = await contar_infracciones(guild_id, usuario.id)

        if count > 0:
            color = emb.COLOR_MALICIOSO
            estado = f"{self.bot.EMOJI_WARNING} Tiene **{count}** infracciones registradas."
        else:
            color = emb.COLOR_SEGURO
            estado = f"{self.bot.EMOJI_CORRECTO} No tiene infracciones registradas."

        embed = emb.aviso(
            "Reputación de seguridad",
            f"**Usuario:** {usuario.mention}\n**ID:** `{usuario.id}`\n\n{estado}",
            campos=[
                (f"{self.bot.EMOJI_LINK} Servidor", interaction.guild.name, False),
                (f"{self.bot.EMOJI_KEY} Comando", "Usa `/help` para ver los demás comandos", False),
            ],
            color=color,
            icono=self.bot.EMOJI_GUARDIAN,
        )

        log.debug(f"USERCHECK → guild={guild_id} usuario_consultado={usuario.id} infracciones={count} moderador={interaction.user.id}")
        try:
            await interaction.edit_original_response(embed=embed)
        except discord.errors.NotFound:
            pass

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ReputacionCog(bot))
