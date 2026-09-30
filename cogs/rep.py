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
    async def usercheck(self, interaction: discord.Interaction, usuario: discord.Member) -> None:
        await interaction.response.defer(ephemeral=True)
        
        guild_id = interaction.guild.id
        config = await self.bot.obtener_config_guild(guild_id)
        infracciones = config.get("infracciones", {})
        count = infracciones.get(str(usuario.id), 0)

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

        log.debug(f"USERCHECK → guild={guild_id} usuario_consultado={usuario.id} infracciones={count} admin={interaction.user.id}")
        try:
            await interaction.edit_original_response(embed=embed)
        except discord.errors.NotFound:
            pass

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ReputacionCog(bot))
