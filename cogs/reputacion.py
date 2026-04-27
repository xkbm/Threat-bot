import discord
from discord.ext import commands
from discord import app_commands

class ReputacionCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="usercheck", description="Muestra las infracciones de seguridad de un usuario (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(usuario="Usuario a consultar")
    async def usercheck(self, interaction: discord.Interaction, usuario: discord.Member):
        """Consulta el número de infracciones acumuladas por un usuario."""
        guild_id = interaction.guild.id
        config = self.bot.obtener_config_guild(guild_id)
        infracciones = config.get("infracciones", {})
        count = infracciones.get(str(usuario.id), 0)

        if count > 0:
            color = discord.Color.orange()
            estado = f"{self.bot.EMOJI_WARNING} Tiene **{count}** infracciones registradas."
        else:
            color = discord.Color.green()
            estado = f"{self.bot.EMOJI_CORRECTO} No tiene infracciones registradas."

        embed = discord.Embed(
            title=f"{self.bot.EMOJI_GUARDIAN} Reputación de seguridad",
            description=f"**Usuario:** {usuario.mention}\n**ID:** `{usuario.id}`\n\n{estado}",
            color=color
        )
        embed.set_footer(text=f"Servidor: {interaction.guild.name}  •  Usa /help para ver otros comandos")

        await interaction.response.send_message(embed=embed, ephemeral=True)

async def setup(bot):
    await bot.add_cog(ReputacionCog(bot))