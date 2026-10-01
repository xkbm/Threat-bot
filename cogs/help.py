import discord
from discord.ext import commands
from discord import app_commands
import logging
from ui import embed as emb

log = logging.getLogger("help")

class HelpCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="help", description="Todos los comandos de Threat")
    async def help_command(self, interaction: discord.Interaction) -> None:
        log.debug(f"HELP → usuario={interaction.user.id} guild={interaction.guild.id if interaction.guild else None}")
        await interaction.response.defer()
        
        embed = emb.aviso("Comandos de Threat", "Lista de comandos disponibles.", con_pie=False)

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis [1]",
            value="`/scan` \u00b7 url \u00b7 archivo \u00b7 hash \u00b7 ip\n"
            "También con el clic derecho sobre cualquier mensaje.",
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Utilidades [6]",
            value="`/stats` \u00b7 `/about` \u00b7 `/uptime` \u00b7 `/ping` \u00b7 `/usercheck` \u00b7 `/help`",
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación [2]",
            value=(
                "`/settings` · **todo se configura aquí**\n"
                "`/history` · últimos análisis del canal"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LOADING} Reacciones",
            value=(
                f"Cada mensaje lleva **una sola** reacción, la de su peor resultado.\n"
                f"{self.bot.EMOJI_CORRECTO} Seguro \u00b7 "
                f"{self.bot.EMOJI_GUARDIAN} Sospechoso \u00b7 "
                f"{self.bot.EMOJI_RESTRINGIDO} Restringido\n"
                f"{self.bot.EMOJI_NSFW} NSFW \u00b7 "
                f"{self.bot.EMOJI_WARNING} Amenaza \u00b7 "
                f"{self.bot.EMOJI_PHISHING} Suplantación\n"
                f"{self.bot.EMOJI_ERROR} Sin comprobar \u00b7 "
                f"{self.bot.EMOJI_COOLDOWN} Límite alcanzado \u00b7 "
                f"{self.bot.EMOJI_LOADING} Analizando"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Veredictos",
            value=(
                "**Restringido** (alcohol, armas) es informativo: avisa y queda "
                "registrado, pero no borra. Solo **Amenaza** y **NSFW** borran en modo "
                "estricto. **Sin comprobar** significa que el análisis falló o no había "
                "cuota: nunca se muestra como seguro."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Nota",
            value="Los comandos de moderación requieren permisos de administrador.",
            inline=False
        )

        emb.pie(embed, "Comandos")

        view = discord.ui.View()
        view.add_item(discord.ui.Button(
            style=discord.ButtonStyle.link,
            url="https://threat-bot-discord.vercel.app",
            label="Sitio Web",
            emoji=self.bot.EMOJI_LINK
        ))

        try:
            await interaction.edit_original_response(embed=embed, view=view)
        except discord.errors.NotFound:
            pass

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(HelpCog(bot))
