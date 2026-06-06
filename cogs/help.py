import discord
from discord.ext import commands
from discord import app_commands
import logging

log = logging.getLogger("help")

class HelpCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="help", description="Lista completa de comandos y funcionalidades del bot de seguridad Threat")
    async def help_command(self, interaction: discord.Interaction) -> None:
        log.debug(f"HELP → usuario={interaction.user.id} guild={interaction.guild.id if interaction.guild else None}")
        await interaction.response.defer()
        
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Comandos de Threat",
            description="Lista de comandos disponibles.",
            color=discord.Color(0x36393F)
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis [1]",
            value="`/scan`",
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Utilidades [5]",
            value="`/stats` • `/about` • `/uptime` • `/ping` • `/help`",
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación [7]",
            value=(
                "`/usercheck` • `/silentmode` • `/strictmode` • "
                "`/whitelist` • `/setlogchannel` • `/disablelogchannel` • `/settings`"
            ),
            inline=False
        )

        embed.set_footer(
            text="Los comandos de moderación requieren permisos de administrador."
        )

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
