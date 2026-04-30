import discord
from discord.ext import commands
from discord import app_commands

class InfoCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="about", description="Información sobre el funcionamiento de Threat")
    async def about(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Acerca de Threat",
            description=(
                "Bot de seguridad que analiza **URLs, IPs, hashes y archivos** usando **VirusTotal**, "
                "con detección **NSFW** mediante **Sightengine**. "
                "Incluye **caché inteligente**, **sistema de infracciones** y **logs con botones**."
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis",
            value=(
                "**Automático:** enlaces, archivos, imágenes, mensajes editados, URLs acortadas, doble extensión.\n\n"
                "**Comandos:** `/scan`, `/stats`, `/about`, `/help`, `/settings`"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación",
            value=(
                "• `/silentmode` — Solo reacciones, sin mensajes\n"
                "• `/strictmode` — Elimina mensajes peligrosos\n"
                "• `/whitelist` — Dominios de confianza\n"
                "• `/setlogchannel` — Canal de logs con botones\n"
                "• `/usercheck` — Infracciones de un usuario"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Caché y límites",
            value=(
                "• **Caché**: 1h en memoria, 7-30 días en SQLite\n"
                "• **API**: 3 keys VirusTotal (12/min), 3 keys Sightengine\n"
                "• **Límites**: 30 análisis/hora, 5 URLs/archivos por mensaje"
            ),
            inline=False
        )

        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(InfoCog(bot))