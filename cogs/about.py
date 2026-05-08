import discord
from discord.ext import commands
from discord import app_commands

class InfoCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="about", description="Información detallada sobre las capacidades y funcionamiento del bot de seguridad Threat")
    async def about(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Acerca de Threat",
            description=(
                "Analiza URLs, IPs, hashes y archivos con VirusTotal "
                "y detecta contenido NSFW con Sightengine.\n"
                "Incluye caché inteligente, sistema de infracciones y logs con botones."
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis",
            value=(
                "• Escaneo automático de enlaces, archivos e imágenes\n"
                "• Mensajes editados y URLs acortadas\n"
                "• Doble extensión y verificación MIME\n"
                "• **`/scan`** — análisis manual de URL, IP, hash o archivo"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación",
            value=(
                "• **`/silentmode`** — Solo reacciones, sin mensajes\n"
                "• **`/strictmode`** — Elimina mensajes peligrosos\n"
                "• **`/whitelist`** — Dominios de confianza\n"
                "• **`/setlogchannel`** — Canal de logs con botones\n"
                "• **`/usercheck`** — Infracciones de un usuario"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Caché y límites",
            value=(
                "• **Caché**: 1h memoria + 7-30 días SQLite\n"
                "• **API**: 3 keys VT (12/min) + 3 Sightengine\n"
                "• **Límites**: 30 análisis/hora, 5 por mensaje"
            ),
            inline=False
        )

        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(InfoCog(bot))
