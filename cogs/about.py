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
                f"{self.bot.EMOJI_LUPA} Analiza URLs, IPs, hashes y archivos con VirusTotal\n"
                f"{self.bot.EMOJI_WARNING} Detecta contenido NSFW con Sightengine\n"
                f"{self.bot.EMOJI_CORRECTO} Caché inteligente + infracciones + logs interactivos"
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis",
            value=(
                f"{self.bot.EMOJI_CORRECTO} Escaneo automático de enlaces, archivos e imágenes\n"
                f"{self.bot.EMOJI_CORRECTO} Mensajes editados y URLs acortadas\n"
                f"{self.bot.EMOJI_CORRECTO} Doble extensión y verificación MIME\n"
                f"{self.bot.EMOJI_LUPA} **`/scan`** — análisis manual de URL, IP, hash o archivo"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación",
            value=(
                f"{self.bot.EMOJI_GUARDIAN} **`/silentmode`** — Solo reacciones, sin mensajes\n"
                f"{self.bot.EMOJI_GUARDIAN} **`/strictmode`** — Elimina mensajes peligrosos\n"
                f"{self.bot.EMOJI_WHITELIST} **`/whitelist`** — Dominios de confianza\n"
                f"{self.bot.EMOJI_REPLY} **`/setlogchannel`** — Canal de logs con botones\n"
                f"{self.bot.EMOJI_REPLY} **`/usercheck`** — Infracciones de un usuario"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Caché y límites",
            value=(
                f"{self.bot.EMOJI_CORRECTO} **Caché**: 1h memoria + 7-30 días SQLite\n"
                f"{self.bot.EMOJI_KEY} **API**: 3 keys VT (12/min) + 3 Sightengine\n"
                f"{self.bot.EMOJI_COOLDOWN} **Límites**: 30 análisis/hora, 5 por mensaje"
            ),
            inline=False
        )

        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(InfoCog(bot))
