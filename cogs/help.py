import discord
from discord.ext import commands
from discord import app_commands

class HelpCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="help", description="Lista completa de comandos y funcionalidades del bot de seguridad Threat")
    async def help_command(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Comandos de Threat",
            description=(
                f"{self.bot.EMOJI_LUPA} Análisis automático y manual con VirusTotal + Sightengine\n"
                f"{self.bot.EMOJI_CORRECTO} Escaneo de mensajes, reputación y caché inteligente"
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis",
            value=(
                f"**`/scan`** — Analiza URL, IP, hash o archivo\n"
                f"└ *Ejemplo:* `/scan tipo:url valor:https://ejemplo.com`\n\n"
                f"**Detección automática:**\n"
                f"{self.bot.EMOJI_CORRECTO} Enlaces en mensajes\n"
                f"{self.bot.EMOJI_CORRECTO} Archivos e imágenes adjuntos\n"
                f"{self.bot.EMOJI_CORRECTO} Mensajes editados\n"
                f"{self.bot.EMOJI_CORRECTO} URLs acortadas (expansión automática)\n"
                f"{self.bot.EMOJI_CORRECTO} Doble extensión y verificación MIME"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Información",
            value=(
                f"{self.bot.EMOJI_STATS} **`/stats`** — Estadísticas globales\n"
                f"{self.bot.EMOJI_SHIELD} **`/about`** — Info del bot y sistema de caché\n"
                f"{self.bot.EMOJI_REPLY} **`/help`** — Este mensaje de ayuda"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación (solo administradores)",
            value=(
                f"{self.bot.EMOJI_REPLY} **`/usercheck`** — Infracciones de un usuario\n"
                f"{self.bot.EMOJI_GUARDIAN} **`/silentmode`** — Solo reacciones\n"
                f"{self.bot.EMOJI_GUARDIAN} **`/strictmode`** — Elimina mensajes peligrosos\n"
                f"{self.bot.EMOJI_WHITELIST} **`/whitelist`** — Dominios de confianza\n"
                f"{self.bot.EMOJI_REPLY} **`/setlogchannel`** — Canal de logs\n"
                f"{self.bot.EMOJI_INCORRECTO} **`/disablelogchannel`** — Desactiva logs\n"
                f"{self.bot.EMOJI_STATS} **`/settings`** — Configuración del servidor"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_KEY} Funcionalidades automáticas",
            value=(
                f"{self.bot.EMOJI_CORRECTO} **Caché inteligente**: memoria (1h) + BD (7-30 días)\n"
                f"{self.bot.EMOJI_WARNING} **NSFW**: nudity, weapons, alcohol, ofensivo\n"
                f"{self.bot.EMOJI_LINK} **VirusTotal**: hasta 3 keys (12 peticiones/min)\n"
                f"{self.bot.EMOJI_WHITELIST} **Whitelist**: ignora dominios seguros\n"
                f"{self.bot.EMOJI_COOLDOWN} **Anti-spam**: 30 análisis/hora por usuario"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_REPLY} Notas",
            value=(
                f"{self.bot.EMOJI_GUARDIAN} Comandos admin requieren permisos\n"
                f"{self.bot.EMOJI_WARNING} Modo silencioso siempre notifica amenazas\n"
                f"{self.bot.EMOJI_REPLY} Logs incluyen botones: banear, expulsar, ignorar\n"
                f"{self.bot.EMOJI_KEY} Prefijo del bot: `-` (ej. `-eval` para el propietario)"
            ),
            inline=False
        )

        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(HelpCog(bot))
