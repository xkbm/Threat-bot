import discord
from discord.ext import commands
from discord import app_commands
import logging

log = logging.getLogger("help")

class HelpCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="help", description="Lista completa de comandos y funcionalidades del bot de seguridad Threat")
    async def help_command(self, interaction: discord.Interaction):
        log.debug(f"HELP → usuario={interaction.user.id} guild={interaction.guild.id if interaction.guild else None}")
        await interaction.response.defer()
        
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Comandos de Threat",
            description=(
                "Análisis automático y manual con VirusTotal + Sightengine.\n"
                "Escaneo de mensajes, reputación y caché inteligente."
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis",
            value=(
                "**`/scan`** — Analiza URL, IP, hash o archivo\n"
                "└ *Ejemplo:* `/scan tipo:url valor:https://ejemplo.com`\n\n"
                "**Detección automática:**\n"
                "• Enlaces en mensajes\n"
                "• Archivos e imágenes adjuntos\n"
                "• Mensajes editados\n"
                "• URLs acortadas (expansión automática)\n"
                "• Doble extensión y verificación MIME"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Información",
            value=(
                "• **`/stats`** — Estadísticas globales\n"
                "• **`/about`** — Info del bot y sistema de caché\n"
                "• **`/help`** — Este mensaje de ayuda"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación (solo administradores)",
            value=(
                "• **`/usercheck`** — Infracciones de un usuario\n"
                "• **`/silentmode`** — Solo reacciones\n"
                "• **`/strictmode`** — Elimina mensajes peligrosos\n"
                "• **`/whitelist`** — Dominios de confianza\n"
                "• **`/setlogchannel`** — Canal de logs\n"
                "• **`/disablelogchannel`** — Desactiva logs\n"
                "• **`/settings`** — Configuración del servidor"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_KEY} Funcionalidades automáticas",
            value=(
                "• **Caché inteligente**: memoria (1h) + BD (7-30 días)\n"
                "• **NSFW**: nudity, weapons, alcohol, ofensivo\n"
                "• **VirusTotal**: hasta 3 keys (12 peticiones/min)\n"
                "• **Whitelist**: ignora dominios seguros\n"
                "• **Anti-spam**: 30 análisis/hora por usuario"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_REPLY} Notas",
            value=(
                "• Comandos admin requieren permisos\n"
                "• Modo silencioso siempre notifica amenazas\n"
                "• Logs incluyen botones: banear, expulsar, ignorar\n"
                "• `-eval` para ejecutar código Python (solo propietario)"
            ),
            inline=False
        )

        try:
            await interaction.edit_original_response(embed=embed)
        except discord.errors.NotFound:
            # La interacción expiró antes de que pudieramos responder - no hay nada que hacer
            pass

async def setup(bot):
    await bot.add_cog(HelpCog(bot))