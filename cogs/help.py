import discord
from discord.ext import commands
from discord import app_commands

class HelpCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="help", description="Muestra todos los comandos disponibles de Threat")
    async def help_command(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Comandos de Threat",
            description=(
                "Bot de seguridad con análisis automático y manual usando **VirusTotal** y **Sightengine (NSFW)**.\n"
                "Incluye escaneo de mensajes editados, sistema de reputación y caché inteligente."
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} Análisis",
            value=(
                f"**`/scan`** — Analiza manualmente una URL, IP, hash o archivo.\n"
                f"*Uso:* `/scan tipo:url valor:https://ejemplo.com`\n"
                f"**Detección automática** — El bot analiza automáticamente:\n"
                f"• Enlaces en mensajes (múltiples URLs a la vez)\n"
                f"• Archivos e imágenes adjuntos\n"
                f"• Mensajes editados (cierres de seguridad)\n"
                f"• URLs acortadas (expansión automática)\n"
                f"• Doble extensión y verificación MIME"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Información",
            value=(
                f"**`/stats`** — Estadísticas globales: análisis, amenazas y uso de API keys.\n"
                f"**`/about`** — Información sobre el funcionamiento del bot y sistema de caché.\n"
                f"**`/help`** — Muestra este mensaje de ayuda."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} Moderación (solo administradores)",
            value=(
                f"**`/usercheck @usuario`** — Infracciones de seguridad acumuladas.\n"
                f"**`/silentmode <true/false>`** — Solo reacciones, sin mensajes (excepto amenazas).\n"
                f"**`/strictmode <true/false>`** — Elimina automáticamente mensajes peligrosos.\n"
                f"**`/whitelist <add/remove/list> <dominio>`** — Gestiona dominios de confianza.\n"
                f"**`/setlogchannel #canal`** — Establece el canal para logs de amenazas.\n"
                f"**`/disablelogchannel`** — Desactiva el envío de logs."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_KEY} Funcionalidades automáticas",
            value=(
                f"{self.bot.EMOJI_CORRECTO} **Caché inteligente**: memoria (1h) + base de datos (7‑30 días).\n"
                f"{self.bot.EMOJI_WARNING} **Detección NSFW**: nudity, weapons, alcohol, ofensivo.\n"
                f"{self.bot.EMOJI_LINK} **VirusTotal**: rota hasta 3 API keys (12 peticiones/min).\n"
                f"{self.bot.EMOJI_WHITELIST} **Whitelist**: ignora dominios seguros.\n"
                f"{self.bot.EMOJI_COOLDOWN} **Anti‑spam**: 30 análisis/hora por usuario."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_REPLY} Notas",
            value=(
                "• Los comandos de administrador requieren el permiso correspondiente.\n"
                "• El modo silencioso **siempre** notifica amenazas reales.\n"
                "• Los logs incluyen botones para banear, expulsar o ignorar infracciones.\n"
                "• Prefijo del bot: `-` (ej. `-eval` para el dueño)."
            ),
            inline=False
        )

        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(HelpCog(bot))