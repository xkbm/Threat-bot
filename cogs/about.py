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
            description="Bot de seguridad que analiza URLs, IPs, hashes y archivos usando la API de VirusTotal, "
                        "con detección de contenido inapropiado mediante Sightengine.",
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} ¿Cómo funciona?",
            value=(
                "• **Análisis automático**: Detecta enlaces y archivos en los mensajes y los analiza al instante.\n"
                "• **Comando `/scan`**: Análisis manual de cualquier URL, IP, hash o archivo.\n"
                "• **Modos de seguridad**: `/silentmode` (solo reacciones) y `/strictmode` (elimina mensajes maliciosos).\n"
                "• **Logs**: `/setlogchannel` para recibir alertas detalladas en un canal privado.\n"
                "• **Estadísticas**: `/stats` muestra total de análisis, amenazas detectadas y uso de API keys.\n"
                "• **Whitelist**: `/whitelist` gestiona dominios de confianza que se ignoran en los análisis.\n"
                "• **Reputación**: `/usercheck` consulta las infracciones acumuladas por un usuario.\n\n"
                "**Protección avanzada:**\n"
                "• **Detección NSFW multimodelo**: nudity, weapons, alcohol y contenido ofensivo.\n"
                "• **Doble extensión**: detecta archivos con extensiones engañosas (ej. `foto.jpg.exe`).\n"
                "• **Verificación MIME**: compara la extensión del archivo con su tipo real.\n"
                "• **Expansión de URLs acortadas**: sigue redirecciones para analizar el destino final.\n"
                "• **Escaneo de ediciones**: analiza automáticamente las URLs o archivos que se añaden al editar un mensaje."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} Sistema de caché",
            value=(
                "• **Caché en memoria**: Guarda resultados durante **1 hora** para respuestas instantáneas.\n"
                "• **Base de datos SQLite**: Almacena resultados de forma persistente con expiración:\n"
                "   - URLs e IPs: **7 días**\n"
                "   - Hashes y archivos: **30 días**\n"
                "   - Imágenes NSFW: **30 días** (usando hash **SHA-256** del contenido)\n"
                "• **Ahorro de API**: Si un recurso ya fue analizado, se reutiliza el resultado sin consumir peticiones."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_KEY} Gestión de API Keys",
            value=(
                "• **Rotación automática**: reparte las peticiones entre hasta 3 claves de VirusTotal.\n"
                "• **Límites**: 4 peticiones/minuto y 500/día por clave (hasta 12/min y 1500/día totales).\n"
                "• **Tracking en `/stats`**: uso por minuto, uso diario y total histórico de cada clave."
            ),
            inline=False
        )

        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(InfoCog(bot))