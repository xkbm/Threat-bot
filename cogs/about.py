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
                "Bot de seguridad que analiza **URLs, IPs, hashes y archivos** usando la API de **VirusTotal**, "
                "con detección de **contenido inapropiado (NSFW)** mediante **Sightengine**.\n"
                "Incluye **caché inteligente**, **escaneo múltiple**, **sistema de infracciones** y **logs con botones**."
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} ¿Cómo funciona?",
            value=(
                "**Análisis automático:**\n"
                "• Enlaces en mensajes (múltiples URLs a la vez)\n"
                "• Archivos e imágenes adjuntos (varios en un solo mensaje)\n"
                "• Mensajes editados (cierre de seguridad)\n"
                "• URLs acortadas (expansión automática)\n"
                "• Doble extensión y verificación MIME\n\n"
                "**Comandos:**\n"
                "• `/scan` — Análisis manual de URL, IP, hash o archivo\n"
                "• `/stats` — Estadísticas globales de análisis\n"
                "• `/about` — Esta información\n"
                "• `/help` — Lista completa de comandos\n\n"
                "**Modos de seguridad:**\n"
                "• `/silentmode` — Solo reacciones, sin mensajes (excepto amenazas)\n"
                "• `/strictmode` — Elimina mensajes peligrosos automáticamente\n"
                "• `/settings` — Muestra la configuración actual del servidor\n\n"
                "**Gestión:**\n"
                "• `/whitelist` — Dominios de confianza ignorados en análisis\n"
                "• `/setlogchannel` — Canal para logs de amenazas (con botones)\n"
                "• `/disablelogchannel` — Desactiva los logs\n"
                "• `/usercheck` — Infracciones de seguridad de un usuario"
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_WARNING} Protección avanzada",
            value=(
                f"• **Detección NSFW multimodelo**: nudity, weapons, alcohol y contenido ofensivo.\n"
                f"• **Doble extensión**: detecta archivos con extensiones engañosas (ej. `foto.jpg.exe`).\n"
                f"• **Verificación MIME**: compara la extensión del archivo con su tipo real.\n"
                f"• **Expansión de URLs acortadas**: sigue redirecciones para analizar el destino final.\n"
                f"• **Escaneo de ediciones**: analiza automáticamente las URLs o archivos que se añaden al editar un mensaje.\n"
                f"• **Sistema de reputación**: infracciones por usuario con prevención de duplicados.\n"
                f"• **Logs con botones**: banear, expulsar o ignorar infracciones desde el canal de logs."
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
                "• **Ahorro de API**: Si un recurso ya fue analizado, se reutiliza el resultado sin consumir peticiones.\n"
                "• **Caché ahorrativa**: Antes de descargar, se verifica si el archivo ya fue analizado (por nombre/tamaño o hash)."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_KEY} Gestión de API Keys",
            value=(
                "• **Rotación automática**: reparte las peticiones entre hasta 3 claves de VirusTotal.\n"
                "• **Límites**: 4 peticiones/minuto y 500/día por clave (hasta 12/min y 1500/día totales).\n"
                "• **Tracking en `/stats`**: uso por minuto, uso diario y total histórico de cada clave.\n"
                "• **Sightengine**: rota hasta 3 pares de API keys para análisis NSFW."
            ),
            inline=False
        )

        embed.add_field(
            name=f"{self.bot.EMOJI_COOLDOWN} Anti-spam y límites",
            value=(
                "• **30 análisis por hora** por usuario.\n"
                "• **Cooldown de 10 segundos** entre análisis del mismo usuario.\n"
                "• **Máximo 5 URLs o archivos** por mensaje (para no saturar las APIs).\n"
                "• **Límites de tamaño**: 32 MB para archivos (VirusTotal) y 2 MB para imágenes (Sightengine)."
            ),
            inline=False
        )

        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(InfoCog(bot))