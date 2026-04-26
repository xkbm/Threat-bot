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
            description="Bot de seguridad con análisis automático y manual usando VirusTotal y Sightengine (NSFW).",
            color=discord.Color.blue()
        )
        embed.add_field(
            name=f"{self.bot.EMOJI_LUPA} `/scan`",
            value="Analiza manualmente una URL, IP, hash o archivo.\n*Uso:* `/scan tipo:url valor:https://ejemplo.com`",
            inline=False
        )
        embed.add_field(
            name=f"{self.bot.EMOJI_STATS} `/stats`",
            value="Muestra estadísticas globales del bot (total análisis, seguros, maliciosos, errores).",
            inline=False
        )
        embed.add_field(
            name=f"{self.bot.EMOJI_SHIELD} `/about`",
            value="Información sobre el funcionamiento del bot y su sistema de caché.",
            inline=False
        )
        embed.add_field(
            name=f"{self.bot.EMOJI_GUARDIAN} `/silentmode` (admin)",
            value="Activa o desactiva el modo silencioso (solo reacciones, sin mensajes automáticos).",
            inline=False
        )
        embed.add_field(
            name=f"{self.bot.EMOJI_WARNING} `/strictmode` (admin)",
            value="Activa o desactiva el modo estricto (elimina automáticamente mensajes maliciosos).",
            inline=False
        )
        embed.add_field(
            name=f"{self.bot.EMOJI_LINK} `/setlogchannel` (admin)",
            value="Establece un canal para recibir logs detallados de amenazas.",
            inline=False
        )
        embed.add_field(
            name=f"{self.bot.EMOJI_INCORRECTO} `/disablelogchannel` (admin)",
            value="Desactiva el envío de logs de amenazas.",
            inline=False
        )
        await interaction.response.send_message(embed=embed)

async def setup(bot):
    await bot.add_cog(HelpCog(bot))