import discord
from discord.ext import commands
from discord import app_commands
import time
import logging

log = logging.getLogger("about")

class InfoCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.start_time: float = time.time()

    @app_commands.command(name="uptime", description="Muestra el tiempo que lleva el bot en línea")
    async def uptime(self, interaction: discord.Interaction) -> None:
        log.debug(f"UPTIME → usuario={interaction.user.id}")
        await interaction.response.defer(ephemeral=True)

        delta = time.time() - self.start_time
        days, rem = divmod(int(delta), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)

        parts: list[str] = []
        if days: parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        uptime_str = " ".join(parts)

        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Tiempo en línea",
            description=f"El bot lleva **{uptime_str}** funcionando.",
            color=discord.Color.green()
        )
        try:
            await interaction.edit_original_response(embed=embed)
        except discord.errors.NotFound:
            pass

    @app_commands.command(name="ping", description="Muestra la latencia del bot")
    async def ping(self, interaction: discord.Interaction) -> None:
        log.debug(f"PING → usuario={interaction.user.id}")
        await interaction.response.defer(ephemeral=True)

        ws_latency = round(self.bot.latency * 1000)
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Pong!",
            description=f"Latencia WebSocket: **{ws_latency}ms**",
            color=discord.Color.green()
        )
        try:
            await interaction.edit_original_response(embed=embed)
        except discord.errors.NotFound:
            pass

    @app_commands.command(name="about", description="Información detallada sobre las capacidades y funcionamiento del bot de seguridad Threat")
    async def about(self, interaction: discord.Interaction) -> None:
        log.debug(f"ABOUT → usuario={interaction.user.id} guild={interaction.guild.id if interaction.guild else None}")
        await interaction.response.defer()
        
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Acerca de Threat",
            description=(
                "Threat es un bot de seguridad para Discord que protege tu servidor "
                "analizando enlaces, archivos y contenido NSFW en tiempo real."
            ),
            color=discord.Color(0x36393F)
        )

        embed.add_field(
            name="Qué hace",
            value=(
                "• Analiza **URLs** contra la base de datos de VirusTotal\n"
                "• Detecta **imágenes NSFW** con Sightengine\n"
                "• Escanea **archivos** adjuntos (hasta 32MB)\n"
                "• Verifica **IPs** y **hashes** sospechosos\n"
                "• **Funciona solo** — solo tienes que añadirlo y olvidarte"
            ),
            inline=False
        )

        embed.add_field(
            name="Cómo protege",
            value=(
                "• Analiza automáticamente cada enlace enviado en el chat\n"
                "• Reacciona con iconos de alerta si detecta amenazas\n"
                "• Los moderadores pueden configurar un **canal de logs**\n"
                "• Modo estricto elimina mensajes peligrosos automáticamente\n"
                "• **Whitelist** para dominios de confianza"
            ),
            inline=False
        )

        embed.set_footer(
            text="El proyecto acualmente es de codigo cerrado, pero puede que en un futuro se vuelva open source. Si quieres apoyar el proyecto puedes compartirlo con otros."
        )

        view = discord.ui.View()
        view.add_item(discord.ui.Button(
            style=discord.ButtonStyle.link,
            url="https://threat-bot-discord.vercel.app",
            label="Sitio Web",
            emoji=self.bot.EMOJI_LINK
        ))
        view.add_item(discord.ui.Button(
            style=discord.ButtonStyle.link,
            url="https://github.com/xkbm",
            label="GitHub",
            emoji=self.bot.EMOJI_GITHUB
        ))

        try:
            await interaction.edit_original_response(embed=embed, view=view)
        except discord.errors.NotFound:
            pass

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(InfoCog(bot))
