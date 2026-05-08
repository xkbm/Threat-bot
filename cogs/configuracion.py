import discord
from discord.ext import commands
from discord import app_commands

class ConfiguracionCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="silentmode", description="Activa/desactiva el modo silencioso (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(estado="True = silencioso, False = normal")
    async def silentmode(self, interaction: discord.Interaction, estado: bool):
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        config = self.bot.obtener_config_guild(interaction.guild.id)
        config["silent_mode"] = estado
        await self.bot.guardar_datos(inmediato=True)
        await interaction.followup.send(f"{self.bot.EMOJI_CORRECTO} Modo silencioso {'activado' if estado else 'desactivado'}.", ephemeral=True)

    @app_commands.command(name="strictmode", description="Activa/desactiva el modo estricto (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(estado="True = estricto, False = normal")
    async def strictmode(self, interaction: discord.Interaction, estado: bool):
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        config = self.bot.obtener_config_guild(interaction.guild.id)
        config["strict_mode"] = estado
        await self.bot.guardar_datos(inmediato=True)
        await interaction.followup.send(f"{self.bot.EMOJI_CORRECTO} Modo estricto {'activado' if estado else 'desactivado'}.", ephemeral=True)

    @app_commands.command(name="setlogchannel", description="Establece el canal para logs de amenazas (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(canal="Canal donde se enviarán los logs")
    async def setlogchannel(self, interaction: discord.Interaction, canal: discord.TextChannel):
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        config = self.bot.obtener_config_guild(interaction.guild.id)
        config["log_channel_id"] = canal.id
        await self.bot.guardar_datos(inmediato=True)
        await interaction.followup.send(f"{self.bot.EMOJI_CORRECTO} Canal de logs establecido a {canal.mention}.", ephemeral=True)

    @app_commands.command(name="disablelogchannel", description="Desactiva el envío de logs (solo admins)")
    @app_commands.default_permissions(administrator=True)
    async def disablelogchannel(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        config = self.bot.obtener_config_guild(interaction.guild.id)
        config["log_channel_id"] = None
        await self.bot.guardar_datos(inmediato=True)
        await interaction.followup.send(f"{self.bot.EMOJI_CORRECTO} Logs desactivados.", ephemeral=True)

    @app_commands.command(name="settings", description="Muestra la configuración actual del bot en este servidor (solo admins)")
    @app_commands.default_permissions(administrator=True)
    async def settings(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return
        config = self.bot.obtener_config_guild(interaction.guild.id)
        silent = config.get("silent_mode", False)
        strict = config.get("strict_mode", False)
        log_id = config.get("log_channel_id")
        log_channel = interaction.guild.get_channel(log_id) if log_id else None

        descripcion = (
            f"{self.bot.EMOJI_GUARDIAN} **Modo silencioso:** {'Activado' if silent else 'Desactivado'}\n"
            f"{self.bot.EMOJI_WARNING} **Modo estricto:** {'Activado' if strict else 'Desactivado'}\n"
            f"{self.bot.EMOJI_LINK} **Canal de logs:** {log_channel.mention if log_channel else '*No configurado*'}"
        )
        embed = discord.Embed(
            title=f"{self.bot.EMOJI_SHIELD} Configuración del servidor",
            description=descripcion,
            color=discord.Color.blue()
        )
        await interaction.followup.send(embed=embed, ephemeral=True)

async def setup(bot):
    await bot.add_cog(ConfiguracionCog(bot))