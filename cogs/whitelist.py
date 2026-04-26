import discord
from discord.ext import commands
from discord import app_commands
from urllib.parse import urlparse

# ========== DOMINIOS PROTEGIDOS (NO ELIMINABLES) ==========
DOMINIOS_PROTEGIDOS = [
    "youtube.com", "youtu.be", "google.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "reddit.com", "twitter.com",
    "x.com", "twitch.tv", "spotify.com", "microsoft.com",
    "apple.com", "amazon.com", "discord.com"
]

class WhitelistCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    def obtener_whitelist(self, guild_id):
        config = self.bot.obtener_config_guild(guild_id)
        if "whitelist" not in config:
            config["whitelist"] = DOMINIOS_PROTEGIDOS.copy()
            self.bot.guardar_datos()
        return config["whitelist"]

    def guardar_whitelist(self, guild_id, whitelist):
        config = self.bot.obtener_config_guild(guild_id)
        config["whitelist"] = whitelist
        self.bot.guardar_datos()

    @app_commands.command(name="whitelist", description="Gestiona la lista de dominios seguros (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.choices(accion=[
        app_commands.Choice(name="add", value="add"),
        app_commands.Choice(name="remove", value="remove"),
        app_commands.Choice(name="list", value="list")
    ])
    async def whitelist(self, interaction: discord.Interaction, accion: app_commands.Choice[str], dominio: str = None):
        if not interaction.guild:
            await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            return

        whitelist = self.obtener_whitelist(interaction.guild.id)

        if accion.value == "add":
            if not dominio:
                await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para añadir.", ephemeral=True)
                return
            dominio = dominio.lower().removeprefix("www.")
            if dominio in whitelist:
                await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` ya está en la whitelist.", ephemeral=True)
                return
            whitelist.append(dominio)
            self.guardar_whitelist(interaction.guild.id, whitelist)
            await interaction.response.send_message(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` añadido a la whitelist.", ephemeral=True)

        elif accion.value == "remove":
            if not dominio:
                await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para eliminar.", ephemeral=True)
                return
            dominio = dominio.lower().removeprefix("www.")
            if dominio not in whitelist:
                await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no está en la whitelist.", ephemeral=True)
                return
            if dominio in DOMINIOS_PROTEGIDOS:
                await interaction.response.send_message(f"{self.bot.EMOJI_WARNING} `{dominio}` es un dominio protegido y no puede eliminarse.", ephemeral=True)
                return
            whitelist.remove(dominio)
            self.guardar_whitelist(interaction.guild.id, whitelist)
            await interaction.response.send_message(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` eliminado de la whitelist.", ephemeral=True)

        elif accion.value == "list":
            if not whitelist:
                await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} No hay dominios en la whitelist.", ephemeral=True)
                return
            lista = "\n".join(f"• `{d}`" for d in whitelist)
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_SHIELD} Whitelist de {interaction.guild.name}",
                description=lista,
                color=discord.Color.blue()
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)

async def setup(bot):
    await bot.add_cog(WhitelistCog(bot))