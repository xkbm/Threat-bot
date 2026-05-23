import re
from typing import Optional
import logging
import discord
from discord.ext import commands
from discord import app_commands
from core.config import DOMINIOS_PROTEGIDOS
from ui.views import WhitelistPaginatorView

log = logging.getLogger("whitelist")
PATRON_DOMINIO: re.Pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

class WhitelistCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    def obtener_whitelist(self, guild_id: int) -> list[str]:
        config = self.bot.obtener_config_guild(guild_id)
        return config["whitelist"]

    async def guardar_whitelist(self, guild_id: int, whitelist: list[str]) -> None:
        config = self.bot.obtener_config_guild(guild_id)
        config["whitelist"] = whitelist
        await self.bot.guardar_datos(inmediato=True)

    @app_commands.command(name="whitelist", description="Gestiona la lista de dominios seguros (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.choices(accion=[
        app_commands.Choice(name="add", value="add"),
        app_commands.Choice(name="remove", value="remove"),
        app_commands.Choice(name="list", value="list")
    ])
    async def whitelist(self, interaction: discord.Interaction, accion: app_commands.Choice[str], dominio: Optional[str] = None) -> None:
        if not interaction.guild:
            try:
                await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            except discord.errors.NotFound:
                pass
            return

        whitelist = self.obtener_whitelist(interaction.guild.id)

        if accion.value == "add":
            if not dominio:
                log.debug(f"WHITELIST ADD → guild={interaction.guild.id} sin dominio")
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para añadir.", ephemeral=True)
                except discord.errors.NotFound:
                    pass
                return
            dominio = dominio.lower()
            if dominio.startswith("www."):
                dominio = dominio[4:]
            if not PATRON_DOMINIO.match(dominio):
                log.debug(f"WHITELIST ADD → guild={interaction.guild.id} dominio inválido: {dominio}")
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no es un dominio válido.", ephemeral=True)
                except discord.errors.NotFound:
                    pass
                return
            if dominio in whitelist:
                log.debug(f"WHITELIST ADD → guild={interaction.guild.id} ya existe: {dominio}")
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` ya está en la whitelist.", ephemeral=True)
                except discord.errors.NotFound:
                    pass
                return
            whitelist.append(dominio)
            await self.guardar_whitelist(interaction.guild.id, whitelist)
            log.debug(f"WHITELIST ADD OK → guild={interaction.guild.id} dominio={dominio} admin={interaction.user.id}")
            try:
                await interaction.response.send_message(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` añadido a la whitelist.", ephemeral=True)
            except discord.errors.NotFound:
                pass

        elif accion.value == "remove":
            if not dominio:
                log.debug(f"WHITELIST REMOVE → guild={interaction.guild.id} sin dominio")
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para eliminar.", ephemeral=True)
                except discord.errors.NotFound:
                    pass
                return
            dominio = dominio.lower()
            if dominio.startswith("www."):
                dominio = dominio[4:]
            if dominio not in whitelist:
                log.debug(f"WHITELIST REMOVE → guild={interaction.guild.id} no encontrado: {dominio}")
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no está en la whitelist.", ephemeral=True)
                except discord.errors.NotFound:
                    pass
                return
            if dominio in DOMINIOS_PROTEGIDOS:
                log.debug(f"WHITELIST REMOVE → guild={interaction.guild.id} protegido: {dominio}")
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_WARNING} `{dominio}` es un dominio protegido y no puede eliminarse.", ephemeral=True)
                except discord.errors.NotFound:
                    pass
                return
            whitelist.remove(dominio)
            await self.guardar_whitelist(interaction.guild.id, whitelist)
            log.debug(f"WHITELIST REMOVE OK → guild={interaction.guild.id} dominio={dominio} admin={interaction.user.id}")
            try:
                await interaction.response.send_message(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` eliminado de la whitelist.", ephemeral=True)
            except discord.errors.NotFound:
                pass

        elif accion.value == "list":
            if not whitelist:
                log.debug(f"WHITELIST LIST → guild={interaction.guild.id} vacía")
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} No hay dominios en la whitelist.", ephemeral=True)
                except discord.errors.NotFound:
                    pass
                return
            log.debug(f"WHITELIST LIST → guild={interaction.guild.id} total={len(whitelist)} admin={interaction.user.id}")
            if len(whitelist) <= 20:
                lista = "\n".join(f"• `{d}`" for d in whitelist)
                embed = discord.Embed(
                    title=f"{self.bot.EMOJI_SHIELD} Whitelist de {interaction.guild.name}",
                    description=lista,
                    color=discord.Color.blue()
                )
                try:
                    await interaction.response.send_message(embed=embed, ephemeral=True)
                except discord.errors.NotFound:
                    pass
            else:
                view = WhitelistPaginatorView(interaction.guild.name, whitelist, self.bot.EMOJI_SHIELD)
                try:
                    await interaction.response.send_message(embed=view.get_page_embed(), view=view, ephemeral=True)
                except discord.errors.NotFound:
                    pass

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(WhitelistCog(bot))
