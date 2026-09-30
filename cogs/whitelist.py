import re
from typing import Optional
import logging
import discord
from discord.ext import commands
from discord import app_commands
from core.config import DOMINIOS_PROTEGIDOS
from core.guild_config import agregar_dominio, quitar_dominio
from ui.views import WhitelistPaginatorView
from ui import embed as emb

log = logging.getLogger("whitelist")
PATRON_DOMINIO: re.Pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def _normalizar_dominio(dominio: str) -> str:
    """Minúsculas y sin prefijo www., como espera la comparación de dominio."""
    dominio = dominio.lower().strip()
    return dominio[4:] if dominio.startswith("www.") else dominio


async def _responder(interaction: discord.Interaction, contenido: str) -> None:
    try:
        await interaction.response.send_message(contenido, ephemeral=True)
    except discord.errors.NotFound:
        pass


class WhitelistCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def obtener_whitelist(self, guild_id: int) -> list[str]:
        config = await self.bot.obtener_config_guild(guild_id)
        return config["whitelist"]

    @app_commands.command(name="whitelist", description="Gestiona la lista de dominios seguros (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.choices(accion=[
        app_commands.Choice(name="add", value="add"),
        app_commands.Choice(name="remove", value="remove"),
        app_commands.Choice(name="list", value="list")
    ])
    async def whitelist(self, interaction: discord.Interaction, accion: app_commands.Choice[str], dominio: Optional[str] = None) -> None:
        if not interaction.guild:
            await _responder(interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.")
            return

        guild_id = interaction.guild.id
        whitelist = await self.obtener_whitelist(guild_id)

        if accion.value in ("add", "remove"):
            if not dominio:
                log.debug(f"WHITELIST {accion.value.upper()} → guild={guild_id} sin dominio")
                await _responder(interaction, f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para {'añadir' if accion.value == 'add' else 'eliminar'}.")
                return

            dominio = _normalizar_dominio(dominio)

            if accion.value == "add":
                if not PATRON_DOMINIO.match(dominio):
                    log.debug(f"WHITELIST ADD → guild={guild_id} dominio inválido: {dominio}")
                    await _responder(interaction, f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no es un dominio válido.")
                    return
                if dominio in whitelist:
                    log.debug(f"WHITELIST ADD → guild={guild_id} ya existe: {dominio}")
                    await _responder(interaction, f"{self.bot.EMOJI_INCORRECTO} `{dominio}` ya está en la whitelist.")
                    return
                await agregar_dominio(guild_id, dominio)
                log.debug(f"WHITELIST ADD OK → guild={guild_id} dominio={dominio} admin={interaction.user.id}")
                await _responder(interaction, f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` añadido a la whitelist.")
                return

            if dominio not in whitelist:
                log.debug(f"WHITELIST REMOVE → guild={guild_id} no encontrado: {dominio}")
                await _responder(interaction, f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no está en la whitelist.")
                return
            if dominio in DOMINIOS_PROTEGIDOS:
                log.debug(f"WHITELIST REMOVE → guild={guild_id} protegido: {dominio}")
                await _responder(interaction, f"{self.bot.EMOJI_WARNING} `{dominio}` es un dominio protegido y no puede eliminarse.")
                return
            await quitar_dominio(guild_id, dominio)
            log.debug(f"WHITELIST REMOVE OK → guild={guild_id} dominio={dominio} admin={interaction.user.id}")
            await _responder(interaction, f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` eliminado de la whitelist.")
            return

        if not whitelist:
            log.debug(f"WHITELIST LIST → guild={guild_id} vacía")
            await _responder(interaction, f"{self.bot.EMOJI_INCORRECTO} No hay dominios en la whitelist.")
            return

        log.debug(f"WHITELIST LIST → guild={guild_id} total={len(whitelist)} admin={interaction.user.id}")
        if len(whitelist) <= 20:
            lista = "\n".join(f"• `{d}`" for d in whitelist)
            embed = emb.aviso(f"Whitelist de {interaction.guild.name}", lista)
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
