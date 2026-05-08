import re
import discord
from discord.ext import commands
from discord import app_commands
from core.config import DOMINIOS_PROTEGIDOS

PATRON_DOMINIO = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

class WhitelistCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    def obtener_whitelist(self, guild_id):
        config = self.bot.obtener_config_guild(guild_id)
        return config["whitelist"]

    async def guardar_whitelist(self, guild_id, whitelist):
        config = self.bot.obtener_config_guild(guild_id)
        config["whitelist"] = whitelist
        await self.bot.guardar_datos(inmediato=True)

    async def _responder(self, interaction, mensaje, **kwargs):
        """Helper para responder con manejo de errores."""
        try:
            await interaction.response.send_message(mensaje, **kwargs)
        except discord.errors.NotFound:
            try:
                await interaction.followup.send(mensaje, **kwargs)
            except Exception as e:
                print(f"Error al responder en whitelist: {e}")

    @app_commands.command(name="whitelist", description="Gestiona la lista de dominios seguros (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.choices(accion=[
        app_commands.Choice(name="add", value="add"),
        app_commands.Choice(name="remove", value="remove"),
        app_commands.Choice(name="list", value="list")
    ])
    async def whitelist(self, interaction: discord.Interaction, accion: app_commands.Choice[str], dominio: str = None):
        if not interaction.guild:
            try:
                await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
            except discord.errors.NotFound:
                try:
                    await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.", ephemeral=True)
                except Exception as e:
                    print(f"Error al responder en whitelist: {e}")
            return

        whitelist = self.obtener_whitelist(interaction.guild.id)

        if accion.value == "add":
            if not dominio:
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para añadir.", ephemeral=True)
                except discord.errors.NotFound:
                    try:
                        await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para añadir.", ephemeral=True)
                    except Exception as e:
                        print(f"Error al responder en whitelist: {e}")
                return
            dominio = dominio.lower()
            if dominio.startswith("www."):
                dominio = dominio[4:]
            if not PATRON_DOMINIO.match(dominio):
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no es un dominio válido.", ephemeral=True)
                except discord.errors.NotFound:
                    try:
                        await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no es un dominio válido.", ephemeral=True)
                    except Exception as e:
                        print(f"Error al responder en whitelist: {e}")
                return
            if dominio in whitelist:
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` ya está en la whitelist.", ephemeral=True)
                except discord.errors.NotFound:
                    try:
                        await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` ya está en la whitelist.", ephemeral=True)
                    except Exception as e:
                        print(f"Error al responder en whitelist: {e}")
                return
            whitelist.append(dominio)
            await self.guardar_whitelist(interaction.guild.id, whitelist)
            try:
                await interaction.response.send_message(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` añadido a la whitelist.", ephemeral=True)
            except discord.errors.NotFound:
                try:
                    await interaction.followup.send(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` añadido a la whitelist.", ephemeral=True)
                except Exception as e:
                    print(f"Error al responder en whitelist: {e}")

        elif accion.value == "remove":
            if not dominio:
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para eliminar.", ephemeral=True)
                except discord.errors.NotFound:
                    try:
                        await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} Especifica un dominio para eliminar.", ephemeral=True)
                    except Exception as e:
                        print(f"Error al responder en whitelist: {e}")
                return
            dominio = dominio.lower()
            if dominio.startswith("www."):
                dominio = dominio[4:]
            if dominio not in whitelist:
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no está en la whitelist.", ephemeral=True)
                except discord.errors.NotFound:
                    try:
                        await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} `{dominio}` no está en la whitelist.", ephemeral=True)
                    except Exception as e:
                        print(f"Error al responder en whitelist: {e}")
                return
            if dominio in DOMINIOS_PROTEGIDOS:
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_WARNING} `{dominio}` es un dominio protegido y no puede eliminarse.", ephemeral=True)
                except discord.errors.NotFound:
                    try:
                        await interaction.followup.send(f"{self.bot.EMOJI_WARNING} `{dominio}` es un dominio protegido y no puede eliminarse.", ephemeral=True)
                    except Exception as e:
                        print(f"Error al responder en whitelist: {e}")
                return
            whitelist.remove(dominio)
            await self.guardar_whitelist(interaction.guild.id, whitelist)
            try:
                await interaction.response.send_message(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` eliminado de la whitelist.", ephemeral=True)
            except discord.errors.NotFound:
                try:
                    await interaction.followup.send(f"{self.bot.EMOJI_CORRECTO} Dominio `{dominio}` eliminado de la whitelist.", ephemeral=True)
                except Exception as e:
                    print(f"Error al responder en whitelist: {e}")

        elif accion.value == "list":
            if not whitelist:
                try:
                    await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} No hay dominios en la whitelist.", ephemeral=True)
                except discord.errors.NotFound:
                    try:
                        await interaction.followup.send(f"{self.bot.EMOJI_INCORRECTO} No hay dominios en la whitelist.", ephemeral=True)
                    except Exception as e:
                        print(f"Error al responder en whitelist: {e}")
                return
            lista = "\n".join(f"• `{d}`" for d in whitelist)
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_SHIELD} Whitelist de {interaction.guild.name}",
                description=lista,
                color=discord.Color.blue()
            )
            try:
                await interaction.response.send_message(embed=embed, ephemeral=True)
            except discord.errors.NotFound:
                try:
                    await interaction.followup.send(embed=embed, ephemeral=True)
                except Exception as e:
                    print(f"Error al responder en whitelist: {e}")

async def setup(bot):
    await bot.add_cog(WhitelistCog(bot))