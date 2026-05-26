import logging
import discord
from discord.ext import commands
from discord import app_commands
from core.config import OWNER_ID, DATABASE_URL

log = logging.getLogger("dbtest")

class DbTestCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="dbtest", description="Prueba la conexión a la base de datos PostgreSQL (solo dueño)")
    async def dbtest(self, interaction: discord.Interaction) -> None:
        if str(interaction.user.id) != OWNER_ID:
            log.warning(f"DBTEST INTENTO NO AUTORIZADO → usuario={interaction.user} ({interaction.user.id})")
            await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} No tienes permiso para usar este comando.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        if not DATABASE_URL:
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Sin configurar",
                description="`DATABASE_URL` no está definida en el entorno.\nAgrega `DATABASE_URL` al archivo `.env`.",
                color=discord.Color.red()
            )
            await interaction.edit_original_response(embed=embed)
            return

        try:
            import asyncpg
            conn = await asyncpg.connect(DATABASE_URL, timeout=10)
            version = await conn.fetchval("SELECT version()")
            await conn.close()

            embed = discord.Embed(
                title=f"{self.bot.EMOJI_CORRECTO} Conexión exitosa",
                description=f"```\n{version}\n```",
                color=discord.Color.green()
            )
            embed.set_footer(text=f"URL: {_sanitizar_url(DATABASE_URL)}")
            log.info(f"DBTEST OK por {interaction.user} ({interaction.user.id}) — {version.split(',')[0]}")
            await interaction.edit_original_response(embed=embed)

        except ImportError:
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} asyncpg no instalado",
                description="Ejecutá `pip install asyncpg` en el servidor.",
                color=discord.Color.red()
            )
            await interaction.edit_original_response(embed=embed)

        except Exception as e:
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Error de conexión",
                description=f"```\n{e}\n```",
                color=discord.Color.red()
            )
            embed.set_footer(text=f"URL: {_sanitizar_url(DATABASE_URL)}")
            log.error(f"DBTEST ERROR por {interaction.user} ({interaction.user.id}): {e}")
            await interaction.edit_original_response(embed=embed)


def _sanitizar_url(url: str) -> str:
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url)
    if parsed.password:
        parsed = parsed._replace(password="****")
    if parsed.username:
        parsed = parsed._replace(username=parsed.username)
    return urlunparse(parsed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(DbTestCog(bot))
