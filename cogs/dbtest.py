import logging
import discord
from discord.ext import commands
from discord import app_commands
from core.config import OWNER_ID, DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

log = logging.getLogger("dbtest")

class DbTestCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="dbtest", description="Prueba la conexión a la base de datos MySQL (solo dueño)")
    async def dbtest(self, interaction: discord.Interaction) -> None:
        if str(interaction.user.id) != OWNER_ID:
            log.warning(f"DBTEST INTENTO NO AUTORIZADO → usuario={interaction.user} ({interaction.user.id})")
            await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} No tienes permiso para usar este comando.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        campos = []
        for var, val in [("DB_HOST", DB_HOST), ("DB_PORT", DB_PORT), ("DB_USER", DB_USER), ("DB_PASSWORD", DB_PASSWORD), ("DB_NAME", DB_NAME)]:
            estado = f"{self.bot.EMOJI_CORRECTO} {var}" if val else f"{self.bot.EMOJI_INCORRECTO} {var}"
            campos.append(estado)

        if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Configuración incompleta",
                description="Faltan variables de base de datos en `.env`:\n" + "\n".join(campos),
                color=discord.Color.red()
            )
            await interaction.edit_original_response(embed=embed)
            return

        try:
            import aiomysql
            conn = await aiomysql.connect(
                host=DB_HOST,
                port=int(DB_PORT) if DB_PORT else 3306,
                user=DB_USER,
                password=DB_PASSWORD,
                db=DB_NAME,
                connect_timeout=10,
            )
            cur = await conn.cursor()
            await cur.execute("SELECT version()")
            version = (await cur.fetchone())[0]
            await cur.close()
            conn.close()

            embed = discord.Embed(
                title=f"{self.bot.EMOJI_CORRECTO} Conexión exitosa",
                description=f"```\n{version}\n```",
                color=discord.Color.green()
            )
            embed.set_footer(text=f"{DB_USER}@{DB_HOST}:{DB_PORT or 3306}/{DB_NAME}")
            log.info(f"DBTEST OK por {interaction.user} ({interaction.user.id}) — {version.split(',')[0]}")
            await interaction.edit_original_response(embed=embed)

        except ImportError:
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} aiomysql no instalado",
                description="Ejecutá `pip install aiomysql` en el servidor.",
                color=discord.Color.red()
            )
            await interaction.edit_original_response(embed=embed)

        except Exception as e:
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Error de conexión",
                description=f"```\n{e}\n```" if str(e).strip() else "Sin detalles.",
                color=discord.Color.red()
            )
            embed.set_footer(text=f"{DB_USER}@{DB_HOST}:{DB_PORT or 3306}/{DB_NAME}")
            log.error(f"DBTEST ERROR por {interaction.user} ({interaction.user.id}): {e}")
            await interaction.edit_original_response(embed=embed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(DbTestCog(bot))
