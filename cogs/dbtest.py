import socket
import logging
import discord
from discord.ext import commands
from discord import app_commands
from core.config import OWNER_ID, DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

log = logging.getLogger("dbtest")

import aiohttp


async def _container_info(session: aiohttp.ClientSession) -> dict:
    hostname = socket.gethostname()
    local_ips = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip not in local_ips:
                local_ips.append(ip)
    except Exception:
        pass
    public_ip = None
    try:
        async with session.get("https://api.ipify.org", timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                public_ip = (await resp.text()).strip()
    except Exception:
        pass
    return {"hostname": hostname, "local_ips": local_ips, "public_ip": public_ip}

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

        info = await _container_info(self.bot.session)

        campos = []
        for var, val in [("DB_HOST", DB_HOST), ("DB_PORT", DB_PORT), ("DB_USER", DB_USER), ("DB_PASSWORD", DB_PASSWORD), ("DB_NAME", DB_NAME)]:
            estado = f"{self.bot.EMOJI_CORRECTO} {var}" if val else f"{self.bot.EMOJI_INCORRECTO} {var}"
            campos.append(estado)

        cont_desc = (
            f"**Hostname:** `{info['hostname']}`\n"
            f"**IP pública:** `{info['public_ip'] or 'No detectada'}`\n"
            f"**IPs locales:** `{'`, `'.join(info['local_ips']) if info['local_ips'] else 'N/A'}`"
        )

        if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Configuración incompleta",
                description=f"**Contenedor**\n{cont_desc}\n\n**Variables**\n" + "\n".join(campos),
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
                description=f"**Contenedor**\n{cont_desc}\n\n**BD**\n```\n{version}\n```",
                color=discord.Color.green()
            )
            embed.set_footer(text=f"{DB_USER}@{DB_HOST}:{DB_PORT or 3306}/{DB_NAME}")
            log.info(f"DBTEST OK por {interaction.user} ({interaction.user.id}) — {version.split(',')[0]}")
            await interaction.edit_original_response(embed=embed)

        except ImportError:
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} aiomysql no instalado",
                description=f"**Contenedor**\n{cont_desc}\n\nEjecutá `pip install aiomysql` en el servidor.",
                color=discord.Color.red()
            )
            await interaction.edit_original_response(embed=embed)

        except Exception as e:
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Error de conexión",
                description=f"**Contenedor**\n{cont_desc}\n\n**Error**\n```\n{e}\n```" if str(e).strip() else f"**Contenedor**\n{cont_desc}\n\nSin detalles.",
                color=discord.Color.red()
            )
            embed.set_footer(text=f"{DB_USER}@{DB_HOST}:{DB_PORT or 3306}/{DB_NAME}")
            log.error(f"DBTEST ERROR por {interaction.user} ({interaction.user.id}): {e}")
            await interaction.edit_original_response(embed=embed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(DbTestCog(bot))
