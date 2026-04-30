import os
import sys
import io
import textwrap
import traceback
import discord
from discord.ext import commands
from discord import app_commands

OWNER_ID = os.getenv("OWNER_ID")

class EvalCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    # ---------- Comando de prefijo (!eval) ----------
    @commands.command(name="eval")
    async def eval_prefix(self, ctx: commands.Context, *, codigo: str):
        # Ignorar completamente a cualquier usuario que no sea el dueño
        if str(ctx.author.id) != OWNER_ID:
            return

        # Verificar que se proporcione código
        if not codigo or not codigo.strip():
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Uso incorrecto",
                description="Uso: `-eval <código>`\n\nEjemplo:\n```\n-eval print('Hola mundo')\n```",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return

        # Limpiar markdown si lo envuelven en ```
        if codigo.startswith("```python") and codigo.endswith("```"):
            codigo = codigo[9:-3].strip()
        elif codigo.startswith("```") and codigo.endswith("```"):
            codigo = codigo[3:-3].strip()

        env = {
            "bot": self.bot,
            "ctx": ctx,
            "guild": ctx.guild,
            "channel": ctx.channel,
            "author": ctx.author,
            "discord": discord,
            "os": os,
            "json": __import__("json"),
            "time": __import__("time"),
            "aiohttp": __import__("aiohttp")
        }

        # Redirigir stdout a una cadena
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        try:
            exec(f"async def __eval_expr():\n{textwrap.indent(codigo, '    ')}", env)
            await env["__eval_expr"]()
            output = buffer.getvalue()
        except Exception as e:
            output = "".join(traceback.format_exception_only(e))
        finally:
            sys.stdout = old_stdout

        if not output.strip():
            output = "Sin salida"

        if len(output) > 1990:
            output = output[:1990] + "\n... (truncado)"

        embed = discord.Embed(title=f"{self.bot.EMOJI_KEY} Resultado de eval", color=discord.Color.dark_blue())
        embed.add_field(name=f"{self.bot.EMOJI_FILE} Código", value=f"```py\n{codigo[:500]}\n```", inline=False)
        embed.add_field(name=f"{self.bot.EMOJI_STATS} Salida", value=f"```\n{output}\n```", inline=False)
        await ctx.send(embed=embed)

    # ---------- Comando slash (/eval) por si aún lo quieres ----------
    @app_commands.command(name="eval", description="Ejecuta código Python (solo dueño)")
    async def eval_slash(self, interaction: discord.Interaction, codigo: str):
        if str(interaction.user.id) != OWNER_ID:
            await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} No tienes permiso para usar este comando.", ephemeral=True)
            return

        # Verificar que se proporcione código
        if not codigo or not codigo.strip():
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Uso incorrecto",
                description="Uso: `/eval codigo:<código>`\n\nEjemplo:\n```\n/eval codigo:print('Hola mundo')\n```",
                color=discord.Color.red()
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        await interaction.response.defer()

        if codigo.startswith("```python") and codigo.endswith("```"):
            codigo = codigo[9:-3].strip()
        elif codigo.startswith("```") and codigo.endswith("```"):
            codigo = codigo[3:-3].strip()

        env = {
            "bot": self.bot,
            "interaction": interaction,
            "guild": interaction.guild,
            "channel": interaction.channel,
            "author": interaction.user,
            "discord": discord,
            "os": os,
            "json": __import__("json"),
            "time": __import__("time"),
            "aiohttp": __import__("aiohttp")
        }

        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        try:
            exec(f"async def __eval_expr():\n{textwrap.indent(codigo, '    ')}", env)
            await env["__eval_expr"]()
            output = buffer.getvalue()
        except Exception as e:
            output = "".join(traceback.format_exception_only(e))
        finally:
            sys.stdout = old_stdout

        if not output.strip():
            output = "Sin salida"

        if len(output) > 1990:
            output = output[:1990] + "\n... (truncado)"

        embed = discord.Embed(title=f"{self.bot.EMOJI_KEY} Resultado de eval", color=discord.Color.dark_blue())
        embed.add_field(name=f"{self.bot.EMOJI_FILE} Código", value=f"```py\n{codigo[:500]}\n```", inline=False)
        embed.add_field(name=f"{self.bot.EMOJI_STATS} Salida", value=f"```\n{output}\n```", inline=False)
        await interaction.followup.send(embed=embed)

async def setup(bot):
    await bot.add_cog(EvalCog(bot))