import sys
import io
import os
from typing import Any
import logging
import textwrap
import traceback
import discord
from discord.ext import commands
from discord import app_commands
from core.config import OWNER_ID

log = logging.getLogger("eval")

class EvalCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @commands.command(name="eval")
    async def eval_prefix(self, ctx: commands.Context, *, codigo: str) -> None:
        if str(ctx.author.id) != OWNER_ID:
            return

        if not codigo or not codigo.strip():
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Uso incorrecto",
                description="Uso: `-eval <código>`\n\nEjemplo:\n```\n-eval print('Hola mundo')\n```",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return

        if codigo.startswith("```python") and codigo.endswith("```"):
            codigo = codigo[9:-3].strip()
        elif codigo.startswith("```") and codigo.endswith("```"):
            codigo = codigo[3:-3].strip()

        env: dict[str, Any] = {
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

        log.warning(f"EVAL by {ctx.author} ({ctx.author.id}): {codigo[:200]}")

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

    @app_commands.command(name="eval", description="Ejecuta código Python (solo dueño)")
    async def eval_slash(self, interaction: discord.Interaction, codigo: str) -> None:
        if str(interaction.user.id) != OWNER_ID:
            log.warning(f"EVAL INTENTO NO AUTORIZADO → usuario={interaction.user} ({interaction.user.id}) servidor={interaction.guild}")
            await interaction.response.send_message(f"{self.bot.EMOJI_INCORRECTO} No tienes permiso para usar este comando.", ephemeral=True)
            return

        if not codigo or not codigo.strip():
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Uso incorrecto",
                description="Uso: `/eval codigo:<código>`\n\nEjemplo:\n```\n/eval codigo:print('Hola mundo')\n```",
                color=discord.Color.red()
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        if codigo.startswith("```python") and codigo.endswith("```"):
            codigo = codigo[9:-3].strip()
        elif codigo.startswith("```") and codigo.endswith("```"):
            codigo = codigo[3:-3].strip()

        env: dict[str, Any] = {
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

        log.warning(f"EVAL by {interaction.user} ({interaction.user.id}): {codigo[:200]}")

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
        try:
            await interaction.followup.send(embed=embed)
        except discord.errors.NotFound:
            pass

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(EvalCog(bot))
