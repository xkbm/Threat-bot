import discord
from discord.ext import commands
from discord import app_commands
import time
import traceback
import logging
from core.utils import maybe_send_review_prompt

log = logging.getLogger("stats")

class EstadisticasCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    def get_vt_combined_minute(self) -> str:
        ahora = time.time()
        total = 0
        for key in self.bot.vt_key_total_requests:
            total += len([t for t in self.bot.vt_key_usage.get(key, []) if ahora - t <= 60])
        limit = self.bot.vt_key_count * 4
        if limit == 0:
            return "```\nSin keys VT configuradas\n```"
        porcentaje = (total / limit) * 100
        barra = self.bot.barra_porcentaje(porcentaje, longitud=10)
        return f"{barra} **{porcentaje:.0f}%** ({total}/{limit})"

    def get_vt_combined_daily(self) -> str:
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        total = 0
        for key in self.bot.vt_key_daily_usage:
            daily_data = self.bot.vt_key_daily_usage.get(key, {"count": 0, "date": ""})
            if daily_data["date"] == hoy:
                total += daily_data["count"]
        limit = self.bot.vt_key_count * 500
        if limit == 0:
            return "```\nSin keys VT configuradas\n```"
        porcentaje = (total / limit) * 100
        barra = self.bot.barra_porcentaje(porcentaje, longitud=10)
        return f"{barra} **{porcentaje:.1f}%** ({total}/{limit})"

    def get_se_combined_daily(self) -> str:
        hoy = time.strftime("%Y-%m-%d", time.gmtime())
        total = 0
        for key in self.bot.se_key_daily_usage:
            daily_data = self.bot.se_key_daily_usage.get(key, {"count": 0, "date": ""})
            if daily_data["date"] == hoy:
                total += daily_data["count"]
        limit = self.bot.se_key_count * 500
        if limit == 0:
            return "```\nSin keys SightEngine configuradas\n```"
        porcentaje = (total / limit) * 100
        barra = self.bot.barra_porcentaje(porcentaje, longitud=10)
        return f"{barra} **{porcentaje:.1f}%** ({total}/{limit})"

    @app_commands.command(name="stats", description="Muestra estadísticas globales y uso de API")
    async def stats_command(self, interaction: discord.Interaction) -> None:
        log.debug(f"STATS → usuario={interaction.user.id} guild={interaction.guild.id if interaction.guild else None}")
        try:
            await interaction.response.defer()
            stats = self.bot.obtener_stats_globales()
            total = stats["total_analisis"]
            porcentaje_maliciosos = (stats["maliciosos"] / total * 100) if total > 0 else 0

            embed = discord.Embed(
                title=f"{self.bot.EMOJI_STATS} Estadísticas Globales de Seguridad",
                color=discord.Color.gold()
            )
            embed.add_field(name=f"{self.bot.EMOJI_LUPA} Total análisis", value=f"**{total}**", inline=True)
            embed.add_field(name=f"{self.bot.EMOJI_CORRECTO} Seguros", value=f"**{stats['seguros']}**", inline=True)
            embed.add_field(name=f"{self.bot.EMOJI_WARNING} Maliciosos", value=f"**{stats['maliciosos']}**", inline=True)
            embed.add_field(name=f"{self.bot.EMOJI_NSFW} NSFW", value=f"**{stats.get('nsfw', 0)}**", inline=True)
            embed.add_field(name=f"{self.bot.EMOJI_INCORRECTO} Errores", value=f"**{stats['errores']}**", inline=True)
            embed.add_field(
                name=f"{self.bot.EMOJI_STATS} Detecciones (%)",
                value=f"`{self.bot.barra_porcentaje(porcentaje_maliciosos)}` **{porcentaje_maliciosos:.1f}%**",
                inline=False
            )

            vt_minuto = self.get_vt_combined_minute()
            embed.add_field(
                name=f"{self.bot.EMOJI_KEY} VT Minuto (límite {self.bot.vt_key_count*4}/min)",
                value=vt_minuto,
                inline=False
            )

            vt_diario = self.get_vt_combined_daily()
            embed.add_field(
                name=f"{self.bot.EMOJI_KEY} VT Diario (límite {self.bot.vt_key_count*500}/día)",
                value=vt_diario,
                inline=False
            )

            se_diario = self.get_se_combined_daily()
            embed.add_field(
                name=f"{self.bot.EMOJI_KEY} Sightengine Diario (límite {self.bot.se_key_count*500} ops/día)",
                value=se_diario,
                inline=False
            )

            await interaction.followup.send(embed=embed)
            await maybe_send_review_prompt(self.bot, interaction.channel)
        except Exception as e:
            log.error(f"Error en comando stats: {e}\n{traceback.format_exc()}")
            if interaction.response.is_done():
                await interaction.followup.send("No se pudieron obtener las estadísticas.", ephemeral=True)
            else:
                await interaction.response.send_message("No se pudieron obtener las estadísticas.", ephemeral=True)

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(EstadisticasCog(bot))
