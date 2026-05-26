import sys
import logging
import discord
from discord.ext import commands
from discord import app_commands
from core.config import OWNER_ID

log = logging.getLogger("reboot")

class RebootCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="reboot", description="Reinicia el bot de forma interna (solo dueño)")
    async def reboot(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)

        if str(interaction.user.id) != OWNER_ID:
            log.warning(f"REBOOT INTENTO NO AUTORIZADO → usuario={interaction.user} ({interaction.user.id})")
            try:
                await interaction.edit_original_response(content="❌ No tienes permiso para reiniciar el bot.")
            except discord.errors.NotFound:
                pass
            return

        log.warning(f"REBOOT INICIADO → usuario={interaction.user} ({interaction.user.id})")
        view = discord.ui.View()
        confirm_btn = discord.ui.Button(label="✅ Sí, reiniciar", style=discord.ButtonStyle.danger)
        cancel_btn = discord.ui.Button(label="❌ Cancelar", style=discord.ButtonStyle.secondary)

        async def confirm_callback(btn_interaction: discord.Interaction) -> None:
            confirm_btn.disabled = True
            cancel_btn.disabled = True
            log.warning(f"REBOOT CONFIRMADO → usuario={btn_interaction.user} ({btn_interaction.user.id})")
            await btn_interaction.response.edit_message(content="🔄 Reiniciando el bot...", view=view)
            await self.bot.close()

        async def cancel_callback(btn_interaction: discord.Interaction) -> None:
            confirm_btn.disabled = True
            cancel_btn.disabled = True
            log.info(f"REBOOT CANCELADO → usuario={btn_interaction.user} ({btn_interaction.user.id})")
            await btn_interaction.response.edit_message(content="🚫 Reinicio cancelado.", view=view)

        confirm_btn.callback = confirm_callback
        cancel_btn.callback = cancel_callback
        view.add_item(confirm_btn)
        view.add_item(cancel_btn)

        try:
            await interaction.edit_original_response(
                content="⚠️ **¿Estás seguro de que deseas reiniciar el bot?**\n"
                "El bot se desconectará y el panel lo reiniciará automáticamente.",
                view=view
            )
        except discord.errors.NotFound:
            pass

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(RebootCog(bot))
