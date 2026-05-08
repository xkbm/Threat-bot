import sys
import discord
from discord.ext import commands
from discord import app_commands
from core.config import OWNER_ID

class RebootCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="reboot", description="Reinicia el bot de forma interna (solo dueño)")
    async def reboot(self, interaction: discord.Interaction):
        # Verificar que solo el dueño pueda usar el comando
        if str(interaction.user.id) != OWNER_ID:
            await interaction.response.send_message("❌ No tienes permiso para reiniciar el bot.", ephemeral=True)
            return

        # Crear botones de confirmación
        view = discord.ui.View()
        confirm_btn = discord.ui.Button(label="✅ Sí, reiniciar", style=discord.ButtonStyle.danger)
        cancel_btn = discord.ui.Button(label="❌ Cancelar", style=discord.ButtonStyle.secondary)

        async def confirm_callback(btn_interaction: discord.Interaction):
            # Deshabilitar botones para evitar doble clic
            confirm_btn.disabled = True
            cancel_btn.disabled = True
            await btn_interaction.response.edit_message(content="🔄 Reiniciando el bot...", view=view)

            # Cerrar sesión de forma ordenada y terminar el proceso
            # El gestor del panel (Pelican) lo reiniciará automáticamente
            await self.bot.close()
            sys.exit(0)

        async def cancel_callback(btn_interaction: discord.Interaction):
            confirm_btn.disabled = True
            cancel_btn.disabled = True
            await btn_interaction.response.edit_message(content="🚫 Reinicio cancelado.", view=view)

        confirm_btn.callback = confirm_callback
        cancel_btn.callback = cancel_callback
        view.add_item(confirm_btn)
        view.add_item(cancel_btn)

        await interaction.response.send_message(
            "⚠️ **¿Estás seguro de que deseas reiniciar el bot?**\n"
            "El bot se desconectará y el panel lo reiniciará automáticamente.",
            view=view,
            ephemeral=True
        )

async def setup(bot):
    await bot.add_cog(RebootCog(bot))