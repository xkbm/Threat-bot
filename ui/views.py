from typing import Optional
import discord
from discord.ext import commands
from core import state
from core.config import EMOJI_BAN, EMOJI_KICK, EMOJI_CLEAN
from core.guild_config import obtener_config_guild
from core.database import guardar_datos

class LogActionView(discord.ui.View):
    def __init__(self, guild_id: int, user_id: int, elemento_id: Optional[str] = None) -> None:
        super().__init__(timeout=None)
        self.guild_id = guild_id
        self.user_id = user_id
        self.elemento_id = elemento_id
        if not elemento_id:
            self.remove_item(self.ignorar_btn)

    @discord.ui.button(label="Banear usuario", style=discord.ButtonStyle.danger, emoji=EMOJI_BAN)
    async def banear_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.user.guild_permissions.ban_members:
            await interaction.response.send_message("No tienes permisos para banear.", ephemeral=True)
            return
        guild = interaction.guild
        user = guild.get_member(self.user_id)
        if user is None:
            await interaction.response.send_message("El usuario ya no está en el servidor.", ephemeral=True)
            return
        confirm_view = ConfirmBanView(guild, user, self, interaction)
        await interaction.response.send_message(f"¿Estás seguro de banear a {user.mention}?", view=confirm_view, ephemeral=True)

    @discord.ui.button(label="Expulsar usuario", style=discord.ButtonStyle.danger, emoji=EMOJI_KICK)
    async def kick_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.user.guild_permissions.kick_members:
            await interaction.response.send_message("No tienes permisos para expulsar.", ephemeral=True)
            return
        guild = interaction.guild
        user = guild.get_member(self.user_id)
        if user is None:
            await interaction.response.send_message("El usuario ya no está en el servidor.", ephemeral=True)
            return
        try:
            await guild.kick(user, reason="Amenaza detectada por Threat (acción desde log)")
            await interaction.response.send_message(f"{user.mention} ha sido expulsado.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("No tengo permisos para expulsar a ese usuario.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Error inesperado: {e}", ephemeral=True)
        else:
            for child in self.children:
                child.disabled = True
            await interaction.message.edit(view=self)

    @discord.ui.button(label="Ignorar (quitar infracción)", style=discord.ButtonStyle.secondary, emoji=EMOJI_CLEAN)
    async def ignorar_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("Solo administradores pueden ignorar infracciones.", ephemeral=True)
            return
        config = obtener_config_guild(self.guild_id)
        uid = str(self.user_id)
        if self.elemento_id and uid in config.get("infracciones_registradas", {}):
            registradas = config["infracciones_registradas"][uid]
            if self.elemento_id in registradas:
                registradas.remove(self.elemento_id)
                if uid in config["infracciones"]:
                    config["infracciones"][uid] = max(0, config["infracciones"].get(uid, 1) - 1)
                await guardar_datos(inmediato=True)
                await interaction.response.send_message("Infracción eliminada.", ephemeral=True)
            else:
                await interaction.response.send_message("Esa infracción ya no existe.", ephemeral=True)
        else:
                await interaction.response.send_message("No se pudo identificar la infracción.", ephemeral=True)
        for child in self.children:
            child.disabled = True
        await interaction.message.edit(view=self)


class ConfirmBanView(discord.ui.View):
    def __init__(self, guild: discord.Guild, user: discord.User, parent_view: LogActionView, parent_interaction: discord.Interaction) -> None:
        super().__init__(timeout=30)
        self.guild = guild
        self.user = user
        self.parent_view = parent_view
        self.parent_interaction = parent_interaction

    @discord.ui.button(label="Confirmar Ban", style=discord.ButtonStyle.danger)
    async def confirm_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        try:
            await self.guild.ban(self.user, reason="Amenaza detectada por Threat (acción desde log)")
            await interaction.response.edit_message(content=f"{self.user.mention} ha sido baneado.", view=None)
        except discord.Forbidden:
            await interaction.response.edit_message(content="No tengo permisos para banear a ese usuario.", view=None)
        except Exception as e:
            await interaction.response.edit_message(content=f"Error inesperado: {e}", view=None)
        else:
            for child in self.parent_view.children:
                child.disabled = True
            await self.parent_interaction.message.edit(view=self.parent_view)

    @discord.ui.button(label="Cancelar", style=discord.ButtonStyle.secondary)
    async def cancel_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="Ban cancelado.", view=None)


class WhitelistPaginatorView(discord.ui.View):
    def __init__(self, guild_name: str, domains: list[str], shield_emoji: str, per_page: int = 20) -> None:
        super().__init__(timeout=60)
        self.domains = domains
        self.guild_name = guild_name
        self.shield_emoji = shield_emoji
        self.per_page = per_page
        self.total_pages = max(1, (len(domains) + per_page - 1) // per_page)
        self.current_page = 0
        self._update_buttons()

    def get_page_embed(self) -> discord.Embed:
        start = self.current_page * self.per_page
        end = start + self.per_page
        page_domains = self.domains[start:end]
        lista = "\n".join(f"• `{d}`" for d in page_domains)
        embed = discord.Embed(
            title=f"{self.shield_emoji} Whitelist de {self.guild_name}",
            description=lista,
            color=discord.Color.blue()
        )
        embed.set_footer(text=f"Página {self.current_page + 1}/{self.total_pages} • {len(self.domains)} dominios totales")
        return embed

    def _update_buttons(self) -> None:
        self.prev_btn.disabled = self.current_page <= 0
        self.next_btn.disabled = self.current_page >= self.total_pages - 1

    @discord.ui.button(label="◀ Anterior", style=discord.ButtonStyle.secondary)
    async def prev_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if self.current_page > 0:
            self.current_page -= 1
            self._update_buttons()
            await interaction.response.edit_message(embed=self.get_page_embed(), view=self)

    @discord.ui.button(label="Siguiente ▶", style=discord.ButtonStyle.secondary)
    async def next_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if self.current_page < self.total_pages - 1:
            self.current_page += 1
            self._update_buttons()
            await interaction.response.edit_message(embed=self.get_page_embed(), view=self)
