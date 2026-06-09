from typing import Optional
import time
import discord
from discord.ext import commands
from core import state
from core.config import EMOJI_BAN, EMOJI_KICK, EMOJI_CLEAN, EMOJI_FINGERPRINT, EMOJI_SHIELD, EMOJI_LINK
from core.guild_config import obtener_config_guild
from core.database import guardar_datos

class RazonModal(discord.ui.Modal, title="Razón de la acción"):
    razon = discord.ui.TextInput(
        label="Razón (opcional)",
        style=discord.TextStyle.short,
        placeholder="Describe la razón de esta acción...",
        required=False,
        max_length=200,
    )

    def __init__(self, accion: str, parent_view: 'LogActionView', parent_interaction: discord.Interaction) -> None:
        super().__init__()
        self.accion = accion
        self.parent_view = parent_view
        self.parent_interaction = parent_interaction
        self.razon_texto: str = "Sin razón"

    async def on_submit(self, interaction: discord.Interaction) -> None:
        self.razon_texto = self.razon.value.strip() if self.razon.value and self.razon.value.strip() else "Sin razón"
        if self.accion == "ban":
            confirm_view = ConfirmBanView(
                self.parent_view.guild, self.parent_view._target_user,
                self.parent_view, self.parent_interaction, self.razon_texto
            )
            await interaction.response.send_message(
                f"¿Estás seguro de banear a {self.parent_view._target_user.mention}?\n**Razón:** {self.razon_texto}",
                view=confirm_view, ephemeral=True
            )
        elif self.accion == "kick":
            guild = self.parent_view.guild
            user = self.parent_view._target_user
            razon_completa = f"Threat Bot: {self.razon_texto}"
            try:
                await guild.kick(user, reason=razon_completa)
                await interaction.response.send_message(f"{user.mention} ha sido expulsado.\n**Razón:** {self.razon_texto}", ephemeral=True)
            except discord.Forbidden:
                await interaction.response.send_message("No tengo permisos para expulsar a ese usuario.", ephemeral=True)
            except Exception as e:
                await interaction.response.send_message(f"Error inesperado: {e}", ephemeral=True)
            else:
                await self.parent_view._finalizar_accion(interaction, "Kick", self.razon_texto)
        elif self.accion == "ignore":
            config = await obtener_config_guild(self.parent_view.guild_id)
            uid = str(self.parent_view.user_id)
            if self.parent_view.elemento_id and uid in config.get("infracciones_registradas", {}):
                registradas = config["infracciones_registradas"][uid]
                if self.parent_view.elemento_id in registradas:
                    registradas.remove(self.parent_view.elemento_id)
                    if uid in config["infracciones"]:
                        config["infracciones"][uid] = max(0, config["infracciones"].get(uid, 1) - 1)
                    await guardar_datos(inmediato=True)
                    await interaction.response.send_message(f"Infracción eliminada.\n**Razón:** {self.razon_texto}", ephemeral=True)
                    await self.parent_view._finalizar_accion(interaction, "Ignorar", self.razon_texto)
                else:
                    await interaction.response.send_message("Esa infracción ya no existe.", ephemeral=True)
            else:
                await interaction.response.send_message("No se pudo identificar la infracción.", ephemeral=True)

    async def on_error(self, interaction: discord.Interaction, error: Exception) -> None:
        await interaction.response.send_message(f"Error: {error}", ephemeral=True)


class LogActionView(discord.ui.View):
    def __init__(self, guild_id: int, user_id: int, elemento_id: Optional[str] = None) -> None:
        super().__init__(timeout=None)
        self.guild_id = guild_id
        self.user_id = user_id
        self.elemento_id = elemento_id
        self.message: Optional[discord.Message] = None
        self.guild: Optional[discord.Guild] = None
        self._target_user: Optional[discord.Member] = None
        if not elemento_id:
            self.remove_item(self.ignorar_btn)

    async def _finalizar_accion(self, interaction: discord.Interaction, accion: str, razon: str) -> None:
        for child in self.children:
            child.disabled = True
        if self.message:
            try:
                embed = self.message.embeds[0].copy()
                embed.add_field(
                    name=f"{EMOJI_FINGERPRINT} Moderador",
                    value=f"{interaction.user.mention}",
                    inline=True
                )
                embed.add_field(
                    name=f"{EMOJI_SHIELD} Acción",
                    value=accion,
                    inline=True
                )
                embed.add_field(
                    name=f"{EMOJI_LINK} Razón",
                    value=razon,
                    inline=False
                )
                await self.message.edit(embed=embed, view=self)
            except Exception:
                pass

    @discord.ui.button(label="Banear usuario", style=discord.ButtonStyle.danger, emoji=EMOJI_BAN)
    async def banear_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.user.guild_permissions.ban_members:
            await interaction.response.send_message("No tienes permisos para banear.", ephemeral=True)
            return
        guild = interaction.guild
        user = guild.get_member(self.user_id) if guild else None
        if user is None:
            await interaction.response.send_message("El usuario ya no está en el servidor.", ephemeral=True)
            return
        self.guild = guild
        self._target_user = user
        modal = RazonModal("ban", self, interaction)
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Expulsar usuario", style=discord.ButtonStyle.danger, emoji=EMOJI_KICK)
    async def kick_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.user.guild_permissions.kick_members:
            await interaction.response.send_message("No tienes permisos para expulsar.", ephemeral=True)
            return
        guild = interaction.guild
        user = guild.get_member(self.user_id) if guild else None
        if user is None:
            await interaction.response.send_message("El usuario ya no está en el servidor.", ephemeral=True)
            return
        self.guild = guild
        self._target_user = user
        modal = RazonModal("kick", self, interaction)
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Ignorar (quitar infracción)", style=discord.ButtonStyle.secondary, emoji=EMOJI_CLEAN)
    async def ignorar_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("Solo administradores pueden ignorar infracciones.", ephemeral=True)
            return
        config = await obtener_config_guild(self.guild_id)
        uid = str(self.user_id)
        if not self.elemento_id or uid not in config.get("infracciones_registradas", {}):
            await interaction.response.send_message("No se pudo identificar la infracción.", ephemeral=True)
            return
        if self.elemento_id not in config["infracciones_registradas"][uid]:
            await interaction.response.send_message("Esa infracción ya no existe.", ephemeral=True)
            return
        modal = RazonModal("ignore", self, interaction)
        await interaction.response.send_modal(modal)


class ConfirmBanView(discord.ui.View):
    def __init__(self, guild: discord.Guild, user: discord.User, parent_view: LogActionView, parent_interaction: discord.Interaction, razon: str = "Sin razón") -> None:
        super().__init__(timeout=30)
        self.message: Optional[discord.Message] = None
        self.guild = guild
        self.user = user
        self.parent_view = parent_view
        self.parent_interaction = parent_interaction
        self.razon = razon

    async def on_timeout(self) -> None:
        for child in self.children:
            child.disabled = True
        if self.message:
            try:
                await self.message.edit(content="⏱️ Tiempo de confirmación agotado.", view=self)
            except discord.NotFound:
                pass

    @discord.ui.button(label="Confirmar Ban", style=discord.ButtonStyle.danger)
    async def confirm_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        razon_completa = f"Threat Bot: {self.razon}"
        try:
            await self.guild.ban(self.user, reason=razon_completa)
            await interaction.response.edit_message(content=f"{self.user.mention} ha sido baneado.\n**Razón:** {self.razon}", view=None)
        except discord.Forbidden:
            await interaction.response.edit_message(content="No tengo permisos para banear a ese usuario.", view=None)
        except Exception as e:
            await interaction.response.edit_message(content=f"Error inesperado: {e}", view=None)
        else:
            await self.parent_view._finalizar_accion(interaction, "Ban", self.razon)

    @discord.ui.button(label="Cancelar", style=discord.ButtonStyle.secondary)
    async def cancel_btn(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="Ban cancelado.", view=None)


class WhitelistPaginatorView(discord.ui.View):
    def __init__(self, guild_name: str, domains: list[str], shield_emoji: str, per_page: int = 20) -> None:
        super().__init__(timeout=60)
        self.message: Optional[discord.Message] = None
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

    async def on_timeout(self) -> None:
        for child in self.children:
            child.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.NotFound:
                pass

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
