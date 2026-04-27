import discord
from discord.ext import commands
from discord import app_commands

class InviteFilterCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @app_commands.command(name="invitefilter", description="Gestiona la whitelist de invitaciones de Discord (solo admins)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.choices(accion=[
        app_commands.Choice(name="add", value="add"),
        app_commands.Choice(name="remove", value="remove"),
        app_commands.Choice(name="list", value="list")
    ])
    @app_commands.describe(accion="Acción a realizar", codigo="Código de invitación (solo para add/remove)")
    async def invitefilter(self, interaction: discord.Interaction, accion: app_commands.Choice[str], codigo: str = None):
        """Administra los códigos de invitación permitidos."""
        if not interaction.guild:
            await interaction.response.send_message(
                f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.",
                ephemeral=True
            )
            return

        config = self.bot.obtener_config_guild(interaction.guild.id)
        if "invite_whitelist" not in config:
            config["invite_whitelist"] = []

        whitelist = config["invite_whitelist"]

        if accion.value == "add":
            if not codigo:
                await interaction.response.send_message(
                    f"{self.bot.EMOJI_INCORRECTO} Proporciona un código de invitación.",
                    ephemeral=True
                )
                return

            # Limpiar posible URL completa
            codigo = codigo.strip().split('/')[-1]
            if codigo in whitelist:
                await interaction.response.send_message(
                    f"{self.bot.EMOJI_INCORRECTO} El código `{codigo}` ya está en la whitelist.",
                    ephemeral=True
                )
                return

            whitelist.append(codigo)
            self.bot.guardar_datos()
            await interaction.response.send_message(
                f"{self.bot.EMOJI_CORRECTO} Código `{codigo}` añadido a la whitelist de invitaciones.",
                ephemeral=True
            )

        elif accion.value == "remove":
            if not codigo:
                await interaction.response.send_message(
                    f"{self.bot.EMOJI_INCORRECTO} Proporciona un código de invitación.",
                    ephemeral=True
                )
                return

            codigo = codigo.strip().split('/')[-1]
            if codigo not in whitelist:
                await interaction.response.send_message(
                    f"{self.bot.EMOJI_INCORRECTO} El código `{codigo}` no está en la whitelist.",
                    ephemeral=True
                )
                return

            whitelist.remove(codigo)
            self.bot.guardar_datos()
            await interaction.response.send_message(
                f"{self.bot.EMOJI_CORRECTO} Código `{codigo}` eliminado de la whitelist de invitaciones.",
                ephemeral=True
            )

        elif accion.value == "list":
            if not whitelist:
                await interaction.response.send_message(
                    f"{self.bot.EMOJI_INCORRECTO} No hay códigos en la whitelist.",
                    ephemeral=True
                )
                return

            lista = "\n".join(f"• `{c}`" for c in whitelist)
            embed = discord.Embed(
                title=f"{self.bot.EMOJI_SHIELD} Whitelist de invitaciones de {interaction.guild.name}",
                description=lista,
                color=discord.Color.blue()
            )
            embed.set_footer(text="Usa /invitefilter add <código> para añadir más.")
            await interaction.response.send_message(embed=embed, ephemeral=True)

async def setup(bot):
    await bot.add_cog(InviteFilterCog(bot))