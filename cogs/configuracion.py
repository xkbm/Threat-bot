import discord
from discord.ext import commands
from discord import app_commands
from typing import Any, Optional
import logging

from core import config_schema as esq
from core.guild_config import actualizar_config, obtener_config_guild
from ui import embed as emb
from ui.panel import panel_por_guild

log = logging.getLogger("configuracion")

class ConfiguracionCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def _safe_followup(self, interaction: discord.Interaction, *args: Any, **kwargs: Any) -> None:
        """Envía un followup.

        Un 400 aquí significa que la interaction no se respondió ni se difirió antes, y
        que el usuario no va a ver nada. Se relanza para que quede traza en el log: antes
        se silenciaba y el fallo solo se manifesting como "el comando no hace nada".
        """
        try:
            await interaction.followup.send(*args, **kwargs)
        except discord.errors.NotFound:
            pass
        except discord.HTTPException:
            log.error(
                "Fallo al enviar el followup: HTTP de Discord. La interaction probablemente "
                "no se difirió antes de enviar. Comando fallido en silencio.",
                exc_info=True,
            )
            raise

    @app_commands.command(
        name="settings",
        description="Abre los ajustes del bot en este servidor (solo admins)",
    )
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(seccion="Sección a la que abrir el panel. Por defecto, Aviso.")
    async def settings(
        self,
        interaction: discord.Interaction,
        seccion: Optional[str] = None,
    ) -> None:
        """Abre el panel de configuración.

        Antes esto imprimía los ajustes y no dejaba cambiar nada: cada opción exigía su
        propio comando. Ahora abre el panel, y el panel se construye recorriendo
        `core.config_schema`, así que no puede mostrar una clave inexistente ni dejar
        fuera una nueva.

        El `defer` no es opcional. Todo lo que se envía aquí va por `followup.send`, y
        Discord rechaza un followup si la interaction no se ha respondido o diferido
        antes: devuelve 400 "This interaction has not been sent yet" y el comando no
        muestra nada. Es lo que pasaba aquí, y en los tests no se veía porque la suite
        fake no reproducía el contrato de la interacción.
        """
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(
                interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.",
                ephemeral=True)
            return

        elegida = seccion if seccion in esq.secciones() else esq.AVISO
        embed, vista = await panel_por_guild(interaction.guild, elegida)
        log.debug(f"SETTINGS → guild={interaction.guild.id} seccion={elegida}")
        await self._safe_followup(interaction, embed=embed, view=vista, ephemeral=True)

    @app_commands.command(
        name="setup",
        description="Explica qué está haciendo el bot en este servidor y qué conviene decidir",
    )
    @app_commands.default_permissions(administrator=True)
    async def puesta_en_marcha(self, interaction: discord.Interaction) -> None:
        """Explica, en texto, qué está haciendo el bot aquí y ahora.

        Existe por el caso de un owner que añade el bot, ve un mensaje desaparecer sin
        saber por qué, y lo desinstala. `/settings` le enseña todos los controles; esto
        le dice qué significan y en qué estado están.

        No es un asistente paso a paso. Uno de esos necesita recordar en qué punto va
        cada servidor, que es un dato más que guardar y que además obliga a actualizar
        la política de privacidad. Con esto el admin lee, decide y cambia lo que quiera en
        `/settings`; nada queda guardado por haber ejecutado este comando.

        El estado sale de la configuración real, no se afirma: si el borrado está activo
        por lo que sea, el texto lo dice. Un explicador que afirma "no borro" mientras sí
        borra es peor que no tener ninguno.
        """
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(
                interaction, f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.",
                ephemeral=True)
            return

        config = await obtener_config_guild(interaction.guild.id)

        if config.get("strict_mode", False):
            borrado = (
                f"{self.bot.EMOJI_WARNING} **Ahora mismo sí borro**: ante malware y NSFW "
                "confirmados el mensaje desaparece y no hay forma de recuperarlo."
            )
        else:
            borrado = (
                "**Ahora mismo no borro nada.** Te aviso con un embed y un emoji, y eso sí "
                "se puede deshacer. Si prefieres que borre el malware y el NSFW "
                "confirmados, actívalo abajo."
            )

        descripcion = (
            f"{self.bot.EMOJI_SHIELD} Reviso **cada mensaje** de este servidor: enlaces "
            f"sospechosos, archivos adjuntos, imágenes y enlaces que imitan a una marca "
            f"real.\n\n{borrado}\n\n"
            f"Los enlaces a {len(config.get('whitelist') or [])} dominios exentos no se "
            "miran."
        )

        campos = [
            (etiqueta, valor, True)
            for seccion in (esq.GENERAL, esq.MODERACION)
            for etiqueta, valor in esq.resumen_seccion(config, seccion)
        ]

        embed = emb.aviso(
            "Threat · puesta en marcha",
            descripcion,
            campos,
            icono=self.bot.EMOJI_SHIELD,
            pie_texto="Todo esto se cambia en /settings",
        )
        log.debug(f"SETUP → guild={interaction.guild.id}")
        await self._safe_followup(interaction, embed=embed, ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ConfiguracionCog(bot))
