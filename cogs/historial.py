"""`/history` y el menú contextual "Analizar con Threat".

El menú contextual existía por una razón práctica: para analizar algo había que copiar la
URL y escribirla en `/scan`. Con el contexto del mensaje a un clic, el moderador revisa en
el sitio, sin copiar nada.

`/history` responde a la pregunta que el bot no podía responder: no había ningún registro
de qué se había escaneado. El `data.json` guardaba infracciones y cuotas, pero no qué
pasó en cada mensaje, así que "este canal estaba limpio ayer" no tenía respuesta.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from api.virustotal import analizar_url
from core.database import obtener_eventos
from core.utils import (
    PATRON_URL_D, check_vt_user_limit, comprobar_antispam, limpiar_url,
)
from core.veredictos import Veredicto
from ui import embed as emb

log = logging.getLogger("historial")


class HistorialCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def _safe_followup(self, interaction: discord.Interaction, *args, **kwargs) -> None:
        try:
            await interaction.followup.send(*args, **kwargs)
        except discord.errors.NotFound:
            pass

    async def _embed(self, interaction: discord.Interaction, embed, ephemeral: bool = True) -> None:
        """Envía un embed.

        Existe porque `_safe_followup` con `*args` es una trampa: al pasar un embed
        POSICIONAL se convierte en el contenido del mensaje y el bot escribe literalmente
        `<discord.embeds.Embed object at 0x...>` en el canal. Pasó con `/history`.
        """
        await self._safe_followup(interaction, embed=embed, ephemeral=ephemeral)

    @app_commands.command(
        name="history",
        description="Muestra los últimos análisis de un canal (solo mods)",
    )
    @app_commands.default_permissions(manage_messages=True)
    @app_commands.describe(
        canal="Canal a consultar. Por defecto, el actual.",
        usuario="Filtra por autor. Por defecto, cualquiera.",
        cantidad="Cuántos mostrar (1-25). Por defecto, 10.",
    )
    async def history(
        self,
        interaction: discord.Interaction,
        canal: Optional[discord.TextChannel] = None,
        usuario: Optional[discord.Member] = None,
        cantidad: int = 10,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        if not interaction.guild:
            await self._safe_followup(
                interaction,
                f"{self.bot.EMOJI_INCORRECTO} Este comando solo funciona en servidores.",
                ephemeral=True,
            )
            return

        objetivo = canal or interaction.channel
        eventos = await obtener_eventos(
            interaction.guild.id,
            channel_id=objetivo.id,
            author_id=usuario.id if usuario else None,
            limite=cantidad,
        )
        log.debug(f"HISTORY → guild={interaction.guild.id} canal={objetivo.id} n={len(eventos)}")

        if not eventos:
            await self._embed(
                interaction,
                emb.aviso(
                    "Sin historial",
                    f"No hay análisis registrados en {objetivo.mention}"
                    + (f" de {usuario.mention}" if usuario else "")
                    + ".",
                ),
                ephemeral=True,
            )
            return

        lineas = []
        for ev in eventos:
            veredicto = Veredicto.desde(ev["veredicto"])
            enlace = (f"https://discord.com/channels/{interaction.guild.id}"
                      f"/{ev['channel_id']}/{ev['message_id']}")
            linea = (f"{veredicto.emoji} [{_tiempo_relativo(ev['created_at'])}]({enlace})"
                     f" \u00b7 {ev['total']} elemento(s)")
            if ev["detalle"]:
                linea += f" \u00b7 {ev['detalle']}"
            lineas.append(linea)

        await self._embed(
            interaction,
            emb.aviso(f"Historial \u00b7 {objetivo.name}", "\n".join(lineas)[:4000], con_pie=False),
        )


# --- Menú contextual --------------------------------------------------------
#
# `app_commands.context_menu` NO admite una definición dentro de una clase: discord.py
# lanza `TypeError: context menus cannot be defined inside a class`. Por eso vive a nivel
# de módulo y se engancha al árbol en `setup`. De dentro usa `interaction.client` para
# llegar al bot.


async def _responder(interaction: discord.Interaction, texto: str) -> None:
    try:
        await interaction.followup.send(texto, ephemeral=True)
    except discord.errors.NotFound:
        pass


def _extraer_objetivo(message: discord.Message) -> Optional[tuple[str, str]]:
    """Decide qué analizar: un hash si el texto parece uno, si no la primera URL."""
    texto = (message.content or "").strip()

    for palabra in texto.split():
        limpia = palabra.strip(",.;:()[]<>")
        if len(limpia) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in limpia):
            return "hash", limpia

    for candidato in PATRON_URL_D.findall(texto):
        url = limpiar_url(candidato)
        if url:
            return "url", url

    if message.attachments:
        return "file", message.attachments[0].filename
    return None


async def _analizar_mensaje(interaction: discord.Interaction, message: discord.Message) -> None:
    """Analiza lo que haya en el mensaje sobre el que se hizo clic derecho."""
    bot = interaction.client
    await interaction.response.defer(ephemeral=True)

    # Primero se mira QUÉ hay, y luego se cobra. Al revés, un moderador que hace clic
    # derecho sobre un mensaje sin enlaces se gastaba una de las 30 unidades por hora y
    # recibía "no hay nada que analizar": 30 clics-equivoco bastaban para bloquearse a
    # sí mismo. La comprobación es síncrona y no cuesta nada.
    objetivo = _extraer_objetivo(message)
    if objetivo is None:
        await _responder(
            interaction,
            f"{bot.EMOJI_INCORRECTO} Este mensaje no tiene ningún enlace que analizar.",
        )
        return

    permitido, espera = await comprobar_antispam(bot, interaction.guild_id, interaction.user.id)
    if not permitido:
        mins = max(1, espera // 60) if espera >= 60 else 0
        texto = f"espera {mins} min" if mins else f"espera {espera} s"
        await _responder(interaction, f"{bot.EMOJI_COOLDOWN} Racha de escaneos muy rápida: {texto}.")
        return

    tipo, valor = objetivo
    guild_id = interaction.guild_id

    if tipo == "file":
        await _responder(interaction, f"{bot.EMOJI_LOADING} Analizando el adjunto\u2026")
        _veredicto, e, _m = await bot.analizar_archivo(message.attachments[0], guild_id=guild_id)
    else:
        if not await check_vt_user_limit(bot, guild_id, interaction.user.id):
            await _responder(interaction, f"{bot.EMOJI_COOLDOWN} Has alcanzado tu límite de escaneos.")
            return
        await _responder(interaction, f"{bot.EMOJI_LOADING} Analizando\u2026")
        _veredicto, e, _m = await analizar_url(
            valor, guild_id=guild_id, guardar_cache=True, registrar_para=interaction.user
        )

    log.debug(f"MENU → guild={guild_id} tipo={tipo}")
    try:
        await interaction.followup.send(embed=e, ephemeral=True)
    except discord.errors.NotFound:
        pass


menu_analizar = app_commands.context_menu(name="Analizar con Threat")(_analizar_mensaje)


def _tiempo_relativo(epoch: float) -> str:
    delta = max(0, int(time.time() - epoch))
    if delta < 60:
        return "hace un momento"
    if delta < 3600:
        return f"hace {delta // 60} min"
    if delta < 86400:
        return f"hace {delta // 3600} h"
    return f"hace {delta // 86400} d"


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(HistorialCog(bot))
    bot.tree.add_command(menu_analizar)
