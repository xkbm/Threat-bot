import discord
from discord.ext import commands
from discord import app_commands
import hashlib
import time
from typing import Optional
import logging
from core.utils import expandir_url, comprobar_antispam, formatear_espera, clave_analisis, vuelo

from ui import embed as emb

log = logging.getLogger("analisis")

class AnalisisCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="scan", description="Analiza URL, IP, hash o archivo con VirusTotal")
    @app_commands.checks.cooldown(1, 30.0, key=lambda i: (i.guild_id, i.user.id))
    @app_commands.describe(
        tipo="Elige qué quieres analizar",
        valor="Introduce la URL, IP o hash (solo para esos tipos)",
        archivo="Sube el archivo (solo para tipo archivo)"
    )
    @app_commands.choices(tipo=[
        app_commands.Choice(name="URL", value="url"),
        app_commands.Choice(name="IP", value="ip"),
        app_commands.Choice(name="Hash", value="hash"),
        app_commands.Choice(name="Archivo", value="file")
    ])
    async def scan(self, interaction: discord.Interaction, tipo: app_commands.Choice[str], valor: Optional[str] = None, archivo: Optional[discord.Attachment] = None) -> None:
        guild_id = interaction.guild.id if interaction.guild else None

        await interaction.response.defer()

        url_original: Optional[str] = None
        expanded: Optional[str] = None

        log.debug(f"SCAN → tipo={tipo.value} usuario={interaction.user.id} guild={guild_id}")

        if tipo.value == "file" and archivo is None:
            log.debug("SCAN → archivo sin adjunto, rechazado")
            await interaction.edit_original_response(content=f"{self.bot.EMOJI_INCORRECTO} Adjunta un archivo para analizar.")
            return
        if tipo.value in ["url", "ip", "hash"] and not valor:
            log.debug(f"SCAN → tipo={tipo.value} sin valor, rechazado")
            await interaction.edit_original_response(content=f"{self.bot.EMOJI_INCORRECTO} Introduce un valor para {tipo.name}.")
            return

        if tipo.value == "url":
            url_original = valor
            try:
                expanded = await expandir_url(self.bot, valor)
            except Exception as e:
                log.error(f"SCAN URL EXPAND ERROR → {valor}: {e}")
                expanded = None
            valor = expanded if expanded else valor
            clave = clave_analisis("url", valor)
            if expanded and expanded != url_original:
                log.debug(f"SCAN URL expandida → {url_original} → {valor}")
        elif tipo.value == "ip":
            clave = clave_analisis("ip", valor)
            log.debug(f"SCAN IP → {valor}")
        elif tipo.value == "hash":
            clave = clave_analisis("hash", valor)
            log.debug(f"SCAN HASH → {valor}")
        elif tipo.value == "file":
            if archivo.size > self.bot.MAX_FILE_SIZE:
                log.debug(f"SCAN ARCHIVO → {archivo.filename} ({archivo.size} bytes) excede MAX_FILE_SIZE")
                embed = emb.error_analisis(
                    f"`{archivo.filename}` supera el tamaño máximo que se puede analizar.",
                    detalle=f"Límite de {self.bot.MAX_FILE_SIZE // (1024 * 1024)} MB por archivo.",
                )
                await interaction.edit_original_response(content=None, embed=embed)
                return

            _t0 = time.time()

            permitido, espera = await comprobar_antispam(self.bot, guild_id, interaction.user.id)
            if not permitido:
                await interaction.edit_original_response(
                    content=f"{self.bot.EMOJI_COOLDOWN} Límite de {self.bot.ANTISPAM_ANALYSIS_PER_HOUR} análisis/hora "
                    f"(o cooldown de {self.bot.ANTISPAM_COOLDOWN}s). Disponible en **{formatear_espera(espera)}**."
                )
                return

            doble_ext = self.bot.tiene_doble_extension(archivo.filename)
            warning_mime = ""

            try:
                log.debug(f"SCAN ARCHIVO DESCARGANDO → {archivo.filename} url={archivo.url}")
                async with self.bot.session.get(archivo.url) as resp:
                    if resp.status != 200:
                        embed = emb.error_analisis(
                            "No se pudo descargar el archivo.",
                            detalle=f"`{archivo.filename}` · el servidor respondió con el código {resp.status}.",
                        )
                        if doble_ext:
                            embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                        await interaction.edit_original_response(content=None, embed=embed)
                        return
                    file_bytes = await resp.read()
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    log.debug(f"SCAN ARCHIVO DESCARGADO → {archivo.filename} hash={file_hash}")

                    content_type = resp.headers.get('Content-Type', '').lower()
                    if archivo.filename.lower().endswith('.jpg') or archivo.filename.lower().endswith('.jpeg'):
                        if content_type not in ('image/jpeg', 'image/jpg'):
                            warning_mime = f"El archivo tiene extensión .jpg pero el tipo real es `{content_type}`."
                    elif archivo.filename.lower().endswith('.png'):
                        if content_type != 'image/png':
                            warning_mime = f"El archivo tiene extensión .png pero el tipo real es `{content_type}`."
            except Exception as e:
                log.error(f"SCAN ARCHIVO ERROR DESCARGA → {archivo.filename}: {e}")
                embed = emb.error_conexion(
                    "No se pudo descargar el archivo.",
                    detalle=f"`{archivo.filename}` · {type(e).__name__}",
                )
                if doble_ext:
                    embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                await interaction.edit_original_response(content=None, embed=embed)
                return

            clave_cache = clave_analisis("file", file_hash)
            tipo_cache, embed_cache, mal_cache = await self.bot.get_from_cache_mem(clave_cache)
            if embed_cache is None:
                tipo_cache, embed_cache, mal_cache = await self.bot.obtener_analisis_db(clave_cache)
                if embed_cache is not None:
                    log.debug(f"SCAN ARCHIVO CACHE SQLITE HIT → {clave_cache} tipo={tipo_cache}")
                    await self.bot.set_cache_mem(clave_cache, tipo_cache, embed_cache, mal_cache)
                else:
                    log.debug(f"SCAN ARCHIVO CACHE MISS → {clave_cache}")
            else:
                log.debug(f"SCAN ARCHIVO CACHE RAM HIT → {clave_cache} tipo={tipo_cache}")

            if embed_cache is not None:
                embed = embed_cache.copy()
                # Sin infracción: en `/scan` no hay un mensaje al que atribuirla. Quien
                # escanea está consultando, no publicando la amenaza.
                if doble_ext:
                    embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                if warning_mime:
                    embed.add_field(name=f"{self.bot.EMOJI_WARNING} Verificación MIME", value=warning_mime, inline=False)
                await interaction.edit_original_response(content=None, embed=embed)
                return

            async def _analizar_archivo() -> tuple[str, discord.Embed, int]:
                log.debug(f"SCAN ARCHIVO ANALIZANDO → {archivo.filename}")
                # Sin ANALYSIS_SEMAPHORE: ver la nota de `_llamar_api`. `analizar_archivo`
                # también sondea con esperas de 55s.
                return await self.bot.analizar_archivo(
                    archivo, file_bytes=file_bytes, file_hash=file_hash,
                    guild_id=guild_id, guardar_cache=True, registrar_para=interaction.user
                )

            try:
                tipo_res, embed, mal = await vuelo(clave_cache, _analizar_archivo)
            except Exception as e:
                log.error(f"SCAN ARCHIVO ERROR ANÁLISIS → {archivo.filename}: {e}")
                embed = emb.error_analisis(
                    "No se pudo completar el análisis del archivo.",
                    detalle=f"`{archivo.filename}` · {type(e).__name__}",
                )
                await interaction.edit_original_response(content=None, embed=embed)
                return

            if doble_ext and not any("Doble extensión" in f.name for f in embed.fields):
                embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
            if warning_mime and not any("Verificación MIME" in f.name for f in embed.fields):
                embed.add_field(name=f"{self.bot.EMOJI_WARNING} Verificación MIME", value=warning_mime, inline=False)

            await interaction.edit_original_response(content=None, embed=embed)
            return
        else:
            clave = ""

        log.debug(f"SCAN CACHE → buscando clave={clave}")
        tipo_cache, embed, mal = await self.bot.get_from_cache_mem(clave)
        if embed is None:
            try:
                tipo_cache, embed, mal = await self.bot.obtener_analisis_db(clave)
            except Exception as e:
                log.error(f"SCAN CACHE DB ERROR → clave={clave}: {e}")
                tipo_cache, embed, mal = None, None, 0
            if embed is not None:
                log.debug(f"SCAN CACHE SQLITE HIT → clave={clave} tipo={tipo_cache} mal={mal}")
                await self.bot.set_cache_mem(clave, tipo_cache, embed, mal)
            else:
                log.debug(f"SCAN CACHE MISS → clave={clave}")
        else:
            log.debug(f"SCAN CACHE RAM HIT → clave={clave} tipo={tipo_cache}")

        if embed is not None:
            if tipo.value == "url" and expanded and expanded != url_original:
                embed.add_field(
                    name=f"{self.bot.EMOJI_REPLY} Redirección",
                    value=f"Original: `{url_original}`\nExpandida: `{valor}`",
                    inline=False
                )
            await interaction.edit_original_response(content=None, embed=embed.copy())
            return

        # El antispam va antes de la API y por fuera del vuelo: el límite es personal
        # y cada invocación consume el suyo, comparta o no el análisis.
        permitido, espera = await comprobar_antispam(self.bot, guild_id, interaction.user.id)
        if not permitido:
            await interaction.edit_original_response(
                content=f"{self.bot.EMOJI_COOLDOWN} Límite de {self.bot.ANTISPAM_ANALYSIS_PER_HOUR} análisis/hora "
                f"(o cooldown de {self.bot.ANTISPAM_COOLDOWN}s). Disponible en **{formatear_espera(espera)}**."
            )
            return

        async def _llamar_api() -> tuple[str, discord.Embed, int]:
            # Sin ANALYSIS_SEMAPHORE a propósito. `analizar_url` y `analizar_archivo`
            # duermen 55s entre sondeos de VirusTotal; retener un hueco del pool
            # durante el sueño bloqueaba el análisis del resto del bot. La concurrencia
            # de verdad ya la limita `adquirir_vt()`, que es la cuota de VT.
            if tipo.value == "url":
                log.debug(f"SCAN URL ANALIZANDO → {valor}")
                return await self.bot.analizar_url(valor, guild_id=guild_id, guardar_cache=True, registrar_para=interaction.user)
            if tipo.value == "ip":
                log.debug(f"SCAN IP ANALIZANDO → {valor}")
                return await self.bot.analizar_ip(valor, guild_id=guild_id, guardar_cache=True, registrar_para=interaction.user)
            log.debug(f"SCAN HASH ANALIZANDO → {valor}")
            return await self.bot.analizar_hash(valor, guild_id=guild_id, guardar_cache=True, registrar_para=interaction.user)

        _t0 = time.time()
        try:
            # El vuelo deduplica solo la llamada a la API: si dos moderadores escanean
            # lo mismo a la vez, el segundo recibe el resultado del primero sin gastar
            # una segunda vez la cuota. Los efectos por invocación (antispam, embed con
            # la redirección) quedan fuera a propósito.
            tipo_res, embed, mal = await vuelo(clave, _llamar_api)
        except Exception as e:
            log.error(f"SCAN ERROR → tipo={tipo.value} valor={valor}: {e} t={time.time()-_t0:.1f}s")
            embed_error = emb.error_analisis(
                "No se pudo completar el análisis.",
                detalle=f"{tipo.value} · {type(e).__name__}",
            )
            try:
                await interaction.edit_original_response(content=None, embed=embed_error)
            except discord.errors.NotFound:
                pass
            return

        if tipo.value == "url" and expanded and expanded != url_original and tipo_res != "error":
            embed.add_field(
                name=f"{self.bot.EMOJI_REPLY} Redirección",
                value=f"Original: `{url_original}`\nExpandida: `{valor}`",
                inline=False
            )
        log.debug(f"SCAN FINAL → tipo={tipo.value} resultado={tipo_res} mal={mal} t={time.time()-_t0:.1f}s")
        await interaction.edit_original_response(content=None, embed=embed)


    async def _safe_followup(self, interaction: discord.Interaction, *args, **kwargs) -> None:
        try:
            await interaction.followup.send(*args, **kwargs)
        except discord.errors.NotFound:
            pass

    @scan.error
    async def scan_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        if isinstance(error, app_commands.CommandOnCooldown):
            log.warning(f"SCAN COOLDOWN → usuario={interaction.user.id} retry_after={error.retry_after:.1f}s")
            await interaction.response.send_message(
                f"{self.bot.EMOJI_WARNING} **¡Cuidado!** Estás usando el comando muy rápido. "
                f"Inténtalo de nuevo en **{error.retry_after:.1f}s**.",
                ephemeral=True
            )
        else:
            log.error(f"SCAN ERROR → {type(error).__name__}: {error}")
            await self._safe_followup(interaction,
                f"{self.bot.EMOJI_INCORRECTO} Ocurrió un error inesperado.",
                ephemeral=True
            )

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AnalisisCog(bot))
