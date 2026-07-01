import discord
from discord.ext import commands
from discord import app_commands
import hashlib
import time
from typing import Optional
import logging
from core.utils import expandir_url
from core.state import ANALYSIS_SEMAPHORE

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
            clave = f"url:{valor}"
            if expanded and expanded != url_original:
                log.debug(f"SCAN URL expandida → {url_original} → {valor}")
        elif tipo.value == "ip":
            clave = f"ip:{valor}"
            log.debug(f"SCAN IP → {valor}")
        elif tipo.value == "hash":
            clave = f"hash:{valor}"
            log.debug(f"SCAN HASH → {valor}")
        elif tipo.value == "file":
            if archivo.size > self.bot.MAX_FILE_SIZE:
                log.debug(f"SCAN ARCHIVO → {archivo.filename} ({archivo.size} bytes) excede MAX_FILE_SIZE")
                embed = discord.Embed(
                    title=f"{self.bot.EMOJI_INCORRECTO} Archivo demasiado grande",
                    description=f"{self.bot.EMOJI_FILE} `{archivo.filename}` excede 32 MB",
                    color=discord.Color.red()
                )
                await interaction.edit_original_response(content=None, embed=embed)
                return

            _t0 = time.time()

            ahora = time.time()
            user_id = interaction.user.id
            spam_key = (guild_id, user_id) if guild_id else user_id
            self.bot.user_scan_history.setdefault(spam_key, [])
            self.bot.user_scan_history[spam_key] = [t for t in self.bot.user_scan_history[spam_key] if ahora - t < 3600]
            if len(self.bot.user_scan_history[spam_key]) >= self.bot.ANTISPAM_ANALYSIS_PER_HOUR:
                oldest = min(self.bot.user_scan_history[spam_key])
                wait = int(oldest + 3600 - ahora)
                minutes, seconds = divmod(wait, 60)
                time_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
                await interaction.edit_original_response(
                    content=f"{self.bot.EMOJI_COOLDOWN} Límite de 30 análisis/hora alcanzado. "
                    f"Disponible en **{time_str}**.")
                return
            self.bot.user_scan_history[spam_key].append(ahora)

            doble_ext = self.bot.tiene_doble_extension(archivo.filename)
            warning_mime = ""

            try:
                log.debug(f"SCAN ARCHIVO DESCARGANDO → {archivo.filename} url={archivo.url}")
                async with self.bot.session.get(archivo.url) as resp:
                    if resp.status != 200:
                        embed = discord.Embed(
                            title=f"{self.bot.EMOJI_INCORRECTO} Error",
                            description="No se pudo descargar el archivo.",
                            color=discord.Color.red()
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
                embed = discord.Embed(
                    title=f"{self.bot.EMOJI_INCORRECTO} Error",
                    description="Error al descargar el archivo.",
                    color=discord.Color.red()
                )
                if doble_ext:
                    embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                await interaction.edit_original_response(content=None, embed=embed)
                return

            tipo_cache, embed_cache, mal_cache = await self.bot.get_from_cache_mem(f"filehash:{file_hash}")
            if embed_cache is None:
                tipo_cache, embed_cache, mal_cache = await self.bot.obtener_analisis_db(f"filehash:{file_hash}")
                if embed_cache is not None:
                    log.debug(f"SCAN ARCHIVO CACHE SQLITE HIT → filehash:{file_hash} tipo={tipo_cache}")
                    await self.bot.set_cache_mem(f"filehash:{file_hash}", tipo_cache, embed_cache, mal_cache)
                else:
                    log.debug(f"SCAN ARCHIVO CACHE MISS → filehash:{file_hash}")
            else:
                log.debug(f"SCAN ARCHIVO CACHE RAM HIT → filehash:{file_hash} tipo={tipo_cache}")
            if embed_cache is not None:
                tipo_res = tipo_cache
                embed = embed_cache.copy()
                mal = mal_cache
                if doble_ext:
                    embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                if warning_mime:
                    embed.add_field(name=f"{self.bot.EMOJI_WARNING} Verificación MIME", value=warning_mime, inline=False)
                await interaction.edit_original_response(content=None, embed=embed)
                return

            try:
                log.debug(f"SCAN ARCHIVO ANALIZANDO → {archivo.filename}")
                async with ANALYSIS_SEMAPHORE:
                    tipo_res, embed, mal = await self.bot.analizar_archivo(
                        archivo, file_bytes=file_bytes, file_hash=file_hash,
                        guild_id=guild_id, guardar_cache=True
                    )
            except Exception as e:
                log.error(f"SCAN ARCHIVO ERROR ANÁLISIS → {archivo.filename}: {e}")
                embed = discord.Embed(
                    title=f"{self.bot.EMOJI_INCORRECTO} Error en análisis",
                    description=str(e),
                    color=discord.Color.red()
                )
                await interaction.edit_original_response(content=None, embed=embed)
                return

            if tipo_res == "error":
                log.debug(f"SCAN ARCHIVO RESULT ERROR → {archivo.filename}")
                if doble_ext:
                    if not any("Doble extensión" in f.name for f in embed.fields):
                        embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                await interaction.edit_original_response(content=None, embed=embed)
                return

            log.debug(f"SCAN ARCHIVO RESULT → tipo={tipo_res} mal={mal} archivo={archivo.filename} t={time.time()-_t0:.1f}s")
            if doble_ext:
                embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
            if warning_mime:
                embed.add_field(name=f"{self.bot.EMOJI_WARNING} Verificación MIME", value=warning_mime, inline=False)

            await interaction.edit_original_response(content=None, embed=embed)
            return
        else:
            clave = ""

        log.debug(f"SCAN CACHE → buscando clave={clave}")
        tipo_res, embed, _ = await self.bot.get_from_cache_mem(clave)
        if embed is None:
            try:
                tipo_res, embed, mal_db = await self.bot.obtener_analisis_db(clave)
                if embed is not None:
                    log.debug(f"SCAN CACHE SQLITE HIT → clave={clave} tipo={tipo_res} mal={mal_db}")
                    await self.bot.set_cache_mem(clave, tipo_res, embed, mal_db)
                else:
                    log.debug(f"SCAN CACHE MISS → clave={clave}")
            except Exception as e:
                log.error(f"SCAN CACHE DB ERROR → clave={clave}: {e}")
                tipo_res, embed, mal_db = None, None, 0
        else:
            log.debug(f"SCAN CACHE RAM HIT → clave={clave} tipo={tipo_res}")

        if embed is not None:
            if tipo.value == "url" and expanded and expanded != url_original:
                embed.add_field(
                    name=f"{self.bot.EMOJI_REPLY} Redirección",
                    value=f"Original: `{url_original}`\nExpandida: `{valor}`",
                    inline=False
                )
            embed = embed.copy()

            await interaction.edit_original_response(content=None, embed=embed)
            return

        ahora = time.time()
        user_id = interaction.user.id
        spam_key = (guild_id, user_id) if guild_id else user_id
        self.bot.user_scan_history.setdefault(spam_key, [])
        self.bot.user_scan_history[spam_key] = [t for t in self.bot.user_scan_history[spam_key] if ahora - t < 3600]
        if len(self.bot.user_scan_history[spam_key]) >= self.bot.ANTISPAM_ANALYSIS_PER_HOUR:
            oldest = min(self.bot.user_scan_history[spam_key])
            wait = int(oldest + 3600 - ahora)
            minutes, seconds = divmod(wait, 60)
            time_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
            await interaction.edit_original_response(
                content=f"{self.bot.EMOJI_COOLDOWN} Límite de 30 análisis/hora alcanzado. "
                f"Disponible en **{time_str}**.")
            return
        self.bot.user_scan_history[spam_key].append(ahora)

        _t0 = time.time()
        try:
            if tipo.value == "url":
                log.debug(f"SCAN URL ANALIZANDO → {valor}")
                async with ANALYSIS_SEMAPHORE:
                    tipo_res, embed, mal = await self.bot.analizar_url(valor, guild_id=guild_id, guardar_cache=True)
                if expanded and expanded != url_original:
                    embed.add_field(
                        name=f"{self.bot.EMOJI_REPLY} Redirección",
                        value=f"Original: `{url_original}`\nExpandida: `{valor}`",
                        inline=False
                    )
                log.debug(f"SCAN URL RESULT → tipo={tipo_res} mal={mal} url={valor} t={time.time()-_t0:.1f}s")
            elif tipo.value == "ip":
                log.debug(f"SCAN IP ANALIZANDO → {valor}")
                async with ANALYSIS_SEMAPHORE:
                    tipo_res, embed, mal = await self.bot.analizar_ip(valor, guild_id=guild_id, guardar_cache=True)
                log.debug(f"SCAN IP RESULT → tipo={tipo_res} mal={mal} ip={valor} t={time.time()-_t0:.1f}s")
            elif tipo.value == "hash":
                log.debug(f"SCAN HASH ANALIZANDO → {valor}")
                async with ANALYSIS_SEMAPHORE:
                    tipo_res, embed, mal = await self.bot.analizar_hash(valor, guild_id=guild_id, guardar_cache=True)
                log.debug(f"SCAN HASH RESULT → tipo={tipo_res} mal={mal} hash={valor} t={time.time()-_t0:.1f}s")

        except Exception as e:
            log.error(f"SCAN ERROR → tipo={tipo.value} valor={valor}: {e} t={time.time()-_t0:.1f}s")
            embed_error = discord.Embed(
                title=f"{self.bot.EMOJI_INCORRECTO} Error inesperado",
                description="No se pudo completar el análisis.",
                color=discord.Color.red()
            )
            try:
                await interaction.edit_original_response(content=None, embed=embed_error)
            except discord.errors.NotFound:
                pass
            return

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
