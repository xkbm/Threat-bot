import discord
from discord.ext import commands
from discord import app_commands
import hashlib
import asyncio

class AnalisisCog(commands.Cog):
    def __init__(self, bot):
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
    async def scan(self, interaction: discord.Interaction, tipo: app_commands.Choice[str], valor: str = None, archivo: discord.Attachment = None):
        await interaction.response.defer()

        guild_id = interaction.guild.id if interaction.guild else None

        # Validación de parámetros
        if tipo.value == "file" and archivo is None:
            await interaction.edit_original_response(content=f"{self.bot.EMOJI_INCORRECTO} Adjunta un archivo para analizar.")
            return
        if tipo.value in ["url", "ip", "hash"] and not valor:
            await interaction.edit_original_response(content=f"{self.bot.EMOJI_INCORRECTO} Introduce un valor para {tipo.name}.")
            return

        # --- URL: expandir acortadores ---
        if tipo.value == "url":
            url_original = valor
            expanded = await self.bot.expandir_url(valor)
            valor = expanded if expanded else valor
            clave = f"url:{url_original}"
        elif tipo.value == "ip":
            clave = f"ip:{valor}"
        elif tipo.value == "hash":
            clave = f"hash:{valor}"
        elif tipo.value == "file":
            if archivo.size > self.bot.MAX_FILE_SIZE:
                embed = discord.Embed(
                    title=f"{self.bot.EMOJI_INCORRECTO} Archivo demasiado grande",
                    description=f"{self.bot.EMOJI_FILE} `{archivo.filename}` excede 32 MB",
                    color=discord.Color.red()
                )
                await interaction.edit_original_response(content=None, embed=embed)
                return
            clave = f"file:{archivo.filename}:{archivo.size}"

        # 1. Revisar Caché (Memoria y DB)
        tipo_res, embed, _ = self.bot.get_from_cache_mem(clave)
        if embed is None:
            tipo_res, embed, _ = await self.bot.obtener_analisis_db(clave)
            if embed is not None:
                self.bot.set_cache_mem(clave, tipo_res, embed, 0)   # mal = 0, se actualizará si es necesario

        if embed is not None:
            if tipo.value == "url" and expanded and expanded != url_original:
                embed.add_field(
                    name=f"{self.bot.EMOJI_REPLY} Redirección",
                    value=f"Original: `{url_original}`\nExpandida: `{valor}`",
                    inline=False
                )
            embed = embed.copy()

            if tipo.value == "file" and archivo is not None:
                if self.bot.tiene_doble_extension(archivo.filename):
                    if not any("Doble extensión" in field.name for field in embed.fields):
                        embed.add_field(
                            name=f"{self.bot.EMOJI_WARNING} Doble extensión",
                            value=f"`{archivo.filename}` podría ser peligroso.",
                            inline=False
                        )
            await interaction.edit_original_response(content=None, embed=embed)
            return

        # 2. Análisis real (devuelven tipo, embed, mal)
        if tipo.value == "url":
            tipo_res, embed, mal = await self.bot.analizar_url(valor, guild_id=guild_id, guardar_cache=True)
            if expanded and expanded != url_original:
                embed.add_field(
                    name=f"{self.bot.EMOJI_REPLY} Redirección",
                    value=f"Original: `{url_original}`\nExpandida: `{valor}`",
                    inline=False
                )
        elif tipo.value == "ip":
            tipo_res, embed, mal = await self.bot.analizar_ip(valor, guild_id=guild_id, guardar_cache=True)
        elif tipo.value == "hash":
            tipo_res, embed, mal = await self.bot.analizar_hash(valor, guild_id=guild_id, guardar_cache=True)
        elif tipo.value == "file":
            doble_ext = self.bot.tiene_doble_extension(archivo.filename)
            warning_mime = ""
            try:
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

                    content_type = resp.headers.get('Content-Type', '')
                    if archivo.filename.lower().endswith('.jpg') or archivo.filename.lower().endswith('.jpeg'):
                        if content_type not in ('image/jpeg', 'image/jpg'):
                            warning_mime = f"El archivo tiene extensión .jpg pero el tipo real es `{content_type}`."
                    elif archivo.filename.lower().endswith('.png'):
                        if content_type != 'image/png':
                            warning_mime = f"El archivo tiene extensión .png pero el tipo real es `{content_type}`."

            except Exception as e:
                embed = discord.Embed(
                    title=f"{self.bot.EMOJI_INCORRECTO} Error",
                    description="Error al descargar el archivo.",
                    color=discord.Color.red()
                )
                if doble_ext:
                    embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                await interaction.edit_original_response(content=None, embed=embed)
                return

            try:
                tipo_res, embed, mal = await self.bot.analizar_archivo(
                    archivo, file_bytes=file_bytes, file_hash=file_hash,
                    guild_id=guild_id, guardar_cache=True
                )
            except Exception as e:
                log.error(f"Error en scan archivo: {e}")
                embed = discord.Embed(
                    title=f"{self.bot.EMOJI_INCORRECTO} Error en análisis",
                    description=str(e),
                    color=discord.Color.red()
                )
                await interaction.edit_original_response(content=None, embed=embed)
                return

            if tipo_res == "error":
                if doble_ext:
                    if not any("Doble extensión" in f.name for f in embed.fields):
                        embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
                await interaction.edit_original_response(content=None, embed=embed)
                return

            if doble_ext:
                embed.add_field(name=f"{self.bot.EMOJI_WARNING} Doble extensión", value=f"`{archivo.filename}` podría ser peligroso.", inline=False)
            if warning_mime:
                embed.add_field(name=f"{self.bot.EMOJI_WARNING} Verificación MIME", value=warning_mime, inline=False)

            await interaction.edit_original_response(content=None, embed=embed)
            return

        # 3. Mostrar el resultado final para URL, IP, Hash
        await interaction.edit_original_response(content=None, embed=embed)

    @scan.error
    async def scan_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.CommandOnCooldown):
            await interaction.response.send_message(
                f"{self.bot.EMOJI_WARNING} **¡Cuidado!** Estás usando el comando muy rápido. "
                f"Inténtalo de nuevo en **{error.retry_after:.1f}s**.",
                ephemeral=True
            )
        else:
            if not interaction.response.is_done():
                await interaction.response.send_message(
                    f"{self.bot.EMOJI_INCORRECTO} Ocurrió un error inesperado.",
                    ephemeral=True
                )

async def setup(bot):
    await bot.add_cog(AnalisisCog(bot))