"""Panel de configuración interactivo de `/settings`.

El problema que resuelve: la configuración eran cinco booleanos accesibles con siete
comandos sueltos, sin forma de cambiar un umbral ni de excluir un canal. Añadir una
opción obligaba a escribir un comando entero.

El panel recorre `core.config_schema`, así que **no puede** mostrar una clave que no
exista ni dejar fuera una que sí, y cada cambio se valida con el mismo validador que usa
el resto del sistema.

Dos detalles de implementación que importan:

- `timeout=None` y el estado vive en la config del guild, no en el objeto. Un view con
  `timeout` se recolecta a los 15 minutos y un panel a medio rellenar se quedaba muerto;
  y si guardara el estado en los botones, tras un reinicio dejarían de responder.
- Los umbrales son botones que ciclan valores, no desplegables. Discord limita a **5
  filas** por panel y cada `Select` ocupa una fila entera: con el menú de secciones y seis
  umbrales, seis desplegables eran ocho filas y `discord.ui.View` lanzaba
  `could not find open space for item`.
"""

from __future__ import annotations

import logging
from typing import Optional

import discord

from core import config_schema as esq
from core.guild_config import actualizar_config, obtener_config_guild
from ui import embed as emb

log = logging.getLogger("panel")

PREFIJO = "threat:cfg:"
BOOLEANO = f"{PREFIJO}bool:"
UMBRAL = f"{PREFIJO}thr:"

MAX_FILAS = 5                 # Discord no admite más de 5 filas por panel
MAX_BOTONES_POR_FILA = 5


class MenuSecciones(discord.ui.Select):
    """Elige la sección del panel."""

    def __init__(self, seccion_actual: str):
        super().__init__(
            placeholder="Sección de los ajustes…",
            min_values=1,
            max_values=1,
            custom_id=f"{PREFIJO}menu",
            options=[
                discord.SelectOption(
                    label=esq.TITULOS_SECCION[s],
                    value=s,
                    description=esq.DESCRIPCION_SECCION[s],
                    default=(s == seccion_actual),
                )
                for s in esq.secciones()
            ],
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        if interaction.guild is None:
            await interaction.response.send_message(
                f"{emb.EMOJI_ERROR} Este panel solo funciona en servidores.", ephemeral=True)
            return
        panel = await PanelConfig.crear(self.values[0], interaction.guild)
        await interaction.response.edit_message(embed=await panel.embed(), view=panel)


class SelectorUmbral(discord.ui.Button):
    """Un umbral, ajustado con un botón que cicla entre pasos.

    Los pasos van en saltos de 25%. Un umbral fino (0.45 frente a 0.50) no cambia la
    vida de nadie; lo que importa es que quien lo ajusta vea de un vistazo dónde está.
    """

    PASOS = (0.0, 0.25, 0.5, 0.75, 1.0)

    def __init__(self, nombre: str, etiqueta: str, valor: float):
        self.nombre = nombre
        super().__init__(
            label=f"{etiqueta[:56]} \u00b7 {valor:.0%}",
            custom_id=f"{UMBRAL}{nombre}",
            style=discord.ButtonStyle.primary,
        )

    def siguiente(self, valor: float) -> float:
        """El paso siguiente, dando la vuelta al final."""
        try:
            i = self.PASOS.index(round(valor, 2))
        except ValueError:
            i = min(range(len(self.PASOS)), key=lambda j: abs(self.PASOS[j] - valor))
        return self.PASOS[(i + 1) % len(self.PASOS)]

    async def callback(self, interaction: discord.Interaction) -> None:
        if interaction.guild is None:
            return
        config = await obtener_config_guild(interaction.guild.id)
        await _guardar(interaction, self.nombre, self.siguiente(float(config.get(self.nombre, 0.5))))


class SelectorMotivos(discord.ui.Select):
    """Qué motivos de fallo avisan al canal. Un solo control, no ocho interruptores.

    Discord admite multi-selección (`min_values=0`), así que esto son ocho opciones en
    un desplegable en vez de ocho interruptores. La diferencia no es cosmetics: ocho
    interruptores serían 256 combinaciones, algunas contradictorias, y hay que explicar
    cuál manda. Con este control, vaciar la selección significa "ningún fallo avisa" y no
    "sin configurar", que es la ambigüedad que hace que un filtro mal entendido termine
    silenciando los avisos que sí importan.

    Solo cuenta si "Avisar errores" está activo. Una amenaza confirmada avisa siempre.
    """

    def __init__(self, seleccion: list[str]):
        seleccion = set(seleccion)
        super().__init__(
            placeholder="Motivos que avisan de un fallo…",
            # min_values=0 es lo que permite vaciarlo del todo.
            min_values=0,
            max_values=len(esq.MOTIVOS_FALLO),
            custom_id=f"{UMBRAL}motivos_fallo",
            options=[
                discord.SelectOption(
                    label=texto,
                    value=clave,
                    default=(clave in seleccion),
                    description=esq.AYUDA_MOTIVOS.get(clave, ""),
                )
                for clave, texto in esq.MOTIVOS_FALLO.items()
            ],
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        # `values` es la lista de los marcados. Discord no cambia el orden, pero se
        # ordena por el del catálogo para que la configuración guardada sea estable y no
        # dependa del orden en que el usuario hizo clic.
        elegidos = {v for v in self.values}
        ordenados = [m for m in esq.MOTIVOS_FALLO if m in elegidos]
        await _guardar(interaction, "motivos_fallo", ordenados)


class SelectorPresetMotivos(discord.ui.Select):
    """Atajo para los tres casos que se dan de verdad.

    Elegir los motivos uno a uno es cansa de visitos para quien solo quiere "solo lo que
    para el bot" o "nada". El preset sustituye la selección entera.
    """

    def __init__(self, actual: list[str]):
        super().__init__(
            placeholder="Atajo…",
            min_values=1, max_values=1,
            custom_id=f"{UMBRAL}preset_motivos",
            options=[
                discord.SelectOption(label=texto, value=valor)
                for valor, texto in esq.PRESETS_MOTIVOS.items()
            ],
        )
        self.actual = set(actual)

    async def callback(self, interaction: discord.Interaction) -> None:
        valor = self.values[0]
        if valor == esq.PRESET_TODO:
            motivos = list(esq.MOTIVOS_FALLO)
        elif valor == esq.PRESET_CRITICOS:
            motivos = list(esq.MOTIVOS_CRITICOS)
        else:
            motivos = []
        await _guardar(interaction, "motivos_fallo", motivos)


class SelectorAccion(discord.ui.Select):
    """Qué hacer ante una categoría: ignorar, borrar, timeout o banear."""

    def __init__(self, nombre: str, actual: str):
        super().__init__(
            placeholder="Acción…",
            min_values=1, max_values=1,
            custom_id=f"{UMBRAL}{nombre}",
            options=[
                discord.SelectOption(label=a.capitalize(), value=a, default=(a == actual))
                for a in esq.ACCIONES
            ],
        )
        self.nombre = nombre

    async def callback(self, interaction: discord.Interaction) -> None:
        await _guardar(interaction, self.nombre, self.values[0])


class BotonBool(discord.ui.Button):
    """Interruptor. Solo sabe su clave; el valor vive en la config del guild.

    El estado se marca con texto ("sí"/"no") y con el color del botón, no con un emoji
    unicode: el set del bot es de emojis personalizados y un tick plano del sistema
    rompería la identidad visual. Con texto además se lee sin depender del color.
    """

    def __init__(self, nombre: str, etiqueta: str, activo: bool):
        self.nombre = nombre
        super().__init__(
            label=f"{etiqueta[:70]} \u00b7 {'sí' if activo else 'no'}",
            custom_id=f"{BOOLEANO}{nombre}",
            style=discord.ButtonStyle.success if activo else discord.ButtonStyle.secondary,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        if interaction.guild is None:
            return
        config = await obtener_config_guild(interaction.guild.id)
        await _guardar(interaction, self.nombre, not bool(config.get(self.nombre)))


class PanelConfig(discord.ui.View):
    """Formulario de una sección. El estado vive en la config, aquí no hay nada."""

    def __init__(self, seccion: str):
        super().__init__(timeout=None)
        self.seccion = seccion
        self.guild: Optional[discord.Guild] = None

    @classmethod
    async def crear(cls, seccion: str, guild: discord.Guild) -> "PanelConfig":
        panel = cls(seccion)
        panel.guild = guild
        panel._rellenar(await obtener_config_guild(guild.id))
        return panel

    def _rellenar(self, config: dict) -> None:
        self.add_item(MenuSecciones(self.seccion))

        if self.seccion == esq.CONTENIDO:
            for clave in esq.claves_de(esq.CONTENIDO):
                if clave.tipo == "float":
                    self.add_item(SelectorUmbral(
                        clave.nombre, clave.etiqueta, float(config.get(clave.nombre, clave.default))))

        # Botones de los booleanos de esta sección. Fuera de "General" se añaden también
        # los de General, que es donde casi siempre se quiere tocar algo junto.
        claves = [c for c in esq.claves_de(self.seccion) if c.tipo == "bool"]
        if self.seccion != esq.GENERAL:
            claves = [c for c in esq.claves_de(esq.GENERAL) if c.tipo == "bool"] + claves

        fila: list[discord.ui.Button] = []
        for clave in claves:
            activo = bool(config.get(clave.nombre, clave.default))
            fila.append(BotonBool(clave.nombre, clave.etiqueta, activo))
            if len(fila) == MAX_BOTONES_POR_FILA:
                for boton in fila:
                    self.add_item(boton)
                fila = []
        for boton in fila:
            self.add_item(boton)

        if self.seccion == esq.FALLOS:
            motivos = list(config.get("motivos_fallo", esq.MOTIVOS_POR_DEFECTO))
            self.add_item(SelectorMotivos(motivos))
            self.add_item(SelectorPresetMotivos(motivos))

        for clave in esq.claves_de(self.seccion):
            if clave.tipo == "str" and clave.opciones and clave.nombre != "motivos_fallo":
                self.add_item(SelectorAccion(
                    clave.nombre, str(config.get(clave.nombre, clave.default))))

        self._avisar_si_no_cabe()

    def _avisar_si_no_cabe(self) -> None:
        """Falla ruidosamente en el log, no de forma incomprensible en el comando.

        Si alguien añade suficientes claves al esquema para pasarse de las 5 filas, esto
        avisa al escribir código en vez de romper en casa del usuario.
        """
        filas, ocupada = 1, 0
        for hijo in self.children:
            ancho = getattr(hijo, "width", 5)
            if ocupada + ancho > 5:
                filas, ocupada = filas + 1, 0
            ocupada += ancho
        if filas > MAX_FILAS:
            log.error(
                f"El panel de '{self.seccion}' necesita {filas} filas y Discord admite "
                f"{MAX_FILAS}. Partir el esquema en dos paneles o quitar controles.")

    async def embed(self) -> discord.Embed:
        config = await obtener_config_guild(self.guild.id)
        lineas = esq.resumen_seccion(config, self.seccion)
        descripcion = esq.DESCRIPCION_SECCION[self.seccion]
        if self.seccion == esq.GENERAL:
            descripcion += "\n\nUsa `/setlogchannel` y `/whitelist` para cambiar el canal y los dominios."
        return emb.aviso(
            f"Ajustes \u00b7 {esq.TITULOS_SECCION[self.seccion]}",
            descripcion,
            campos=[(etiqueta, valor, True) for etiqueta, valor in lineas] or None,
            con_pie=False,
        )


async def _guardar(interaction: discord.Interaction, nombre: str, valor) -> None:
    """Valida, guarda y repinta. Todo va editado en el sitio y efímero."""
    if interaction.guild is None:
        await interaction.response.send_message(
            f"{emb.EMOJI_ERROR} Este panel solo funciona en servidores.", ephemeral=True)
        return

    clave = esq.POR_NOMBRE.get(nombre)
    if clave is None:
        await interaction.response.send_message(
            f"{emb.EMOJI_ERROR} Ajuste desconocido: `{nombre}`.", ephemeral=True)
        return

    try:
        validado = clave.valida(valor)
    except ValueError as e:
        await interaction.response.send_message(f"{emb.EMOJI_ERROR} {e}", ephemeral=True)
        return

    await actualizar_config(interaction.guild.id, **{nombre: validado})
    if nombre == "silent_mode":
        # El master y "avisar limpios" van juntos: con el master activo no se manda nada
        # limpio, y al desactivarlo vuelve a mandarse. `/silentmode` ya lo hacía así, así
        # que sin esto los dos caminos divergían: el panel dejaba la guild en "general
        # apagado pero no avises de lo limpio", que el usuario no ve que es contradictorio.
        await actualizar_config(interaction.guild.id, avisar_limpios=not validado)
    log.debug(f"PANEL {nombre}={validado!r} → guild={interaction.guild.id}")

    panel = await PanelConfig.crear(_seccion_de(nombre), interaction.guild)
    await interaction.response.edit_message(embed=await panel.embed(), view=panel)


def _seccion_de(nombre: str) -> str:
    clave = esq.POR_NOMBRE.get(nombre)
    return clave.seccion if clave else esq.AVISO


async def panel_por_guild(guild: discord.Guild, seccion: str = esq.AVISO):
    """Punto de entrada para `/settings`: devuelve (embed, vista)."""
    panel = await PanelConfig.crear(seccion, guild)
    return await panel.embed(), panel
