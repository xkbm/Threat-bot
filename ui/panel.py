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
from core.utils import es_dominio_valido, normalizar_dominio
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


class SelectorCanalLog(discord.ui.Select):
    """Elige el canal de logs entre los del servidor.

    Antes el panel lo mostraba pero no lo cambiaba: había que resorting a
    `/setlogchannel`. Es una opción por guild más, de las que un admin tiene que poder
    tocar sin recordar un comando aparte.
    """

    def __init__(self, actual: Optional[int], canales: list[discord.TextChannel]):
        opciones = [
            discord.SelectOption(
                label="Sin canal de logs",
                value="0",
                description="No se avisará a ningún canal de amenazas.",
                default=(not actual),
            )
        ]
        # Discord admite 25 opciones: primero los del servidor, y si hay más se avisa por
        # log, porque truncarlos en silencio sería dejar fuera canales a propósito.
        texto = [c for c in canales if c is not None][:24]
        if len([c for c in canales if c is not None]) > 24:
            log.warning(
                "Más de 24 canales de texto: el desplegable muestra los primeros. "
                "Usa /setlogchannel para elegir uno que no aparezca."
            )
        for c in texto:
            opciones.append(discord.SelectOption(
                label=c.name[:100],
                value=str(c.id),
                description=(c.topic or "")[:100] or None,
                default=(c.id == actual),
            ))
        super().__init__(placeholder="Canal de logs…", min_values=1, max_values=1,
                         custom_id=f"{UMBRAL}log_channel_id", options=opciones)

    async def callback(self, interaction: discord.Interaction) -> None:
        valor = int(self.values[0])
        await _guardar(interaction, "log_channel_id", valor or None)


class AnadirWhitelist(discord.ui.Modal, title="Añadir dominio a la whitelist"):
    """Pedir el dominio a escribir. Un `Select` de canales no sirve para texto libre."""

    def __init__(self):
        super().__init__()
        self.dominio = discord.ui.TextInput(
            label="Dominio",
            placeholder="ejemplo.com",
            max_length=100,
            required=True,
        )
        self.add_item(self.dominio)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        from core.guild_config import agregar_dominio, obtener_config_guild

        # Se reutiliza la normalización y la validación del comando `/whitelist`, en vez
        # de reimplementarlas: dos copias del chequeo de dominio siempre divergen.
        bruto = normalizar_dominio(self.dominio.value)
        if not es_dominio_valido(bruto):
            await interaction.response.send_message(
                f"{emb.EMOJI_ERROR} Eso no parece un dominio: `{self.dominio.value}`",
                ephemeral=True)
            return

        config = await obtener_config_guild(interaction.guild.id)
        if bruto in config.get("whitelist", []):
            await interaction.response.send_message(
                f"{emb.EMOJI_CORRECTO} `{bruto}` ya está en la whitelist.",
                ephemeral=True)
            return

        await agregar_dominio(interaction.guild.id, bruto)
        await interaction.response.send_message(
            f"{emb.EMOJI_CORRECTO} `{bruto}` añadido a la whitelist. Sus enlaces no se "
            f"analizan, pero el bot sigue avisando si quieres.",
            ephemeral=True)


class BotonAnadirWhitelist(discord.ui.Button):
    def __init__(self):
        super().__init__(label="Añadir dominio", custom_id=f"{PREFIJO}wl_add",
                         style=discord.ButtonStyle.secondary)

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_modal(AnadirWhitelist())


class SelectorQuitarWhitelist(discord.ui.Select):
    """Quita un dominio de la whitelist.

    El complements de `BotonAnadirWhitelist`. Sin esto, quitar un dominio obligaba a
    recordar `/whitelist remove`: se podía añadir desde el panel pero no deshacer, lo
    que es la peor forma de dejar medio migrado un ajuste.

    Solo aparece si hay dominios: un `Select` sin opciones no se puede construir, y un
    desplegable vacío se lee como un fallo del bot.
    """

    def __init__(self, dominios: list[str], protegidos: frozenset):
        self.dominios = list(dominios)
        # Discord admite 25 opciones. Los protegidos no se ofrecen: no se pueden quitar
        # por comando, así que incluirlos sería ofrecer algo que va a fallar.
        quitables = [d for d in self.dominios if d not in protegidos]
        if not quitables:
            quitables = self.dominios
        opciones = []
        for d in quitables[:25]:
            opciones.append(discord.SelectOption(
                label=d[:100],
                value=d,
                description=("Protegido: se puede quitar, pero volverá al reiniciar"
                             if d in protegidos else "Quitar de la whitelist"),
            ))
        if not opciones:
            return
        super().__init__(placeholder="Quitar un dominio…", min_values=1, max_values=1,
                         custom_id=f"{UMBRAL}wl_quitar", options=opciones)

    async def callback(self, interaction: discord.Interaction) -> None:
        from core.guild_config import quitar_dominio

        dominio = self.values[0]
        await quitar_dominio(interaction.guild.id, dominio)
        await interaction.response.send_message(
            f"{emb.EMOJI_CORRECTO} `{dominio}` ya no está en la whitelist. Sus enlaces se "
            f"analizarán con normalidad.",
            ephemeral=True,
        )


class SelectorNotificaciones(discord.ui.Select):
    """Qué categorías avisan al canal. Un dial por categoría, en un solo desplegable.

    Discord admite multi-selección con `min_values=0`, así que esto son quince opciones
    marcadas y desmarcadas a voluntad, en vez de quince interruptores repartidos por
    cinco filas de un panel que Discord limita a cinco.

    Vaciar la selección es un estado legítimo: "no me avises de nada, solo pon la
    reacción". Por eso `min_values=0` y no "al menos una": no se puede forzar al usuario a
    recibir avisos que no quiere.
    """

    def __init__(self, seleccion: list[str]):
        marcados = set(seleccion)
        super().__init__(
            placeholder="Categorías que avisan…",
            min_values=0,
            max_values=len(esq.CATEGORIAS),
            custom_id=f"{UMBRAL}notificar",
            options=[
                discord.SelectOption(
                    label=etiqueta,
                    value=clave,
                    description=ayuda[:100],
                    default=(clave in marcados),
                )
                for clave, (etiqueta, ayuda) in esq.CATEGORIAS.items()
            ],
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        # Se guarda en el orden del catálogo, no en el que hizo clic: así el JSON de
        # configuración es estable y dos servidores con lo mismo se parecen.
        elegidos = set(self.values)
        ordenados = [c for c in esq.CATEGORIAS if c in elegidos]
        await _guardar(interaction, "notificar", ordenados)


class SelectorPresetNotificaciones(discord.ui.Select):
    """Atajo para los tres casos que se dan de verdad.

    Marcar quince casillas una a una es un coñazo, y casi nadie quiere una configuración
    intermediaria: quiere "todo", "solo lo grave" o "nada".
    """

    def __init__(self):
        super().__init__(
            placeholder="Atajo…",
            min_values=1, max_values=1,
            custom_id=f"{UMBRAL}preset_notificar",
            options=[
                discord.SelectOption(label=texto, value=valor)
                for valor, texto in esq.PRESETS_NOTIFICACION.items()
            ],
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        valor = self.values[0]
        if valor == esq.PRESET_TODO:
            seleccion = list(esq.CATEGORIAS_AVISO)
        elif valor == esq.PRESET_CRITICOS:
            seleccion = list(esq.CATEGORIAS_CRITICAS)
        else:
            seleccion = []
        await _guardar(interaction, "notificar", seleccion)


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

        # El canal de logs solo se puede elegir si el panel se abrió en un servidor con
        # canales de texto; sin ellos, el valor se sigue mostrando en el embed.
        if self.seccion == esq.GENERAL and self.guild is not None:
            canales = self._canales_de_texto()
            if canales is not None:
                self.add_item(SelectorCanalLog(config.get("log_channel_id"), canales))

        if self.seccion == esq.EXCLUSIONES:
            self.add_item(BotonAnadirWhitelist())
            # Solo si hay algo que quitar. Los protegidos se ofrecen igual, con aviso
            # aparte: están en la whitelist porque vino de serie, no porque el admin
            # los eligió, y no debe poder distinguirlos a simple vista.
            dominios = list(config.get("whitelist") or [])
            if dominios:
                self.add_item(SelectorQuitarWhitelist(
                    dominios, esq.DOMINIOS_PROTEGIDOS))

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
            # La lista completa va en su propia seccion (se llama FALLOS pero contiene
            # también hallazgos): en Aviso ya hay interruptores y los desplegables ocupan
            # filas enteras de las cinco que admite Discord.
            self.add_item(SelectorNotificaciones(
                list(config.get("notificar") or esq.CATEGORIAS_POR_DEFECTO)))
            self.add_item(SelectorPresetNotificaciones())

        for clave in esq.claves_de(self.seccion):
            if clave.tipo == "str" and clave.opciones and clave.nombre != "notificar":
                self.add_item(SelectorAccion(
                    clave.nombre, str(config.get(clave.nombre, clave.default))))

        self._avisar_si_no_cabe()

    def _canales_de_texto(self):
        """Canales de texto del guild, o None si no se pueden obtener.

        Se capturan los errores: un panel que no se puede construir es peor que un panel
        sin el selector, y `get_channel` puede fallar por permisos o por rate limit.
        """
        try:
            return [c for c in self.guild.text_channels if c.permissions_for(self.guild.me).send_messages]
        except Exception as e:
            log.debug(f"No se pudieron listar los canales: {type(e).__name__}")
            return None

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
            descripcion += (
                "\n\nTodo se ajusta desde aquí: el interruptor general silencia el bot "
                "de golpe, y en **Aviso** hay un dial por cada categoría."
            )
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
