"""Esquema declarativo de la configuración por servidor.

Motivo: la configuración eran cinco booleanos y una lista repartidos por `dict` sueltos en
cinco ficheros. Añadir un ajuste era tocar cinco sitios y era fácil que uno se quedara
sin cubrir, que es como aparecieron los descuadres entre `/settings`, `/silentmode` y la
lógica real.

Aquí cada clave se declara **una vez**, con su tipo, su rango, su sección y su etiqueta.
A partir de ahí:

- la validación y el recorte ("clampar") salen del esquema, no de un `if` por comando;
- el panel se dibuja recorriendo el esquema, así que no puede mostrar una clave que no
  exista ni dejar fuera una que sí;
- `/settings` y los atajos de un paso leen y escriben por el mismo sitio.

Los valores por defecto de los interruptores de aviso NO se fijan aquí: se derivan de
`silent_mode` la primera vez que se ve un servidor, para que actualizar el bot no cambie
lo que recibe nadie. Ver `core.aviso.config_aviso_por_defecto`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# --- Secciones -------------------------------------------------------------
GENERAL = "general"
AVISO = "aviso"
CONTENIDO = "contenido"
MODERACION = "moderacion"
EXCLUSIONES = "exclusiones"

TITULOS_SECCION = {
    GENERAL: "General",
    AVISO: "Avisos",
    CONTENIDO: "Contenido",
    MODERACION: "Moderación",
    EXCLUSIONES: "Exclusiones",
}

DESCRIPCION_SECCION = {
    GENERAL: "Qué analiza el bot y dónde manda sus avisos.",
    AVISO: "Qué te avisa el bot, y cómo.",
    CONTENIDO: "Qué considera peligroso en las imágenes.",
    MODERACION: "Qué hace el bot cuando encuentra algo.",
    EXCLUSIONES: "Dónde el bot no mira.",
}

ACCIONES = ("ignorar", "borrar", "timeout", "banear")


# --- Categorías notificables ------------------------------------------------
#
# Un dial por categoría. La alternativa eran tres interruptores (limpios, sospechosos,
# errores) y una lista aparte para los motivos de fallo, con lo que el admin no podía
# silencingar "se acabó la cuota" sin callar también "había demasiados adjuntos", y no
# podía callar el NSFW sin callar el malware.
#
# Con un dial por categoría, quien configura decide qué le importa en su servidor, que es
# justo lo que no se puede suponer. El estado "todo apagado" existe y es legítimo: hay
# quien prefiere mirar el panel en silencio y usar solo la reacción.
#
# El orden es el de a qué le conviene al usuario enterarse antes.

# Clave -> (etiqueta, [ayuda del desplegable])
CATEGORIAS: dict[str, tuple[str, str]] = {
    # Lo que se ha encontrado
    "malicioso": ("Malware", "Archivos y enlaces confirmados como maliciosos"),
    "phishing": ("Suplantación de marca", "Dominios que imitan a una marca real"),
    "nsfw": ("NSFW", "Desnudez, gore y contenido ofensivo en imágenes"),
    "restringido": ("Restringido", "Alcohol y armas. No borra el mensaje"),
    "sospechoso": ("Sospechoso", "Señal débil de VirusTotal, sin confirmar"),
    "nombre_sospechoso": ("Nombre engañoso", "Doble extensión o extensión que no cuadra"),
    # Lo que no se ha podido mirar
    "sin_cuota": ("Cuota agotada", "El bot dejó de analizar: se acabó la cuota de la API"),
    "sin_claves": ("Sin configurar", "Las APIs no están configuradas en el bot"),
    "red": ("Fallo de red", "La API no respondió"),
    "sin_resultados": ("Sin resultados", "La API respondió pero sin datos útiles"),
    "cooldown": ("Límite de escaneos", "El usuario alcanzó su límite por hora"),
    "tamano": ("No analizable por tamaño", "El archivo supera lo que admite la API"),
    "whitelist": ("Enlaces en whitelist", "Había enlaces ignorados a propósito"),
    "omitidos": ("Demasiados adjuntos", "El mensaje traía más de los que se analizan"),
    "limpio": ("Mensajes limpios", "No se encontró nada en absoluto"),
}

CATEGORIAS_AVISO = tuple(CATEGORIAS)

# Todo activado menos lo que es ruido puro: un mensaje sin nada no requiere un aviso, y
# decir "traías 6 adjuntos y analicé 5" cada vez tampoco.
CATEGORIAS_POR_DEFECTO = tuple(
    c for c in CATEGORIAS_AVISO if c not in ("limpio", "omitidos")
)

PRESET_TODO = "todo"
PRESET_CRITICOS = "criticos"
PRESET_NADA = "nada"
PRESETS_NOTIFICACION = {
    PRESET_TODO: "Todo",
    PRESET_CRITICOS: "Solo lo grave",
    PRESET_NADA: "Nada",
}
# Lo grave es lo que requiere acción inmediata: una amenaza confirmada, una suplantación
# y el bot parado por cuota.
CATEGORIAS_CRITICAS = ("malicioso", "phishing", "nsfw", "sin_cuota", "sin_claves")


@dataclass(frozen=True)
class Clave:
    """Una opción de configuración."""

    nombre: str
    tipo: str                       # 'bool' | 'float' | 'int' | 'str' | 'list'
    seccion: str
    etiqueta: str
    default: Any
    minimo: Optional[float] = None
    maximo: Optional[float] = None
    opciones: Optional[List[str]] = None   # valores admitidos si es elección cerrada
    ayuda: str = ""
    # La etiqueta ya es una afirmación ("Avisar de todo"): el botón pone el estado sin
    # invertirla, porque "Avisar de todo: no" sí se lee al revés.
    afirmativa: bool = False

    def valida(self, valor: Any) -> Any:
        """Normaliza un valor o lanza `ValueError` si no se puede representar.

        Los números fuera de rango se recortan en lugar de fallar: un `0.99` calculado a
        mano no debería dejar el bot sin poder arrancar.
        """
        if self.tipo == "bool":
            if isinstance(valor, bool):
                return valor
            if isinstance(valor, str):
                bajo = valor.strip().lower()
                if bajo in ("true", "1", "si", "sí", "yes"):
                    return True
                if bajo in ("false", "0", "no"):
                    return False
            if isinstance(valor, (int, float)):
                return bool(valor)
            raise ValueError(f"{self.nombre}: se esperaba booleano, llegó {valor!r}")

        if self.tipo in ("int", "float"):
            try:
                numero = float(valor)
            except (TypeError, ValueError):
                raise ValueError(f"{self.nombre}: se esperaba un número, llegó {valor!r}")
            if self.minimo is not None and numero < self.minimo:
                numero = self.minimo
            if self.maximo is not None and numero > self.maximo:
                numero = self.maximo
            return int(numero) if self.tipo == "int" else float(numero)

        if self.tipo == "list":
            if isinstance(valor, str):
                valor = [v.strip() for v in valor.split(",") if v.strip()]
            if not isinstance(valor, list):
                raise ValueError(f"{self.nombre}: se esperaba una lista, llegó {valor!r}")
            items = [str(v) for v in valor]
            if self.opciones is not None:
                # Un motivo desconocido se descarta en vez de propagarse: no coincide
                # nunca con nada, así que guardarlo es ruido que confunde al leer la
                # configuración.
                desconocidos = [i for i in items if i not in self.opciones]
                if desconocidos:
                    raise ValueError(
                        f"{self.nombre}: valor no válido: {', '.join(desconocidos)}. "
                        f"Vale: {', '.join(self.opciones)}"
                    )
            return items

        texto = str(valor)
        if self.opciones is not None and texto not in self.opciones:
            raise ValueError(
                f"{self.nombre}: '{texto}' no es válido. Vale: {', '.join(self.opciones)}"
            )
        # `minimo`/`maximo` también valen para texto. Antes se declaraban y no se
        # usaban, así que un prefijo de 200 caracteres se guardaba entero.
        if self.maximo is not None and len(texto) > self.maximo:
            texto = texto[: self.maximo]
        return texto


def _b(nombre, seccion, etiqueta, default, ayuda="") -> Clave:
    return Clave(nombre, "bool", seccion, etiqueta, default, ayuda=ayuda)


def _n(nombre, seccion, etiqueta, default, minimo=None, maximo=None, ayuda="") -> Clave:
    return Clave(nombre, "float", seccion, etiqueta, default, minimo, maximo, ayuda=ayuda)


def _e(nombre, seccion, etiqueta, default, opciones, ayuda="") -> Clave:
    return Clave(nombre, "str", seccion, etiqueta, default, opciones=opciones, ayuda=ayuda)


ESQUEMA: tuple[Clave, ...] = (
    # --- General ---
    _b("auto_scan_enabled", GENERAL, "Analizar los mensajes", True,
       "Con esto apagado el bot solo responde cuando alguien usa /scan."),
    _b("avisar_amenazas", GENERAL, "Avisar en el canal de registro", True,
       "Marca cada hallazgo en el canal de registro. Puedes dejarlo apagado y seguir "
       "recibiendo los avisos en el chat de donde salió el mensaje."),
    Clave("log_channel_id", "int", GENERAL, "Canal de registro", None,
          ayuda="Donde queda constancia de lo que se ha encontrado. Déjalo vacío si no "
                "quieres registro."),
    # --- Aviso ---
    Clave("avisar_todo", "bool", AVISO, "Avisar de todo", True,
          afirmativa=True,
          ayuda="El interruptor general. Desactivado, el bot no manda ningún aviso, ni de "
                "amenazas: es para cuando se está comiendo un canal. Para callar una sola "
                "cosa, desmarcala abajo. Las reacciones se ponen igual."),
    _b("reacciones", AVISO, "Poner un emoji en el mensaje", True,
       "El emoji que resume cómo acabó el análisis. Es independiente de los avisos: "
       "puedes querer el emoji pero no los mensajes largos."),
    Clave("notificar", "list", AVISO, "Avisar de",
          list(CATEGORIAS_POR_DEFECTO), opciones=CATEGORIAS_AVISO,
          ayuda="Marca lo que quieres que llegue al canal. Lo que no marques, no suena."),

    # --- Contenido ---
    _n("umbral_nudity", CONTENIDO, "Desnudez explícita", 0.5, 0.0, 1.0,
       ayuda="Contenido sexual directo. A 50% solo marca lo muy claro."),
    _n("umbral_partial", CONTENIDO, "Desnudez parcial", 0.45, 0.0, 1.0,
       ayuda="Bikini, lencería, escote. Es lo que más llega a un servidor, así que "
             "suele querer un umbral más bajo que el de la explícita."),
    _n("umbral_gore", CONTENIDO, "Gore", 0.5, 0.0, 1.0,
       ayuda="Sangre, heridas, violencia gráfica. En servidores de juegos es habitual."),
    _n("umbral_offensive", CONTENIDO, "Ofensivo", 0.7, 0.0, 1.0,
       ayuda="Símbolos ofensivos y contenido de odio. Más alto que el resto porque "
             "casi nunca es intencionado."),
    _n("umbral_alcohol", CONTENIDO, "Alcohol", 0.7, 0.0, 1.0,
       ayuda="Entra en 'restringido', que avisa pero no borra. Súbelo para ignorar "
             "cervezas en un meme."),
    _n("umbral_weapon", CONTENIDO, "Armas", 0.6, 0.0, 1.0,
       ayuda="También en 'restringido', así que avisa pero no borra. Los juguetes y "
             "los gestos con las manos no cuentan como arma."),
    _b("detectar_phishing", CONTENIDO, "Buscar enlaces que imitan a una marca", True,
       "Detecta cosas como rnicrosoft.com sin llamar a ninguna API, así que no gasta "
       "cuota. Avisa, pero no borra el mensaje."),
    # `vt_para_imagenes` NO es configurable, por el mismo motivo que los límites: cada
    # imagen cuesta un request de VirusTotal, y dejar que un admin lo active es darle
    # la llave de tu cuota mensual. Ahora lo decide el código.

    # --- Moderación ---
    _b("strict_mode", MODERACION, "Borrar los mensajes peligrosos", True,
       "Solo ante malware y NSFW confirmados. Ni el alcohol, ni las armas, ni un enlace "
       "sospechoso borran nada por su cuenta."),

    # --- Exclusiones ---
    # Solo `whitelist` de esta sección: canales y roles exentos quedarían como
    # controles muertos. Se pueden añadir cuando se implementen de verdad.
    Clave("whitelist", "list", EXCLUSIONES, "Dominios en los que no se mira", [],
          ayuda="Los enlaces a estos dominios no se analizan. Sirve para los sitios "
                "legítimos que mandan avisos falsos."),

    # No hay sección `CUOTA`, y es deliberado.
    #
    # Las claves de las APIs son de quien mantiene el bot y las comparten todos los
    # servidores. Si el administrador de un servidor puede subir sus propios límites,
    # gasta la cuota mensual de quien lo mantiene: le sale gratis y nadie se entera. Por
    # eso `max_adjuntos` y `max_urls` no son configurables; viven como constantes en
    # `ui/message_handler.py` y solo el código las cambia.
)

POR_NOMBRE: Dict[str, Clave] = {c.nombre: c for c in ESQUEMA}

# Claves que viven en la configuración pero no son opciones del panel.
FUERA_DEL_ESQUEMA = (
    "infracciones",
    "infracciones_registradas",
    "log_channel_id",
)


def secciones() -> List[str]:
    """Secciones en el orden en que se muestran."""
    orden: List[str] = []
    for clave in ESQUEMA:
        if clave.seccion not in orden:
            orden.append(clave.seccion)
    return orden


def claves_de(seccion: str) -> List[Clave]:
    return [c for c in ESQUEMA if c.seccion == seccion]


def validar(config: dict) -> dict:
    """Copia de `config` con las claves del esquema ya normalizadas.

    Las claves desconocidas se conservan intactas: el esquema no es una lista cerrada y
    borrarlas perdería cosas de otros módulos. Tampoco añade las que falten: rellenar es
    trabajo de `_asegurar_guild`, que conoce los defaults por guild.
    """
    limpio = dict(config)
    for clave in ESQUEMA:
        if clave.nombre not in limpio:
            continue
        try:
            limpio[clave.nombre] = clave.valida(limpio[clave.nombre])
        except ValueError:
            limpio[clave.nombre] = clave.default
    return limpio


def defaults() -> Dict[str, Any]:
    """Defaults del esquema, con la whitelist real.

    `claves_de("exclusiones")` devolvía una whitelist vacía mientras el default de
    verdad son los 15 dominios protegidos: dos defaults distintos en el módulo que
    existe precisamente para que no los haya. Cualquier código nuevo que usara la
    fuente "declarativa" se habría和规范izado de proteger `youtube.com`, `github.com` y
    `discord.com` sin decirlo.
    """
    from core.config import DOMINIOS_PROTEGIDOS

    valores = {c.nombre: c.default for c in ESQUEMA}
    valores["whitelist"] = list(DOMINIOS_PROTEGIDOS)
    return valores


def aplicar_config(umbrales: Optional[dict] = None) -> dict:
    """Construye el diccionario de umbrales que espera `evaluar_contenido`.

    Los nombres del esquema llevan prefijo `umbral_` y los de SightEngine no. Si el panel
    no ha tocado nada devuelve los de `core.config`, para que haya una sola fuente.
    """
    from core.config import UMBRALES_CONTENIDO

    resultado = dict(UMBRALES_CONTENIDO)
    if not umbrales:
        return resultado
    equivalencia = {
        "umbral_nudity": "nudity_raw",
        "umbral_partial": "nudity_partial",
        "umbral_gore": "gore",
        "umbral_offensive": "offensive",
        "umbral_alcohol": "alcohol",
        "umbral_weapon": "weapon",
    }
    for clave_esquema, clave_se in equivalencia.items():
        if clave_esquema in umbrales:
            resultado[clave_se] = float(umbrales[clave_esquema])
    return resultado


def _legible_notificar(seleccion: List[str]) -> str:
    """Resumen de qué avisa, para el embed del panel.

    La versión anterior listaba las categorías **apagadas**: "3 de 15 · sin avisar:
    Suplantación de marca, Restringido (+10)". Con quince opciones eso es un muro de
    texto, y además responde a la pregunta equivocada: quien abre la sección quiere ver
    lo que SÍ va a sonar.
    """
    activos = [c for c in CATEGORIAS if c in set(seleccion)]
    total = len(CATEGORIAS)
    if not activos:
        return "*Nada*. Solo quedará el emoji en los mensajes."
    if len(activos) == total:
        return f"*Todo* ({total})"
    return (f"**{len(activos)}** de {total} \u00b7 "
            + ", ".join(CATEGORIAS[c][0] for c in activos[:3])
            + (f" (+{len(activos) - 3})" if len(activos) > 3 else ""))


def resumen_seccion(config: dict, seccion: str) -> List[tuple[str, str]]:
    """[(etiqueta, valor legible)] de una sección, para mostrarla."""
    return [(c.etiqueta, _legible(c, config.get(c.nombre, c.default)))
            for c in claves_de(seccion)]


def _legible(clave: Clave, valor: Any) -> str:
    if clave.tipo == "bool":
        return "Activado" if valor else "Desactivado"
    if clave.tipo == "float":
        return f"{float(valor):.0%}"
    if clave.nombre == "notificar":
        return _legible_notificar(valor or [])
    if clave.tipo == "list":
        if not valor:
            return "*Ninguno*"
        texto = ", ".join(str(v) for v in valor[:3])
        extra = f" *+{len(valor) - 3}*" if len(valor) > 3 else ""
        return texto + extra
    return "*No configurado*" if valor is None else str(valor)


# Los dominios que el bot trae en la whitelist de serie. Se pueden quitar desde el panel,
# pero vuelven a aparecer al reiniciar, y el panel lo avisa en vez de dejarlo caer en
# silencio. Está aquí y no importado en cada sitio para que quien use el esquema no tenga
# que saber de dónde sale la lista.
from core.config import DOMINIOS_PROTEGIDOS  # noqa: E402  (al final: evita ciclo


def es_protegido(dominio: str) -> bool:
    """¿Este dominio venía de serie en lugar de haberlo añadido un admin?"""
    return (dominio or "").lower() in DOMINIOS_PROTEGIDOS
