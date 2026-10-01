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
FALLOS = "fallos"
CONTENIDO = "contenido"
MODERACION = "moderacion"
EXCLUSIONES = "exclusiones"

TITULOS_SECCION = {
    GENERAL: "General",
    AVISO: "Aviso",
    FALLOS: "Fallos",
    CONTENIDO: "Contenido",
    MODERACION: "Moderación",
    EXCLUSIONES: "Exclusiones",
}

DESCRIPCION_SECCION = {
    GENERAL: "Qué se analiza y dónde se avisa.",
    AVISO: "Cuándo se manda el embed al canal. Nada de esto toca la reacción.",
    FALLOS: "Qué fallos merecen un aviso. No aplica a las amenazas, que avisan siempre.",
    CONTENIDO: "Qué se considera NSFW y qué es contenido restringido.",
    MODERACION: "Qué hace el bot sin preguntar.",
    EXCLUSIONES: "Dónde no mirar.",
}

ACCIONES = ("ignorar", "borrar", "timeout", "banear")


# --- Motivos por los que se avisa de un fallo --------------------------------
#
# "Avisar errores" era un único interruptor para cosas que no significan lo mismo: que la
# cuota se acabó (el bot dejó de trabajar) y que un archivo era grande (no pasa nada).
#
# No son 8 interruptores sueltos: serían 256 combinaciones, algunas contradictorias, y
# duplicarían los tres maestros que ya existen. Es **un** control con los motivos, y los
# motivos solo cuentan si `avisar_errores` está activo. Una amenaza confirmada avisa
# siempre, con la configuración que haya.
#
# El orden va de "esto para el bot" a "esto es ruido", que es el orden en el que un
# admin lee la lista.
MOTIVOS_FALLO = {
    "sin_cuota": "La cuota de la API se agotó",
    "sin_claves": "Las APIs no están configuradas",
    "red": "Fallo de red o la API cayó",
    "tamano": "El archivo supera el tamaño analysesable",
    "sin_resultados": "La API no devolvió resultados",
    "cooldown": "Se alcanzó el límite de escaneos",
    "whitelist": "Había enlaces en la whitelist",
    "omitidos": "Había más adjuntos o enlaces de los permitidos",
}

# Solo estos dos valen la pena por defecto. "Demasiados adjuntos" es ruido informativo
# en cualquier servidor con tráfico normal, y la whitelist la puso el propio admin.
MOTIVOS_POR_DEFECTO = (
    "sin_cuota", "sin_claves", "red", "tamano", "sin_resultados",
    "cooldown", "whitelist",
)

# Los que explican que el bot ha dejado de funcionar. Preset "solo críticos".
MOTIVOS_CRITICOS = ("sin_cuota", "sin_claves")

# Texto corto de cada opción, que es lo que cabe en el desplegable de Discord.
AYUDA_MOTIVOS = {
    "sin_cuota": "El bot ha dejado de analizar",
    "sin_claves": "Error de configuración del bot",
    "red": "Fallo pasajero de la API",
    "tamano": "El archivo era demasiado grande",
    "sin_resultados": "La API no respondió bien",
    "cooldown": "Límite de escaneos alcanzado",
    "whitelist": "Había enlaces ignorados a propósito",
    "omitidos": "Mensaje con demasiados elementos",
}

PRESET_TODO = "todo"
PRESET_CRITICOS = "criticos"
PRESET_NINGUNO = "ninguno"
PRESETS_MOTIVOS = {
    PRESET_TODO: "Todos",
    PRESET_CRITICOS: "Solo los que paran el bot",
    PRESET_NINGUNO: "Ninguno",
}


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
    _b("auto_scan_enabled", GENERAL, "Auto-scan", True,
       "Analiza los enlaces y adjuntos de cada mensaje."),
    Clave("log_channel_id", "int", GENERAL, "Canal de logs", None, ayuda="Donde van las amenazas."),
    # --- Aviso ---
    _b("silent_mode", AVISO, "Modo silencioso", True,
       "General: con él activo solo se avisa si hay algo que mirar."),
    _b("avisar_limpios", AVISO, "Avisar limpios", False,
       "Manda el embed aunque no haya nada. Se deriva del modo silencioso."),
    _b("avisar_sospechosos", AVISO, "Avisar sospechosos", True),
    _b("avisar_errores", AVISO, "Avisar errores", True,
       "Elementos que no se pudieron comprobar por falta de cuota o por fallo."),
    _b("reacciones", AVISO, "Reacciones", True,
       "La reacción no se rige por los interruptores de aviso: va aparte."),

    # --- Contenido ---
    _n("umbral_nudity", CONTENIDO, "Nudity explícita", 0.5, 0.0, 1.0),
    _n("umbral_partial", CONTENIDO, "Nudity parcial", 0.45, 0.0, 1.0,
       "Bikini, lencería, escote: lo que más llega a un servidor."),
    _n("umbral_gore", CONTENIDO, "Gore", 0.5, 0.0, 1.0),
    _n("umbral_offensive", CONTENIDO, "Ofensivo", 0.7, 0.0, 1.0),
    _n("umbral_alcohol", CONTENIDO, "Alcohol (restringido)", 0.7, 0.0, 1.0),
    _n("umbral_weapon", CONTENIDO, "Armas (restringido)", 0.6, 0.0, 1.0,
       "Se ignoran juguetes y gestos: no son armas."),
    _b("detectar_phishing", CONTENIDO, "Detectar suplantación", True,
       "Comprobación local de texto, no gasta cuota de ninguna API."),
    # `vt_para_imagenes` NO es configurable, por el mismo motivo que los límites: cada
    # imagen cuesta un request de VirusTotal, y dejar que un admin lo active es darle
    # la llave de tu cuota mensual. Ahora lo decide el código.

    # --- Fallos ---
    # En su propia sección, y no en Aviso, por dos razones: la sección Aviso llegaba a
    # las 5 filas que Discord admite (un desplegable ocupa una fila entera), y mezclar
    # "qué se manda" con "qué fallos merecen la pena" en la misma pantalla obliga a
    # leer dos cosas distintas para entender una decisión.
    Clave("motivos_fallo", "list", FALLOS, "Motivos que avisan",
          list(MOTIVOS_POR_DEFECTO), opciones=tuple(MOTIVOS_FALLO),
          ayuda="Solo cuentan si 'Avisar errores' está activo. Una amenaza "
                "confirmada avisa siempre, pase lo que pase."),

    # --- Moderación ---
    _b("strict_mode", MODERACION, "Modo estricto", True,
       "Borra el mensaje ante una amenaza confirmada."),
    _e("accion_restringido", MODERACION, "Acción ante restringido", "ignorar", ACCIONES),
    _e("accion_phishing", MODERACION, "Acción ante suplantación", "ignorar", ACCIONES),
    _e("accion_malicious", MODERACION, "Acción ante malware", "borrar", ACCIONES),

    # --- Exclusiones ---
    # Solo `whitelist` de esta sección: canales y roles exentos quedarían como
    # controles muertos. Se pueden añadir cuando se implementen de verdad.
    Clave("whitelist", "list", EXCLUSIONES, "Dominios en whitelist", []),

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


def _legible_motivos(seleccion: List[str]) -> str:
    """Resumen de los motivos activos que quepa en un campo de embed.

    La cuenta es lo que importa ("7 de 8"), no la lista entera: con ocho motivos, un
    campo de embed quedaría en un muro de texto que nadie lee. Y los motivos que faltan
    son los interesantes: son los que están callados.
    """
    total = len(MOTIVOS_FALLO)
    activos = [m for m in MOTIVOS_FALLO if m in set(seleccion)]
    if not activos:
        return f"*Ninguno* · {total} silenciados"
    if len(activos) == total:
        return f"*Todos* ({total})"
    faltan = total - len(activos)
    return f"**{len(activos)}** de {total} · sin avisar: {', '.join(faltan and [MOTIVOS_FALLO[m] for m in MOTIVOS_FALLO if m not in set(seleccion)][:2])}" + (f" (+{faltan - 2})" if faltan > 2 else "")


def resumen_seccion(config: dict, seccion: str) -> List[tuple[str, str]]:
    """[(etiqueta, valor legible)] de una sección, para mostrarla."""
    return [(c.etiqueta, _legible(c, config.get(c.nombre, c.default)))
            for c in claves_de(seccion)]


def _legible(clave: Clave, valor: Any) -> str:
    if clave.tipo == "bool":
        return "Activado" if valor else "Desactivado"
    if clave.tipo == "float":
        return f"{float(valor):.0%}"
    if clave.nombre == "motivos_fallo":
        return _legible_motivos(valor or [])
    if clave.tipo == "list":
        if not valor:
            return "*Ninguno*"
        texto = ", ".join(str(v) for v in valor[:3])
        extra = f" *+{len(valor) - 3}*" if len(valor) > 3 else ""
        return texto + extra
    return "*No configurado*" if valor is None else str(valor)
