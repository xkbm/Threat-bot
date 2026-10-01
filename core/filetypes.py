"""Detección del tipo real de un archivo por sus bytes iniciales.

Por qué existe: `es_imagen()` en `core/utils.py` decide por extensión o por el
`Content-Type` que Discord deduce del nombre. Eso deja pasar un ejecutable llamado
`malware.png`, porque Discord lo sirve como `image/png` y el bot lo trata como imagen:
solo NSFW, nunca malware. Aquí la decisión la toman los bytes.

`imghdr` no sirve: está deprecado desde 3.11 y se eliminó en 3.13 (PEP 594). Se
implementa a mano porque las firmas son pocas y así no se añade una dependencia.

Regla de oro: ante la duda, `DESCONOCIDO`. Un archivo que no se sabe clasificar se
manda a VirusTotal, que es el análisis más conservador de los dos.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple

# Cabecera leída para clasificar. Todas las firmas relevantes caben aquí de sobra.
CABECERA_BYTES = 4096


class TipoContenido(Enum):
    """Familia de contenido. Determina qué análisis se aplica."""

    IMAGEN = "imagen"
    EJECUTABLE = "ejecutable"
    DOCUMENTO = "documento"
    ARCHIVO = "archivo"
    DESCONOCIDO = "desconocido"

    @property
    def es_imagen(self) -> bool:
        return self is TipoContenido.IMAGEN


# MIME esperado por formato. Sirve para detectar el "extensión .png pero bytes PE".
# Los alias van porque `foto.jpg` y `foto.jpeg` son el mismo formato: sin la clave
# "jpg", `mime_de_extension` devolvía None y un `.jpg` se saltaba la comprobación de
# MIME entera, que el código antiguo sí hacía.
_MIME_IMAGEN: Dict[str, str] = {
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "jpe": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "webp": "image/webp",
    "bmp": "image/bmp",
    "ico": "image/x-icon",
    "tif": "image/tiff",
    "tiff": "image/tiff",
    "heic": "image/heic",
    "heif": "image/heif",
    "avif": "image/avif",
    "svg": "image/svg+xml",
}

# Formatos que Discord no acepta ni sirve como imagen: un archivo con cabecera PDF
# al que se le pone extensión .png es exactamente el ataque que queremos ver.
_MIME_EJECUTABLE: Dict[str, str] = {
    "pe": "application/vnd.microsoft.portable-executable",
    "elf": "application/x-executable",
    "macho": "application/x-mach-binary",
    "script": "text/x-script",
}

_MIME_DOCUMENTO: Dict[str, str] = {
    "pdf": "application/pdf",
    "zip": "application/zip",
    "ooxml": "application/vnd.openxmlformats-officedocument",
    "ole": "application/msword",
    "rar": "application/vnd.rar",
    "sevenzip": "application/x-7z-compressed",
}


@dataclass(frozen=True)
class Deteccion:
    """Resultado de clasificar unos bytes.

    `formato` es el nombre corto ('png', 'pe', 'pdf'...). Puede ser None cuando los
    bytes no coinciden con ninguna firma conocida, en cuyo caso el tipo es
    DESCONOCIDO y `mime_esperado` también lo es.
    """

    tipo: TipoContenido
    formato: Optional[str]
    mime_esperado: Optional[str]

    @property
    def es_imagen(self) -> bool:
        return self.tipo is TipoContenido.IMAGEN

    def __str__(self) -> str:
        return self.formato or self.tipo.value


DESCONOCIDA = Deteccion(TipoContenido.DESCONOCIDO, None, None)


def _empieza(datos: bytes, firma: bytes) -> bool:
    return datos[: len(firma)] == firma


def _formato_imagen(datos: bytes) -> Optional[Tuple[str, str]]:
    """Devuelve (formato, mime) si los bytes son una imagen."""
    if _empieza(datos, b"\xff\xd8\xff"):
        return "jpeg", "image/jpeg"
    if _empieza(datos, b"\x89PNG\r\n\x1a\n"):
        return "png", "image/png"
    if _empieza(datos, b"GIF87a") or _empieza(datos, b"GIF89a"):
        return "gif", "image/gif"
    # WebP es RIFF + 4 bytes de tamaño + "WEBP".
    if _empieza(datos, b"RIFF") and datos[8:12] == b"WEBP":
        return "webp", "image/webp"
    if _empieza(datos, b"BM"):
        return "bmp", "image/bmp"
    if _empieza(datos, b"\x00\x00\x01\x00"):
        return "ico", "image/x-icon"
    if _empieza(datos, b"II*\x00") or _empieza(datos, b"MM\x00*"):
        return "tiff", "image/tiff"
    # Contenedores HEIF/AVIF: la caja empieza con 4 bytes de tamaño, luego "ftyp" en
    # el offset 4, y la marca real 4 bytes después de eso.
    if datos[4:8] == b"ftyp":
        marca = datos[8:12]
        if marca in (b"heic", b"heix", b"hevc", b"hevx"):
            return "heic", "image/heic"
        if marca in (b"avif", b"avis"):
            return "avif", "image/avif"
        return None
    # SVG es texto: puede venir con BOM, espacios o una declaración XML delante, o
    # empezar directamente por la etiqueta.
    inicio = datos.lstrip()[:512].lower()
    if b"<svg" in inicio:
        return "svg", "image/svg+xml"
    return None


def _formato_ejecutable(datos: bytes) -> Optional[Tuple[str, str]]:
    """Devuelve (formato, mime) si los bytes son código ejecutable."""
    if _empieza(datos, b"MZ"):
        return "pe", "application/vnd.microsoft.portable-executable"
    if _empieza(datos, b"\x7fELF"):
        return "elf", "application/x-executable"
    # Mach-O tiene varias cabeceras; esta comprobación cubre las de 64 y 32 bits.
    if datos[:4] in (
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ):
        return "macho", "application/x-mach-binary"
    # shebang: #!/bin/sh, #!/usr/bin/env python, ...
    if _empieza(datos, b"#!"):
        return "script", "text/x-script"
    return None


def _formato_documento(datos: bytes) -> Optional[Tuple[str, str]]:
    """Devuelve (formato, mime) si los bytes son un documento o contenedor."""
    if _empieza(datos, b"%PDF"):
        return "pdf", "application/pdf"
    if _empieza(datos, b"PK\x03\x04"):
        # Un ZIP con [Content_Types].xml es un documento de Office moderno.
        if b"[Content_Types].xml" in datos[:2048]:
            return "ooxml", "application/vnd.openxmlformats-officedocument"
        return "zip", "application/zip"
    if _empieza(datos, b"Rar!"):
        return "rar", "application/vnd.rar"
    if _empieza(datos, b"7z\xbc\xaf\x27\x1c"):
        return "sevenzip", "application/x-7z-compressed"
    # OLE2: el contenedor de .doc/.xls antiguos. Distinto de D0CF11E0 (OLE) sí, OLE2.
    if _empieza(datos, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole", "application/msword"
    return None


def detectar(contenido: bytes) -> Deteccion:
    """Clasifica `contenido` leyendo solo sus primeros `CABECERA_BYTES`.

    El orden importa: se comprueba ejecutable ANTES que documento y documento antes
    que imagen. Hay formatos que comparten prefijo y, en caso de ambigüedad real,
    gana siempre la clasificación que lleva el archivo a VirusTotal.
    """
    if not contenido:
        return DESCONOCIDA

    datos = contenido[:CABECERA_BYTES]

    # PE antes que documento: un .doc antiguo empieza igual que un .exe de DOS.
    ejecutable = _formato_ejecutable(datos)
    if ejecutable:
        return Deteccion(TipoContenido.EJECUTABLE, ejecutable[0], ejecutable[1])

    documento = _formato_documento(datos)
    if documento:
        return Deteccion(TipoContenido.DOCUMENTO, documento[0], documento[1])

    imagen = _formato_imagen(datos)
    if imagen:
        return Deteccion(TipoContenido.IMAGEN, imagen[0], imagen[1])

    return DESCONOCIDA


def es_imagen_por_bytes(contenido: bytes) -> bool:
    """Atajo para "¿son estos bytes una imagen?"."""
    return detectar(contenido).es_imagen


def mime_de_extension(nombre: str) -> Optional[str]:
    """MIME que Discord deduce del nombre del archivo, o None si no la conoce.

    Se usa solo para comparar con `Deteccion.mime_esperado` y avisar de discrepancias.
    """
    import os

    extension = os.path.splitext(nombre or "")[1].lower().lstrip(".")
    if not extension:
        return None
    return _MIME_IMAGEN.get(extension) or _MIME_DOCUMENTO.get(extension) or _MIME_EJECUTABLE.get(extension)


def hay_mismatch_mime(deteccion: Deteccion, mime_declarado: Optional[str]) -> Optional[str]:
    """Devuelve el MIME declarado si contradice al real, o None si concuerdan.

    Solo compara cuando se sabe el formato real y hay algo declarado. Sin datos
    suficientes no se inventa una discrepancia.
    """
    if not mime_declarado or not deteccion.mime_esperado:
        return None
    if mime_declarado.lower() == deteccion.mime_esperado:
        return None
    # audio/video genéricos no aportan nada: `application/octet-stream` sí es señal.
    if mime_declarado.lower() in ("application/octet-stream", "binary/octet-stream"):
        return mime_declarado
    return mime_declarado