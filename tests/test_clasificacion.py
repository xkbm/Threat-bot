"""Detección por magic bytes.

El caso que motiva el módulo: `malware.png` con cabecera PE. Discord lo sirve como
`image/png`, la clasificación por extensión lo llama imagen y el malware nunca llega a
VirusTotal.
"""

import pytest

from core import filetypes as F
from core.filetypes import TipoContenido
from core.utils import verificar_nombre


class TestImagenes:
    @pytest.mark.parametrize(
        "datos,formato",
        [
            (b"\xff\xd8\xff\xe0" + b"\x00" * 60, "jpeg"),
            (b"\x89PNG\r\n\x1a\n" + b"\x00" * 60, "png"),
            (b"GIF89a" + b"\x00" * 60, "gif"),
            (b"GIF87a" + b"\x00" * 60, "gif"),
            (b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 40, "webp"),
            (b"BM" + b"\x00" * 60, "bmp"),
            (b"\x00\x00\x01\x00" + b"\x00" * 60, "ico"),
            (b"\x49\x49\x2a\x00" + b"\x00" * 60, "tiff"),
            (b"\x00\x00\x00\x18ftypheic" + b"\x00" * 40, "heic"),
            (b"\x00\x00\x00\x18ftypavif" + b"\x00" * 40, "avif"),
        ],
    )
    def test_reconoce_formatos_de_imagen(self, datos, formato):
        deteccion = F.detectar(datos)
        assert deteccion.tipo is TipoContenido.IMAGEN
        assert deteccion.formato == formato
        assert deteccion.es_imagen

    def test_reconoce_svg_con_declaracion_xml(self):
        datos = b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"></svg>'
        assert F.detectar(datos).formato == "svg"

    def test_svg_sin_xml_previo_tambien(self):
        assert F.detectar(b'<svg viewBox="0 0 1 1"></svg>').formato == "svg"


class TestElBugDeMalwarePng:
    def test_png_con_cabecera_pe_es_ejecutable(self):
        """El caso del que sale todo el módulo: extensión .png, bytes de ejecutable."""
        datos = b"MZ\x90\x00\x03" + b"\x00" * 200
        deteccion = F.detectar(datos)
        assert deteccion.tipo is TipoContenido.EJECUTABLE
        assert not deteccion.es_imagen

    def test_extension_png_por_defecto_ios_y_bytes_pe(self):
        """Lo que hacía Discord: content_type image/png y contenido malicioso."""
        # `es_imagen` (por extensión) dice que sí; los bytes dicen que no.
        import os

        from core.utils import es_imagen

        class AdjuntoFalso:
            filename = "malware.png"
            content_type = "image/png"

        # La pista por extensión sigue diciendo "imagen": por eso no puede decidir.
        extension_dice_imagen = F.mime_de_extension(AdjuntoFalso.filename) == "image/png"
        # Pero los bytes mandan.
        assert extension_dice_imagen
        assert F.detectar(b"MZ\x90\x00").tipo is TipoContenido.EJECUTABLE
        assert os.path.exists("core/filetypes.py")

    def test_pe_tiene_prioridad_sobre_ole_ambos_documentos_visibles(self):
        assert F.detectar(b"MZ\x00\x00").formato == "pe"
        assert F.detectar(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 40).formato == "ole"


class TestEjecutables:
    @pytest.mark.parametrize(
        "datos,formato",
        [
            (b"MZ\x90\x00", "pe"),
            (b"\x7fELF\x02\x01\x01", "elf"),
            (b"\xcf\xfa\xed\xfe\x07\x00", "macho"),
            (b"#!/bin/bash\necho hola\n", "script"),
            (b"#!/usr/bin/env python3\n", "script"),
        ],
    )
    def test_reconoce_ejecutables(self, datos, formato):
        deteccion = F.detectar(datos)
        assert deteccion.tipo is TipoContenido.EJECUTABLE
        assert deteccion.formato == formato


class TestDocumentos:
    @pytest.mark.parametrize(
        "datos,formato",
        [
            (b"%PDF-1.7\n", "pdf"),
            (b"PK\x03\x04" + b"\x00" * 40, "zip"),
            (b"Rar!\x1a\x07", "rar"),
            (b"7z\xbc\xaf\x27\x1c", "sevenzip"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
        ],
    )
    def test_reconoce_documentos(self, datos, formato):
        deteccion = F.detectar(datos)
        assert deteccion.tipo is TipoContenido.DOCUMENTO
        assert deteccion.formato == formato

    def test_zip_con_content_types_es_ooxml(self):
        datos = b"PK\x03\x04" + b"[Content_Types].xml" + b"\x00" * 40
        assert F.detectar(datos).formato == "ooxml"


class TestDesconocido:
    @pytest.mark.parametrize("datos", [b"", b"hola mundo", b"\x01\x02\x03\x04\x05", b"{}"])
    def test_bytes_sin_firma_no_se_inventan_tipo(self, datos):
        """Ante la duda, desconocido: es lo que lleva el archivo a VirusTotal."""
        assert F.detectar(datos).tipo is TipoContenido.DESCONOCIDO
        assert not F.detectar(datos).es_imagen


class TestMismatchMime:
    def test_png_que_sirve_ejecutable_se_marca(self):
        deteccion = F.detectar(b"MZ\x90\x00" + b"\x00" * 60)
        assert F.hay_mismatch_mime(deteccion, "image/png") == "image/png"

    def test_png_que_sirve_png_no_se_marca(self):
        deteccion = F.detectar(b"\x89PNG\r\n\x1a\n")
        assert F.hay_mismatch_mime(deteccion, "image/png") is None

    def test_sin_mime_declarado_no_hay_mismatch(self):
        deteccion = F.detectar(b"MZ\x90\x00")
        assert F.hay_mismatch_mime(deteccion, None) is None

    def test_formato_desconocido_no_genera_mismatch(self):
        """Sin datos suficientes no se inventa una discrepancia."""
        assert F.hay_mismatch_mime(F.detectar(b"hola"), "image/png") is None

    def test_octet_stream_se_marca(self):
        deteccion = F.detectar(b"\x89PNG\r\n\x1a\n")
        assert F.hay_mismatch_mime(deteccion, "application/octet-stream") is not None

    def test_pdf_servido_como_png_se_marca(self):
        deteccion = F.detectar(b"%PDF-1.7")
        assert F.hay_mismatch_mime(deteccion, "image/png") == "image/png"


class TestSoloLeeCabecera:
    def test_no_necesita_el_archivo_entero(self):
        """Solo mira los primeros 4KB: un archivo de 32MB se clasifica igual de rápido."""
        datos = b"\x89PNG\r\n\x1a\n" + b"\x00" * (5 * 1024 * 1024)
        assert F.detectar(datos).tipo is TipoContenido.IMAGEN

    def test_firma_despues_del_primer_kb_no_ve(self):
        datos = b"\x00" * 4096 + b"\x89PNG\r\n\x1a\n"
        assert F.detectar(datos).tipo is TipoContenido.DESCONOCIDO


class TestVerificarNombreCompartida:
    """`_procesar_archivo` e `_procesar_imagen` deben sacar las mismas señales.

    Antes estas comprobaciones vivían dentro del handler de archivos, así que una
    imagen nunca las obtenía: un `foto.exe.png` se colaba sin aviso.
    """

    def test_extension_que_miente_sobre_el_tipo_declarado(self):
        """`.png` pero Discord sirve `text/html`: el scam de la página falsa."""
        d, wm = verificar_nombre("foto.png", "text/html")
        assert d is False
        assert "text/html" in wm

    def test_png_coherente_no_avisa(self):
        d, wm = verificar_nombre("foto.png", "image/png")
        assert (d, wm) == (False, "")

    def test_bytes_que_contradicen_nombre_y_tipo(self):
        """Nombre y cabecera coinciden en mentir; solo los bytes lo delatan."""
        det = F.detectar(b"MZ\x90\x00" + b"\x00" * 60)
        _, wm = verificar_nombre("malware.png", "image/png", det)
        assert wm != ""
        assert "png" in wm.lower() or "ejecutable" in wm.lower() or "microsoft" in wm.lower()

    def test_bytes_correctos_no_avisa_aunque_haya_deteccion(self):
        det = F.detectar(b"\x89PNG\r\n\x1a\n")
        assert verificar_nombre("foto.png", "image/png", det) == (False, "")

    def test_doble_extension_se_detecta_todavia(self):
        d, _ = verificar_nombre("informe.pdf.exe", "application/octet-stream")
        assert d is True

    def test_sin_content_type_no_se_inventa_aviso(self):
        """Sin cabecera no hay comparación posible."""
        assert verificar_nombre("foto.png", None) == (False, "")

    def test_tipo_repetido_en_web_legacy_arma_no_va(self):
        """Un navegador que manda el MIME dos veces no debe generar ruido."""
        assert verificar_nombre("foto.png", "image/png; charset=x") == (False, "")

    def test_misma_senal_para_imagen_que_para_archivo(self):
        """La función es la misma, así que el resultado tiene que ser el mismo."""
        det = F.detectar(b"<html>ola</html>")
        assert verificar_nombre("foto.png", "text/html", det) == verificar_nombre("foto.png", "text/html", det)

    def test_no_depende_del_tipo_de_anexo(self):
        """Nada de esto mira si el adjunto es imagen o no: eso lo decide el enrutado."""
        _, wm = verificar_nombre("captura.png", "text/html")
        assert wm != ""

    @pytest.mark.parametrize(
        "nombre,content_type",
        [
            # El código antiguo comprobaba .jpg y .jpeg explícitamente. Sin el alias
            # "jpg" en el mapa de MIMEs, `foto.jpg` se saltaba la comprobación entera.
            ("foto.jpg", "text/html"),
            ("foto.jpeg", "text/html"),
            ("foto.jpg", "application/octet-stream"),
            # Y las demás que tampoco deben colarse.
            ("foto.bmp", "image/png"),
            ("foto.webp", "image/png"),
            ("foto.gif", "image/png"),
            ("doc.pdf", "text/html"),
        ],
    )
    def test_toda_extension_conocida_se_comprueba(self, nombre, content_type):
        """Cada extensión con MIME conocido tiene que poder dar aviso.

        Regresión: `mime_de_extension` devolvía None para `.jpg` porque el mapa solo
        tenía "jpeg", y con None la comparación se saltaba sin avisar.
        """
        _, wm = verificar_nombre(nombre, content_type)
        assert wm != "", f"{nombre} con {content_type} debería dar aviso"

    @pytest.mark.parametrize(
        "nombre,content_type",
        [
            ("foto.jpg", "image/jpeg"),
            ("foto.jpeg", "image/jpeg"),
            ("foto.png", "image/png"),
            ("foto.gif", "image/gif"),
            ("foto.webp", "image/webp"),
            ("foto.bmp", "image/bmp"),
            ("captura.heic", "image/heic"),
            ("doc.pdf", "application/pdf"),
            ("ejecutable.exe", "application/x-msdownload"),
        ],
    )
    def test_coherentes_no_dan_aviso(self, nombre, content_type):
        assert verificar_nombre(nombre, content_type) == (False, "")