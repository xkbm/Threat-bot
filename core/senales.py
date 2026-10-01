"""Recogida de todo lo detectado en un mensaje, en un solo sitio.

Antes, `procesar_analisis` arrastraba catorce variables locales sueltas
(`has_threat`, `has_suspicious`, `img_results`, `omitidos`...) que se pasaban a mano
entre el análisis, el embed y la reacción final. Añadir un caso obligaba a tocar las
tres cosas y era fácil que una se quedara atrás: por eso una URL en whitelist se
marcaba antes de conocer el resultado y nunca se quitaba la reacción.

Aquí se acumulan las señales y se derivan las banderas agregadas, una sola vez.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.veredictos import Veredicto


@dataclass
class Elemento:
    """Un objeto evaluado: una URL, un adjunto, una URL de imagen.

    `veredicto` es el resultado de una dimensión: reputación (VirusTotal) o contenido
    (SightEngine). Un mismo adjunto puede tener ambas: una imagen puede ser limpia para
    SightEngine y aun así tener un hash marcado por antivirus.
    """

    nombre: str
    tipo: str                      # 'url' | 'file' | 'image' | 'image_url' | 'ip' | 'hash'
    veredicto: Veredicto = Veredicto.SEGURO
    mal: int = 0
    vt_link: Optional[str] = None
    elemento_id: Optional[str] = None
    # URL a la que llevaba el acortador, si lo hubo. Antes vivía en `UrlResult` y el
    # embed la tenía que leer de las tuplas; aquí viaja con el elemento.
    redireccion: Optional[str] = None
    # Contenido (SightEngine). Antes se perdía al cruzar funciones.
    detalle_contenido: str = ""
    modelos: Dict[str, Any] = field(default_factory=dict)
    # Señales de nombre, no de contenido.
    aviso_mime: Optional[str] = None
    doble_extension: bool = False

    @property
    def hay_senal_de_nombre(self) -> bool:
        """El objeto no es lo que dice ser, aunque ningún engine lo confirme."""
        return bool(self.aviso_mime) or self.doble_extension


@dataclass
class Senales:
    """Todo lo que se sabe de un mensaje tras escanearlo."""

    elementos: List[Elemento] = field(default_factory=list)

    # Banderas de lo que pasó en el mensaje, no en un elemento concreto.
    cooldown: bool = False        # antispam: no se pudo analizar nada
    omitidos: int = 0             # adjuntos que no cabían en el límite
    whitelist_omitidos: int = 0   # enlaces ignorados por estar en whitelist
    # Límite aplicado a los adjuntos, para que el embed diga el número real y no el
    # del fallback.
    max_adjuntos: int = 5

    # Scores crudos de SightEngine. Se guardan para poder explicar el por qué de un
    # veredicto sin volver a llamar a la API.
    datos_nsfw: Dict[str, Any] = field(default_factory=dict)

    def anadir(self, elemento: Elemento) -> Elemento:
        self.elementos.append(elemento)
        return elemento

    # --- Agregados -------------------------------------------------------
    # Son properties, no campos: no pueden desincronizarse de los elementos.

    @property
    def veredictos(self) -> List[Veredicto]:
        return [e.veredicto for e in self.elementos]

    @property
    def malicious(self) -> bool:
        return any(e.veredicto is Veredicto.MALICIOSO for e in self.elementos)

    @property
    def nsfw(self) -> bool:
        return any(e.veredicto is Veredicto.NSFW for e in self.elementos)

    @property
    def restringido(self) -> bool:
        return any(e.veredicto is Veredicto.RESTRINGIDO for e in self.elementos)

    @property
    def phishing(self) -> bool:
        return any(e.veredicto is Veredicto.PHISHING for e in self.elementos)

    @property
    def suspicious(self) -> bool:
        return any(e.veredicto is Veredicto.SOSPECHOSO for e in self.elementos)

    @property
    def error(self) -> bool:
        """Algo no se pudo comprobar.

        Deliberadamente separado de `malicious`: un análisis fallido y un análisis
        limpio son estados distintos, y confundirlos hacía que lo no verificado se
        reportara como seguro.
        """
        return any(e.veredicto is Veredicto.ERROR for e in self.elementos)

    @property
    def hay_amenaza(self) -> bool:
        return self.malicious or self.nsfw

    @property
    def hay_hallazgo(self) -> bool:
        return any(e.veredicto.es_hallazgo for e in self.elementos)

    @property
    def doble_ext(self) -> bool:
        return any(e.doble_extension for e in self.elementos)

    @property
    def mime_mismatch(self) -> bool:
        return any(e.aviso_mime for e in self.elementos)

    @property
    def hay_senal_de_nombre(self) -> bool:
        return self.doble_ext or self.mime_mismatch

    @property
    def completo(self) -> bool:
        return not self.error and not self.cooldown and not self.omitidos

    @property
    def hay_algo_que_mostrar(self) -> bool:
        return bool(self.elementos) or self.cooldown or self.omitidos or self.whitelist_omitidos > 0


def desde_tuplas(
    url_results: Optional[List[Tuple]] = None,
    img_url_results: Optional[List[Tuple]] = None,
    img_results: Optional[List[Tuple]] = None,
    arch_results: Optional[List[Tuple]] = None,
) -> Senales:
    """Construye unas `Senales` desde las tuplas que devuelven los analizadores.

    Es un puente: mientras los analizadores no devuelvan `Elemento`, esta función
    traduce. Cuando todos lo hagan, se borra y ya no hace falta conocer las tuplas.
    """
    senales = Senales()

    for r in url_results or []:
        nombre, tipo, mal, vt_link, eid, _ya_logueado, redireccion = (list(r) + [None] * 7)[:7]
        senales.anadir(Elemento(
            nombre=nombre, tipo="url", veredicto=Veredicto.desde(tipo), mal=mal or 0,
            vt_link=vt_link, elemento_id=eid, redireccion=redireccion,
        ))

    for r in img_url_results or []:
        nombre, tipo, detalle, eid = (list(r) + ["", "", None])[:4]
        senales.anadir(Elemento(
            nombre=nombre, tipo="image_url", veredicto=Veredicto.desde(tipo),
            detalle_contenido=detalle or "", elemento_id=eid,
        ))

    for r in img_results or []:
        nombre, tipo, modelos, content_hash = (list(r) + [None, {}, None])[:4]
        modelos = modelos or {}
        senales.anadir(Elemento(
            nombre=nombre, tipo="image", veredicto=Veredicto.desde(tipo),
            modelos=modelos,
            # `evaluar_contenido` ya deja el texto con los umbrales aplicados. Se copia
            # aquí para que el embed no tenga que recalcularlo: antes leía
            # `models['nudity']`, clave que ya no existe, y por eso nunca nombraba qué
            # se había detectado.
            detalle_contenido=str(modelos.get("detalle") or ""),
            elemento_id=f"nsfw:{content_hash}" if content_hash else None,
            aviso_mime=modelos.get("aviso_mime") or None,
            doble_extension=bool(modelos.get("doble_extension")),
        ))

    for r in arch_results or []:
        nombre, tipo, mal, _fh, aviso_mime, doble_ext = (list(r) + [None, 0, None, "", False])[:6]
        senales.anadir(Elemento(
            nombre=nombre, tipo="file", veredicto=Veredicto.desde(tipo), mal=mal or 0,
            aviso_mime=aviso_mime or None, doble_extension=bool(doble_ext),
        ))

    return senales