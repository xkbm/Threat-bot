"""Sistema unificado de embeds: contrato de estilo, paleta y render-on-read."""

import os
import re
import asyncio

import aiohttp
import discord
import pytest

from core.config import (
    COLOR_NEUTRAL, COLOR_SEGURO, COLOR_MALICIOSO, COLOR_SOSPECHOSO, COLOR_ERROR, COLOR_NSFW, COLOR_TOPGG,
    EMOJI_SHIELD, EMOJI_LINK, EMOJI_GUARDIAN, EMOJI_FINGERPRINT,
)
from ui import embed as emb
from ui.embed import MARCA, TITULOS, TITULOS_PROHIBIDOS, ACRONIMOS

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATOS_URL = {"valor": "https://ejemplo.com/ruta", "vt_link": "https://vt/gui/x", "top_text": "Kaspersky, ESET"}
DATOS_HASH = {"valor": "a" * 64, "vt_link": "https://vt/gui/h", "top_text": "Kaspersky"}
DATOS_IP = {"valor": "8.8.8.8", "vt_link": "https://vt/gui/i", "top_text": None}
DATOS_FILE = {"valor": "documento.pdf", "vt_link": None, "top_text": None}

import core.config as _cfg
_EMOJI = [v for v in vars(_cfg).values() if isinstance(v, str) and v.startswith("<:")]


def texto_pie(embed) -> str:
    return (embed.footer.text or "") if embed.footer else ""


def nombres_campos(embed):
    """Los nombres de campo llevan el emoji del bot como prefijo."""
    return [f.name for f in embed.fields]


def etiqueta(nombre: str) -> str:
    """Quita el prefijo de emoji a un nombre de campo."""
    for e in _EMOJI:
        if nombre.startswith(e):
            return nombre[len(e):].strip()
    return nombre


class TestPieDeMarca:
    """El pie es lo que hace identificable al bot. Debe estar en todos."""

    @pytest.mark.parametrize("construir", [
        lambda: emb.resultado("url", DATOS_URL, 3),
        lambda: emb.resultado("url", DATOS_URL, 0),
        lambda: emb.resultado("hash", DATOS_HASH, 1),
        lambda: emb.resultado("ip", DATOS_IP, 0),
        lambda: emb.resultado("file", DATOS_FILE, 7),
        lambda: emb.error_analisis("algo falló"),
        lambda: emb.error_conexion("sin red"),
        lambda: emb.error_cuota(65),
        lambda: emb.aviso("título", "desc"),
        lambda: emb.topgg("deja una reseña"),
    ])
    def test_siempre_presente(self, construir):
        pie = texto_pie(construir())
        assert pie, "el embed no tiene pie"
        assert pie.startswith(MARCA), f"el pie no empieza por la marca: {pie!r}"

    @pytest.mark.parametrize("construir", [
        lambda: emb.resultado("url", DATOS_URL, 3),
        lambda: emb.error_analisis("algo falló"),
        lambda: emb.aviso("título", "desc"),
    ])
    def test_formato_con_fecha_utc(self, construir):
        pie = texto_pie(construir())
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", pie), pie

    def test_contexto_se_incluye(self):
        pie = texto_pie(emb.aviso("Configuración", "x"))
        assert "Configuración" in pie

    def test_contexto_se_trunca(self):
        largo = texto_pie(emb.aviso("x" * 300, "d"))
        assert "…" in largo
        assert len(largo) < len("Threat · " + "x" * 300 + " · fecha")

    def test_avatar_si_se_pasa(self):
        e = emb.aviso("t", "d", avatar_url="https://cdn/x.png")
        assert e.thumbnail.url == "https://cdn/x.png"

    def test_sin_avatar_no_thumbnail(self):
        assert emb.aviso("t", "d").thumbnail.url is None


class TestPrefijoDeMarca:
    @pytest.mark.parametrize("construir", [
        lambda: emb.resultado("url", DATOS_URL, 3),
        lambda: emb.error_analisis("fallo"),
        lambda: emb.aviso("título", "desc"),
    ])
    def test_escudo_en_el_titulo(self, construir):
        assert construir().title.startswith(EMOJI_SHIELD), construir().title


class TestPaletaPorSeveridad:
    def test_malicioso_es_ambar(self):
        assert emb.resultado("url", DATOS_URL, 3).color == discord.Color(COLOR_MALICIOSO)

    def test_seguro_es_verde(self):
        assert emb.resultado("url", DATOS_URL, 0).color == discord.Color(COLOR_SEGURO)

    @pytest.mark.parametrize("tipo", ["url", "hash", "ip", "file"])
    def test_malicioso_ambar_en_todos_los_tipos(self, tipo):
        datos = {"url": DATOS_URL, "hash": DATOS_HASH, "ip": DATOS_IP, "file": DATOS_FILE}[tipo]
        assert emb.resultado(tipo, datos, 4).color == discord.Color(COLOR_MALICIOSO)
        assert emb.resultado(tipo, datos, 0).color == discord.Color(COLOR_SEGURO)

    @pytest.mark.parametrize("tipo", ["url", "hash", "ip", "file"])
    def test_sospechoso_en_todos_los_tipos(self, tipo):
        """El color de severidad tiene que distinguir sospechoso de malicioso: es la
        barra lateral lo primero que se lee, y es la diferencia entre "borra esto" y
        "mira esto"."""
        datos = {"url": DATOS_URL, "hash": DATOS_HASH, "ip": DATOS_IP, "file": DATOS_FILE}[tipo]
        e = emb.resultado(tipo, {**datos, "veredicto": "sospechoso", "susp": 2}, 0)
        assert e.color == discord.Color(COLOR_SOSPECHOSO)
        assert e.color != discord.Color(COLOR_MALICIOSO)

    @pytest.mark.parametrize("construir", [
        lambda: emb.error_analisis("x"),
        lambda: emb.error_conexion("x"),
        lambda: emb.error_cuota(),
    ])
    def test_errores_en_rojo(self, construir):
        assert construir().color == discord.Color(COLOR_ERROR)

    def test_aviso_neutro_es_gris(self):
        assert emb.aviso("t", "d").color == discord.Color(COLOR_NEUTRAL)

    def test_nsfw_rojo(self):
        u = type("U", (), {"mention": "<@1>", "id": 1})()
        e = emb.nsfw("Imagen", "http://x.png", "Desnudez 90%", u)
        assert e.color == discord.Color(COLOR_NSFW)

    def test_amenaza_roja(self):
        u = type("U", (), {"mention": "<@1>", "id": 1})()
        assert emb.amenaza("URL", "http://x", "3 detecciones", u).color == discord.Color(COLOR_ERROR)

    def test_topgg_rosa(self):
        assert emb.topgg("reseña").color == discord.Color(COLOR_TOPGG)

    def test_severidad_abierta(self):
        e = emb.aviso("t", "d", color=emb.COLOR_MALICIOSO)
        assert e.color == discord.Color(COLOR_MALICIOSO)


class TestTitulos:
    @pytest.mark.parametrize("tipo,datos,mal,esperado", [
        ("url", DATOS_URL, 3, TITULOS["url_maliciosa"]),
        ("url", DATOS_URL, 0, TITULOS["url_segura"]),
        ("hash", DATOS_HASH, 1, TITULOS["hash_malicioso"]),
        ("hash", DATOS_HASH, 0, TITULOS["hash_seguro"]),
        ("ip", DATOS_IP, 2, TITULOS["ip_maliciosa"]),
        ("ip", DATOS_IP, 0, TITULOS["ip_segura"]),
        ("file", DATOS_FILE, 5, TITULOS["archivo_malicioso"]),
        ("file", DATOS_FILE, 0, TITULOS["archivo_seguro"]),
        # El veredicto viaja en `datos`, no se deduce de `mal`: con 0 detecciones
        # maliciosas y varias sospechosa el elemento no está limpio.
        ("url", {**DATOS_URL, "veredicto": "sospechoso", "susp": 3}, 0, TITULOS["url_sospechosa"]),
        ("hash", {**DATOS_HASH, "veredicto": "sospechoso", "susp": 1}, 0, TITULOS["hash_sospechoso"]),
        ("ip", {**DATOS_IP, "veredicto": "sospechoso", "susp": 2}, 0, TITULOS["ip_sospechosa"]),
        ("file", {**DATOS_FILE, "veredicto": "sospechoso", "susp": 4}, 0, TITULOS["archivo_sospechoso"]),
    ])
    def test_titulo_correcto(self, tipo, datos, mal, esperado):
        assert emb.resultado(tipo, datos, mal).title == f"{EMOJI_SHIELD} {esperado}"

    def test_vocabulario_de_errores_cerrado(self):
        assert emb.error_analisis("x").title.endswith(TITULOS["error_analisis"])
        assert emb.error_conexion("x").title.endswith(TITULOS["error_conexion"])
        assert emb.error_cuota().title.endswith(TITULOS["error_cuota"])

    def test_los_tres_errores_llevan_el_mismo_icono(self):
        """La severidad la comunican el color rojo y el texto; el icono del título
        se reserva para la marca, así que los tres errores llevan el escudo."""
        titulos = {
            emb.error_analisis("x").title,
            emb.error_conexion("x").title,
            emb.error_cuota().title,
        }
        prefijos = {t.split(" ", 1)[0] for t in titulos}
        assert prefijos == {EMOJI_SHIELD}, f"iconos inconsistentes: {titulos}"

    def test_sentence_case_en_titulos(self):
        """Sentence case: se capitaliza la primera palabra y los ACRÓNIMOS.
        El resto de palabras van en minúscula, así que "Hash malicioso detectado"
        es correcto y "Hash Malicioso Detectado" no."""
        for clave, texto in TITULOS.items():
            assert texto[0].isupper(), f"{clave}: {texto!r} no capitaliza la primera palabra"
            for palabra in texto.split()[1:]:
                limpia = palabra.strip(".:,()")
                if not limpia or limpia in ACRONIMOS:
                    continue
                assert not limpia.isupper(), f"{clave}: {limpia!r} en mayúsculas sin ser acrónimo"
                assert not (limpia[0].isupper() and limpia.lower() not in ("de", "y", "al")), (
                    f"{clave}: Title Case en {limpia!r} ({texto!r})"
                )

    def test_titulos_unicos(self):
        assert len(set(TITULOS.values())) == len(TITULOS)


class TestGuardiaDeTitulosViejos:
    """Si un título viejo reaparece en el código, el rediseño se ha deshecho."""

    FICHEROS = ["api", "ui", "cogs", "core", "bot.py"]

    def _fuente(self):
        for base in self.FICHEROS:
            ruta = os.path.join(RAIZ, base)
            rutas = [ruta] if os.path.isfile(ruta) else [
                os.path.join(ruta, f) for f in sorted(os.listdir(ruta)) if f.endswith(".py")
            ]
            for r in rutas:
                if r.endswith("embed.py"):
                    continue
                with open(r, encoding="utf-8") as fh:
                    yield r, fh.read()

    @pytest.mark.parametrize("prohibido", TITULOS_PROHIBIDOS)
    def test_no_reaparece(self, prohibido):
        for ruta, texto in self._fuente():
            assert prohibido not in texto, f"'{prohibido}' reaparece en {ruta}"

    def test_ningun_embed_construido_a_mano(self):
        """ui/embed.py debe ser el único que llama a discord.Embed()."""
        for ruta, texto in self._fuente():
            assert "discord.Embed(" not in texto, f"discord.Embed() fuera de ui/embed.py en {ruta}"

    def test_ningun_color_literal_de_discord(self):
        for ruta, texto in self._fuente():
            for patron in ("Color.gold(", "Color.blue(", "Color.dark_blue(",
                           "Color.orange(", "Color.green(", "Color.red("):
                assert patron not in texto, f"{patron} en {ruta}: usar los tokens de core.config"

    def test_sin_el_truco_de_espacio_cero(self):
        for ruta, texto in self._fuente():
            assert "\\u200b" not in texto, f"el truco \\u200b sigue en {ruta}"

    def test_sin_emoji_unicode(self):
        """Solo emojis personalizados. Un emoji unicode se vería plano y distinto
        al resto del set, que es justo lo que rompe la identidad visual."""
        # Rangos de emoji unicode y símbolo. Un rango amplio a propósito: mejor un
        # falso positivo que dejar pasar uno, como el U+23F0 del cronómetro que
        # había en reboot.py.
        patron = re.compile(
            "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U00002B00-\U00002BFF"
            "\U00002300-\U000023FF\U00002190-\U000021FF\U0000FE0F]"
        )
        for ruta, texto in self._fuente():
            if ruta.endswith("ui/embed.py"):
                continue
            encontrados = set(patron.findall(texto))
            # La flecha "→" se usa como separador en los log.debug(); no es un emoji.
            encontrados.discard("→")
            assert not encontrados, f"emoji unicode en {ruta}: {encontrados}"

    def test_todos_los_emoji_de_config_son_personalizados(self):
        import core.config as cfg
        emojis = {k: v for k, v in vars(cfg).items() if k.startswith("EMOJI_")}
        assert emojis, "no se encontraron constantes EMOJI_"
        for nombre, valor in emojis.items():
            assert valor.startswith("<:") and valor.endswith(">"), f"{nombre} no es personalizado: {valor!r}"
            assert ":" in valor[2:-1], f"{nombre} mal formado: {valor!r}"


class TestServerHostname:
    """Conectar por IP rompe el TLS salvo que se diga a aiohttp cuál es el
    hostname real: sin esto, cualquier CDN (media.discordapp.net) falla con
    CERTIFICATE_VERIFY_FAILED y el embed muestra un traceback crudo."""

    def test_las_tres_rutas_pasan_server_hostname(self):
        with open(os.path.join(RAIZ, "core/utils.py"), encoding="utf-8") as fh:
            fuente = fh.read()
        # url_es_imagen, expandir_url y descargar_url_segura
        for fn in ("url_es_imagen", "expandir_url", "descargar_url_segura"):
            bloque = fuente.split(f"async def {fn}")[1].split("\nasync def")[0].split("\ndef ")[0]
            assert "server_hostname=hostname" in bloque, f"{fn} conecta por IP sin server_hostname"

    def test_aiohttp_esta_por_encima_de_la_version_con_el_parche(self):
        """CVE-2026-54275: hasta 3.14.0 el server_hostname no entraba en la clave del
        pool, así que una conexión reutilizada se saltaba la comprobación SNI."""
        with open(os.path.join(RAIZ, "requirements.txt"), encoding="utf-8") as fh:
            requisitos = fh.read()
        match = re.search(r"^aiohttp==(\d+)\.(\d+)\.(\d+)", requisitos, re.M)
        assert match, "aiohttp sin pinchar en requirements.txt"
        mayor, menor, parche = (int(g) for g in match.groups())
        assert (mayor, menor, parche) >= (3, 14, 1), f"aiohttp {match.group(0)} es vulnerable a CVE-2026-54275"

    def test_no_se_filtra_str_de_excepcion_al_usuario(self):
        with open(os.path.join(RAIZ, "core/utils.py"), encoding="utf-8") as fh:
            fuente = fh.read()
        bloque = fuente.split("async def descargar_url_segura")[1].split("\nasync def")[0]
        assert "return None, str(e)" not in bloque, "descargar_url_segura sigue filtrando str(e)"
        assert "_motivo_legible" in bloque

    def test_motivo_legible_nunca_devuelve_el_traceback(self):
        from core.utils import _motivo_legible

        # Se usan excepciones propias en vez de las de aiohttp: sus constructores
        # exigen objetos de conexión válidos y aquí solo importa el mapeo por tipo.
        class _TooManyRedirects(aiohttp.TooManyRedirects):
            def __init__(self):
                Exception.__init__(self, "too many redirects")

        class _SSLCertVerificationError(Exception):
            pass

        class _SSLSubprocessError(Exception):
            pass

        class _ClientConnectorDNSError(Exception):
            pass

        class _Explosivo(Exception):
            """Su __str__ revienta, como el de ClientConnectorError de aiohttp
            cuando el objeto no tiene _conn_key."""

            def __str__(self):
                raise AttributeError("no tiene _conn_key")

        casos = [
            asyncio.TimeoutError(),
            _TooManyRedirects(),
            _SSLCertVerificationError("certificate verify failed: IP address mismatch"),
            _SSLSubprocessError("bad handshake"),
            _ClientConnectorDNSError("getaddrinfo failed"),
            _Explosivo(),
            OSError("connection reset by peer"),
            ValueError("raro"),
        ]
        for exc in casos:
            motivo = _motivo_legible(exc)
            assert isinstance(motivo, str) and motivo, type(exc).__name__
            assert "Traceback" not in motivo, motivo
            assert "_ssl.c" not in motivo, motivo
            assert len(motivo) < 80, motivo


class TestElLogSiempreDiceQuien:
    """Ningún log de amenaza puede salir sin el autor.

    El log del canal es donde un moderador decide a quién banea. `emb.amenaza` ya lo
    llevaba, pero `emb.nsfw` no lo recibía: el embed salía con el elemento y el motivo
    y nada más, mientras los botones de Ban/Kick sí apuntaban al autor correcto. Es decir,
    un moderador podía banear a alguien que el propio log no nombraba, y sin el ID no
    había forma de comprobar si eran la misma persona.
    """

    @staticmethod
    def _usuario():
        return type("U", (), {"mention": "<@42>", "id": 42})()

    def test_nsfw_lleva_usuario(self):
        e = emb.nsfw("Imagen NSFW", "foto.png", "Desnudez 90%", self._usuario())
        assert any("Usuario" in f.name for f in e.fields), [f.name for f in e.fields]

    def test_nsfw_lleva_el_id_explicito(self):
        e = emb.nsfw("Imagen NSFW", "foto.png", "Desnudez 90%", self._usuario())
        assert any(f.name == "ID" and "42" in f.value for f in e.fields)

    def test_amenaza_sigue_llevando_usuario(self):
        e = emb.amenaza("URL", "http://x", "3 detecciones", self._usuario())
        assert any("Usuario" in f.name for f in e.fields)

    def test_ambos_formatean_el_usuario_igual(self):
        """Un moderador no debería aprender dos formatos para leer quién publicó qué.

        Los nombres del resto de campos sí difieren, y a propósito: un threat de URL y
        una imagen no tienen la misma información. Lo que tiene que ser igual es cómo se
        identifica a la persona, que es lo que se lee en los dos.
        """
        u = self._usuario()
        n = emb.nsfw("Imagen NSFW", "foto.png", "d", u)
        a = emb.amenaza("URL", "http://x", "d", u)

        def _autor(e):
            return sorted(
                (etiqueta(f.name), f.value) for f in e.fields if "Usuario" in f.name or f.name == "ID"
            )

        assert _autor(n) == _autor(a), (_autor(n), _autor(a))
        assert _autor(n), "el embed de NSFW tiene que identificar al autor"

    def test_el_elemento_va_en_code_block(self):
        """Un nombre de archivo o una URL es texto de atacante: sin code block puede
        inyectar markdown y romper la maquetación del log."""
        e = emb.nsfw("Imagen NSFW", "`inyeccion`", "d", self._usuario())
        elemento = next(f for f in e.fields if "Elemento" in f.name)
        assert elemento.value.startswith("```") and elemento.value.endswith("```")


class TestElLogDiceLoQueRealmentePasa:
    """El texto del log tiene que salir del veredicto, no de que "no sea NSFW".

    El embed que sale en tu captura decía "**CONTENIDO RESTRINGIDO** resultó
    **malicioso**", con un botón de banear debajo. `emb.amenaza` escribía "resultó
    malicioso" en el texto y se usaba para TODO veredicto que no fuera NSFW, así que el
    contenido restringido —que el bot define como "avisa pero no borra"— salía como
    malware. Un moderador que se fiara del texto podía banear a alguien por una cerveza.

    Estos tests fijan que el texto siga al veredicto, incluido el color: el rojo de
    "requiere acción" no es el mismo aviso que un dislike por una foto de arma en un juego.
    """

    @staticmethod
    def _usuario():
        return type("U", (), {"mention": "<@42>", "id": 42})()

    def test_restringido_no_se_dice_malicioso(self):
        e = emb.amenaza("Contenido restringido", "image.png", "Alcohol 80%", self._usuario(),
                        veredicto="restringido")
        assert "malicioso" not in (e.description or "").lower(), e.description
        assert "restringido" in (e.description or "").lower(), e.description

    def test_malicioso_si_se_dice_malicioso(self):
        e = emb.amenaza("URL", "http://x", "3 detecciones", self._usuario(),
                        veredicto="malicioso")
        assert "malicioso" in (e.description or "").lower(), e.description

    def test_restringido_no_es_el_color_de_malware(self):
        """El rojo es "requiere acción". Una cerveza no es lo mismo que un malware."""
        r = emb.amenaza("Contenido restringido", "i.png", "Alcohol", self._usuario(),
                        veredicto="restringido")
        m = emb.amenaza("URL", "http://x", "3 detecciones", self._usuario(),
                        veredicto="malicioso")
        assert r.color != m.color, "un contenido restringido no puede verse como malware"

    def test_un_veredicto_desconocido_no_destroza_el_embed(self):
        """Si algún día llega un veredicto nuevo, sale como malware y no revienta."""
        e = emb.amenaza("X", "y", "z", self._usuario(), veredicto="inventado")
        assert e is not None and e.description

    def test_el_pie_no_sigue_diciendo_amenaza_a_todo(self):
        """El pie dice "Amenaza · Contenido restringido", que sí es un poco incoherente,
        pero cambiarlo rompería el contrato de títulos; lo que no puede pasar es que el
        cuerpo diga una cosa y el veredicto otra."""
        e = emb.amenaza("Contenido restringido", "i.png", "Alcohol", self._usuario(),
                        veredicto="restringido")
        assert "Amenaza" in (e.footer.text if e.footer else "")


class TestEnlaceAlMensaje:
    """El log de amenaza es un registro, y un registro sin el mensaje al que se refiere
    obliga a buscarlo a mano."""

    def test_el_enlace_lleva_a_guild_canal_y_mensaje(self):
        enlace = emb.enlace_mensaje(1, 10, 100)
        assert "https://discord.com/channels/1/10/100" in enlace

    def test_sin_mensaje_no_hay_enlace(self):
        """Mensaje borrado, o escaneo manual sin mensaje: nada de enlace roto."""
        assert emb.enlace_mensaje(1, 10, None) == ""
        assert emb.enlace_mensaje(None, 10, 100) == ""
        assert emb.enlace_mensaje(1, None, 100) == ""

    def test_el_embed_lo_incluye_cuando_se_puede(self):
        u = type("U", (), {"mention": "<@42>", "id": 42})()
        e = emb.amenaza("URL", "http://x", "d", u, mensaje=emb.enlace_mensaje(1, 10, 100))
        assert any("Origen" in f.name for f in e.fields), [f.name for f in e.fields]

    def test_el_embed_no_muestra_campo_vacio(self):
        """Sin mensaje no hay campo: un "Origen" vacío es ruido."""
        u = type("U", (), {"mention": "<@42>", "id": 42})()
        e = emb.amenaza("URL", "http://x", "d", u, mensaje="")
        assert not any("Origen" in f.name for f in e.fields), [f.name for f in e.fields]


class TestCampos:
    def test_vocabulario_cerrado_de_campos(self):
        permitidos = {"URL", "Hash", "IP", "Archivo", "Detectado por", "VirusTotal", "Detalle"}
        for e in (emb.resultado("url", DATOS_URL, 3), emb.resultado("hash", DATOS_HASH, 1),
                  emb.resultado("ip", DATOS_IP, 0), emb.resultado("file", DATOS_FILE, 0),
                  emb.error_analisis("x", detalle="d")):
            for n in nombres_campos(e):
                assert etiqueta(n) in permitidos, f"campo inesperado: {n!r}"

    def test_campos_valor_que_ya_ordena(self):
        e = emb.resultado("url", DATOS_URL, 3)
        assert [etiqueta(n) for n in nombres_campos(e)] == ["URL", "Detectado por", "VirusTotal"]
        # El elemento se identifica con el emoji de huella y el link con el de enlace.
        assert nombres_campos(e)[0].startswith(EMOJI_FINGERPRINT)
        assert nombres_campos(e)[2].startswith(EMOJI_LINK)

    def test_sin_detectado_por_si_no_hay_datos(self):
        assert "Detectado por" not in [etiqueta(n) for n in nombres_campos(emb.resultado("url", DATOS_IP, 3))]

    def test_sin_vt_link_no_hay_campo_vt(self):
        assert "VirusTotal" not in [etiqueta(n) for n in nombres_campos(emb.resultado("file", DATOS_FILE, 5))]

    def test_vt_link_solo_si_existe(self):
        etiquetas = [etiqueta(n) for n in nombres_campos(emb.resultado("url", DATOS_URL, 3))]
        assert "VirusTotal" in etiquetas

    def test_error_con_detalle(self):
        e = emb.error_analisis("desc", detalle="porque sí")
        assert "Detalle" in [etiqueta(n) for n in nombres_campos(e)]
        assert "porque sí" in e.fields[0].value

    def test_error_sin_detalle_no_crea_campo(self):
        assert "Detalle" not in [etiqueta(n) for n in nombres_campos(emb.error_analisis("desc"))]

    def test_amenaza_lleva_id_explicito(self):
        u = type("U", (), {"mention": "<@1>", "id": 12345})()
        e = emb.amenaza("URL", "http://x", "3 detecciones", u)
        assert "ID" in [etiqueta(n) for n in nombres_campos(e)]
        assert "12345" in next(f.value for f in e.fields if f.name == "ID")

    def test_amenaza_escapa_el_valor_en_code_block(self):
        """El valor viene de un mensaje de usuario: si no va en code block podría
        inyectar markdown y romper la maquetación del embed de moderación."""
        malicioso = "http://x\n**inyectado**"
        u = type("U", (), {"mention": "<@1>", "id": 1})()
        e = emb.amenaza("URL", malicioso, "d", u)
        campo = next(f for f in e.fields if f.name.endswith("Valor"))
        assert campo.value.startswith("```") and campo.value.endswith("```")


class TestRenderOnRead:
    def test_resultado_es_puro(self):
        """Mismos datos -> mismo embed. Es lo que hace seguro el render-on-read."""
        a = emb.resultado("url", DATOS_URL, 3)
        b = emb.resultado("url", DATOS_URL, 3)
        assert a.to_dict() == b.to_dict()

    def test_puro_entre_llamadas_con_otros_tipos_mezclados(self):
        emb.resultado("hash", DATOS_HASH, 1)
        emb.resultado("file", DATOS_FILE, 9)
        a = emb.resultado("url", DATOS_URL, 3)
        b = emb.resultado("url", DATOS_URL, 3)
        assert a.to_dict() == b.to_dict()

    def test_no_depende_del_estado_global(self):
        primero = emb.resultado("ip", DATOS_IP, 2).to_dict()
        emb.aviso("otro", "cosa", color=emb.COLOR_TOPGG)
        assert emb.resultado("ip", DATOS_IP, 2).to_dict() == primero

    def test_descripcion_consistente_entre_tipos(self):
        mal = emb.resultado("url", DATOS_URL, 3)
        ok = emb.resultado("url", DATOS_URL, 0)
        assert "3" in mal.description and "detecciones" in mal.description
        assert ok.description == "Sin detecciones"

    def test_serializable(self):
        """El embed tiene que poder ir a to_dict/from_dict: es lo que se guarda en caché."""
        e = emb.resultado("url", DATOS_URL, 3)
        hidratado = discord.Embed.from_dict(e.to_dict())
        assert hidratado.title == e.title
        assert hidratado.color == e.color
        assert [f.name for f in hidratado.fields] == [f.name for f in e.fields]


class TestBarra:
    def test_barra_rellena(self):
        assert emb.resultado_barra(100.0, 10, 10).startswith("█" * 10)

    def test_barra_vacia(self):
        assert "░" in emb.resultado_barra(0, 0, 10)

    def test_barra_texto(self):
        s = emb.resultado_barra(50, 5, 10)
        assert "50%" in s and "5/10" in s

    def test_barra_acota_por_encima_de_100(self):
        assert emb.resultado_barra(150, 15, 10).count("░") == 0


class TestElTituloDiceCuantas:
    """El número va en el título y en plural.

    El cambio se perdió dos veces en un resync de rama, así que hay un test que lo fija.
    «Amenaza detectada» a secas no dice si es una cosa o seis, y «1 detecciones» hace dudar
    de si el contador es real: en un panel de moderación eso se lee como un bug, no como
    un descuido de texto.
    """

    @staticmethod
    def _usuario():
        return type("U", (), {"mention": "<@42>", "id": 42})()

    def test_una_sola_deteccion_en_singular(self):
        e = emb.amenaza_agrupada(
            [("URL", "https://a.test/1", "1 detección", "url:1")], self._usuario())
        titulo = e.title or ""
        assert "1 detección" in titulo, titulo
        assert "detecciones" not in titulo, titulo
        assert "·" in titulo, f"el número tiene que estar en el título: {titulo}"

    def test_varias_en_plural(self):
        e = emb.amenaza_agrupada(
            [("URL", f"https://a.test/{i}", "1 detección", f"url:{i}") for i in range(3)],
            self._usuario())
        titulo = e.title or ""
        assert "3 detecciones" in titulo, titulo

    def test_el_pie_usa_el_mismo_numero(self):
        e = emb.amenaza_agrupada(
            [("URL", "https://a.test/1", "1 detección", "url:1")], self._usuario())
        assert "1 detección" in e.footer.text, e.footer.text


class TestElAvisoDeTamanoLlevaCifras:
    """Un límite sin números obliga a mirar el peso del fichero para entender por qué.

    Y si el tamaño no se conoce —viene de la caché o de la respuesta de la API— no se
    inventa un «0.0 MB» que parece un dato medido.
    """

    def test_con_el_tamano_de_la_imagen(self):
        from ui.message_handler import _motivo_de_error

        texto = _motivo_de_error({"error": "too_large", "tamano": 3_266_277})
        assert "3.1 MB" in texto, texto
        assert "10 MB" in texto, texto
        assert "demasiado grande" in texto, texto

    def test_sin_tamano_no_inventa_ceras(self):
        from ui.message_handler import _motivo_de_error

        texto = _motivo_de_error({"error": "too_large"})
        assert "0.0 MB" not in texto, texto
        assert "demasiado grande" in texto, texto


class TestElLimiteDeImagenAceptaLoQueDiscordAcepta:
    """2 MiB rechazaban una foto de 3 MB: perfectamente normal de compartir.

    El límite lo pone Discord (10 MB en plan gratuito), no la API: SightEngine admite más.
    Y no cuesta cuota, porque el contador cobra una operación por modelo y no por byte.
    """

    def test_el_limite_es_el_de_discord(self):
        from core.config import MAX_IMAGE_SIZE

        assert MAX_IMAGE_SIZE == 10 * 1024 * 1024, MAX_IMAGE_SIZE

    def test_una_foto_normal_no_se_rechaza(self):
        """La que falló en producción medía 3,1 MiB."""
        from core.config import MAX_IMAGE_SIZE

        assert 3_266_277 < MAX_IMAGE_SIZE
