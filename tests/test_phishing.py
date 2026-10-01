"""Anti-phishing local.

Dos cosas difíciles, y las dos están cubiertas aquí:

1. `rnicrosoft.com` NO se detectaba cuando se comparaba primero el texto normalizado: al
   aplicarle los homoglifos se convierte en "microsoft", y eso se leía como la marca
   legítima. El orden correcto es comparar **crudo** primero, y si en crudo no es la marca
   pero normalizado sí, eso es precisamente una imitación.
2. Los dominios reales que contienen la marca (`cdn.discordapp.com`,
   `store.steampowered.com`) salían como phishing. Sin lista de dominios legítimos, el
   detector marca ruido y un moderador acaba ignorándolo.
"""

import pytest

from core.phishing import DOMINIOS_LEGITIMOS, MARCAS, _host_de, detectar, es_phishing


class TestVerdaderosPositivos:
    @pytest.mark.parametrize(
        "url,marca",
        [
            ("https://rnicrosoft.com/gift", "microsoft"),
            ("https://paypa1-secure.tk/login", "paypal"),
            ("https://discorcl.com/nitro", "discord"),
            ("https://steamcomunnity.ru/trade", "steam"),
            ("https://instagrarn.com/login", "instagram"),
            ("https://netfliix-to-free.club", "netflix"),
            ("https://roblox-gift-generator.tk", "roblox"),
            ("https://notmicrosoft.com/", "microsoft"),
            ("https://discord.com.evil.io/nitro", "discord"),
            ("https://paypal.com.login-verify.tk/", "paypal"),
        ],
    )
    def test_detecta_suplantacion(self, url, marca):
        r = detectar(url)
        assert r.es_phishing is True, f"{url} → {r.razon}"
        assert r.marca == marca

    def test_ip_publica_es_sospechosa(self):
        assert es_phishing("https://8.8.8.8/dns-query")

    def test_punycode_oculta_texto(self):
        r = detectar("https://xn--discord-ypa.com/gift")
        assert r.es_phishing is True
        assert "punycode" in r.razon


class TestVerdaderosNegativos:
    """La parte que importa: un detector que marca de más acaba ignorándose."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://discord.com/api/v10/users",
            "https://discord.gg/abc123",
            "https://cdn.discordapp.com/avatars/1/a.png",
            "https://store.steampowered.com/app/440/Team_Fortress",
            "https://steamcommunity.com/app/1",
            "https://help.epicgames.com/en-US",
            "https://github.com/usuario/repo",
            "https://stackoverflow.com/questions/1",
            "https://reddit.com/r/python",
            "https://example.com/index.html",
            "http://192.168.1.1/admin",
            "http://10.0.0.1:8080",
            "http://localhost:3000",
        ],
    )
    def test_no_marca_urls_legitimas(self, url):
        r = detectar(url)
        assert r.es_phishing is False, f"{url} → {r.razon}"

    def test_url_sin_esquema_no_rompe(self):
        assert detectar("no-es-una-url").es_phishing is False

    def test_url_vacia_no_rompe(self):
        assert detectar("").es_phishing is False

    def test_nombre_de_archivo_no_es_url(self):
        assert detectar("steam.png").es_phishing is False

    def test_marca_como_subdominio_legitimo(self):
        assert es_phishing("https://help.paypal.com/us/home") is False

    def test_tld_sospechoso_sin_palabra_no_alerta(self):
        assert es_phishing("https://blog.tk/post") is False

    def test_credenciales_en_la_url_se_ignoran(self):
        """`https://discord.com@evil.io` lleva realmente a evil.io.

        Discord y los navegadores muestran `evil.io` como destino, así que no suplanta a
        Discord visualmente. Lo importante es que el host que se analiza es el de verdad.
        """
        assert _host_de("https://discord.com@evil.io/gift") == "evil.io"
        assert es_phishing("https://discord.com@evil.io/gift") is False


class TestDominiosOficiales:
    def test_todo_dominio_legitimo_pasa_el_filtro(self):
        for dominio in DOMINIOS_LEGITIMOS:
            assert es_phishing(f"https://{dominio}/x") is False, dominio

    def test_los_legitimos_estan_normalizados(self):
        for dominio in DOMINIOS_LEGITIMOS:
            assert dominio == dominio.lower() and dominio == dominio.strip()


class TestMarcas:
    def test_ninguna_marca_esta_repetida(self):
        assert len(MARCAS) == len(set(MARCAS))

    def test_las_marcas_no_son_dominios_completos(self):
        for m in MARCAS:
            assert "." not in m, m


class TestRobustez:
    @pytest.mark.parametrize(
        "url",
        [
            "https://", "http://", "https://.", "https://....",
            "https://" + "a" * 3000 + ".com",
            "https://ñ.com/ñ", "https://emoji\U0001F600.com",
            "https://..com", "https://a..b",
        ],
    )
    def test_no_revienta_con_entradas_raras(self, url):
        r = detectar(url)
        assert isinstance(r.es_phishing, bool)
        assert isinstance(r.razon, str) and r.razon

    def test_siempre_explica_la_razon(self):
        """Un aviso sin motivo es un aviso que el moderador descarta."""
        for url in ("https://discord.com", "https://rnicrosoft.com", "no-url"):
            assert detectar(url).razon

    def test_es_phishing_coincide_con_detectar(self):
        for url in ("https://discord.com", "https://rnicrosoft.com", "http://8.8.8.8"):
            assert es_phishing(url) is detectar(url).es_phishing


class TestNoBloqueaElBot:
    """El detector corre en serie, dentro del bucle de URLs y antes de la API.

    Medido antes del tope: una URL con una etiqueta de 200 caracteres pasaba de 2 ms a
    33 ms, y `discord.com.` seguido de 300 caracteres llegaba a 59 ms. Con cinco enlaces en
    un mensaje son ~300 ms de CPU en el event loop, lo que atasca el resto del bot: otros
    mensajes, reacciones y comandos. Es un fallo de rendimiento silencioso: nada falla, todo
    va lento.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "https://ejemplo.com",
            "https://" + "a" * 200 + ".ejemplo.com",
            "https://discord.com." + "x" * 300 + ".io",
            "https://" + ".".join(["sub"] * 15) + ".ejemplo.com",
            "https://" + "y" * 500,
            "https://" + "-".join(["z"] * 60) + ".com",
        ],
    )
    def test_siempre_rapido(self, url):
        import time

        t = time.perf_counter()
        detectar(url)
        ms = (time.perf_counter() - t) * 1000
        # El presupuesto es holgado a propósito: en un portátil esto son microsegundos
        # siendo generoso. Antes este mismo test tardaba 59 ms.
        assert ms < 25, f"{url[:40]}... tardó {ms:.1f} ms"

    def test_el_tope_no_pierde_detecciones_reales(self):
        """Recortar la etiqueta para comparar no puede perder un phishing de verdad."""
        assert detectar("https://rnicrosoft.com/gift").es_phishing
        assert detectar("https://netfliix-to-free.club").es_phishing
        assert detectar("https://paypa1-secure.tk/login").es_phishing
        # Y una marca preceded de relleno largo sigue detectándose por el prefijo.
        assert detectar("https://discord.com." + "x" * 300 + ".io").es_phishing

    def test_una_etiqueta_larga_no_puede_reventar_el_coste(self):
        """El coste de Levenshtein es O(n x m) y se repite por cada marca."""
        import time

        from core.phishing import _distancia

        # El tope de 32 chars es la garantia: mas alla, no se compara por similitud.
        assert 32 > len("microsoft")
        t = time.perf_counter()
        for _ in range(33):
            _distancia("a" * 32, "discord")
        ms = (time.perf_counter() - t) * 1000
        assert ms < 50, f"33 comparaciones tardaron {ms:.1f} ms"


class TestNoGastaCuota:
    """El detector es local a propósito: con plan gratis cada request cuenta."""

    def test_no_importa_nada_de_red(self):
        import pathlib

        fuente = pathlib.Path(__file__).resolve().parent.parent / "core" / "phishing.py"
        texto = fuente.read_text(encoding="utf-8")
        for prohibido in ("import aiohttp", "import requests", "session", "await"):
            assert prohibido not in texto, prohibido

    def test_es_sincrono(self):
        """Si fuera async alguien podría.await y romper la integración."""
        assert detectar("https://discord.com").__class__.__name__ == "ResultadoPhishing"
