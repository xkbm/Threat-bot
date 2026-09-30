import ipaddress

import pytest

from core.utils import _ip_permitida, _url_a_ip, dominio_en_whitelist, normalizar_url
from ui.message_handler import _limpiar_url


# IPs que NUNCA deben alcanzarse desde el contenedor del bot.
BLOQUEADAS = [
    "127.0.0.1",          # loopback
    "0.0.0.0",            # sin especificar
    "0.0.0.1",            # bloque 0.0.0.0/8
    "10.0.0.1",           # RFC 1918
    "172.16.0.1",         # RFC 1918
    "192.168.1.1",        # RFC 1918
    "169.254.169.254",    # link-local: metadatos de cloud
    "100.64.0.1",         # CGNAT: is_private=False e is_global=False
    "224.0.0.1",          # multicast (is_private=False)
    "240.0.0.1",          # reservado
    "255.255.255.255",    # broadcast
    "::1",                # loopback v6
    "::",                 # sin especificar v6
    "fe80::1",            # link-local v6
    "fc00::1",            # ULA v6
    "ff02::1",            # multicast v6
]

PERMITIDAS = [
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
    "2606:4700:4700::1111",
]


class TestIpPermitida:
    @pytest.mark.parametrize("ip", BLOQUEADAS)
    def test_bloqueada(self, ip):
        assert _ip_permitida(ipaddress.ip_address(ip)) is False

    @pytest.mark.parametrize("ip", PERMITIDAS)
    def test_permitida(self, ip):
        assert _ip_permitida(ipaddress.ip_address(ip)) is True

    def test_cgnat_es_el_hueco_clasico(self):
        """ipaddress.is_private es False aquí: por eso hace falta el chequeo explícito."""
        ip = ipaddress.ip_address("100.64.0.1")
        assert ip.is_private is False
        assert ip.is_global is False
        assert _ip_permitida(ip) is False

    def test_multicast_no_es_privado(self):
        ip = ipaddress.ip_address("224.0.0.1")
        assert ip.is_private is False
        assert _ip_permitida(ip) is False


class TestUrlAIp:
    """`_url_a_ip` es corrutina porque delega en `_resolve_url`, que hace getaddrinfo."""

    @pytest.mark.asyncio
    async def test_ip_literal_bloqueada(self):
        url, err = await _url_a_ip("http://127.0.0.1:8080/admin")
        assert url is None
        assert "127.0.0.1" in (err or "")

    @pytest.mark.asyncio
    async def test_link_local_bloqueada(self):
        url, err = await _url_a_ip("http://169.254.169.254/latest/meta-data/")
        assert url is None
        assert err

    @pytest.mark.asyncio
    async def test_ipv6_loopback_bloqueada(self):
        url, err = await _url_a_ip("http://[::1]:9000/")
        assert url is None
        assert err

    @pytest.mark.asyncio
    async def test_cgnat_bloqueada(self):
        url, err = await _url_a_ip("http://100.64.1.1/")
        assert url is None
        assert err

    @pytest.mark.asyncio
    async def test_sin_esquema_otorga_error(self):
        url, err = await _url_a_ip("no-es-una-url")
        assert url is None
        assert err

    @pytest.mark.asyncio
    async def test_ip_publica_conserva_puerto_y_esquema(self):
        url, err = await _url_a_ip("https://8.8.8.8:8443/x?y=1")
        assert err is None
        assert url == "https://8.8.8.8:8443/x?y=1"

    @pytest.mark.asyncio
    async def test_ipv6_publica_va_entre_corchetes(self):
        url, err = await _url_a_ip("https://[2606:4700::1111]:8443/x")
        assert err is None
        assert url == "https://[2606:4700::1111]:8443/x"


class TestDominioEnWhitelist:
    def test_sufijo_truncado_no_cuadra(self):
        assert dominio_en_whitelist("notyoutube.com", ["youtube.com"]) is False

    def test_dominio_como_sufijo_no_cuadra(self):
        assert dominio_en_whitelist("youtube.com.evil.io", ["youtube.com"]) is False


class TestNormalizarUrl:
    def test_puerto_http_por_defecto(self):
        assert normalizar_url("http://ejemplo.com:80/a") == "http://ejemplo.com/a"

    def test_puerto_https_por_defecto(self):
        assert normalizar_url("https://ejemplo.com:443/a") == "https://ejemplo.com/a"

    def test_barra_final(self):
        assert normalizar_url("https://ejemplo.com/a/") == "https://ejemplo.com/a"

    def test_query_se_conserva(self):
        assert normalizar_url("https://ejemplo.com/a?b=1") == "https://ejemplo.com/a?b=1"

    def test_hostname_en_minusculas(self):
        assert normalizar_url("https://EJEMPLO.com/A") == "https://ejemplo.com/A"


class TestLimpiarUrl:
    def test_quita_puntuacion_final(self):
        assert _limpiar_url("https://ejemplo.com/a)") == "https://ejemplo.com/a"
        assert _limpiar_url("https://ejemplo.com/a.") == "https://ejemplo.com/a"

    def test_quita_varios_caracteres(self):
        assert _limpiar_url("https://ejemplo.com/a],") == "https://ejemplo.com/a"

    def test_no_toca_url_valida(self):
        assert _limpiar_url("https://ejemplo.com/a/b") == "https://ejemplo.com/a/b"
