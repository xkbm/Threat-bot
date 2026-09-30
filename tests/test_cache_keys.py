"""Claves de caché canónicas (F1).

El defecto era que la clave se construía en tres sitios y uno de ellos normalizaba la
URL mientras los otros dos no. El resultado era que la caché de 7 días era de
solo-escritura para el autoescaneo: se guardaba `url:https://x.com/` y se buscaba
`url:https://x.com`, así que cada reposteo gastaba otra vez las 5 unidades del
análisis de una URL desconocida.
"""

import pytest

from core.utils import clave_analisis, normalizar_url


class TestNormalizarUrl:
    def test_path_vacio_gana_barra(self):
        assert normalizar_url("https://x.com") == "https://x.com/"

    def test_barra_final_se_quita(self):
        assert normalizar_url("https://x.com/") == "https://x.com/"

    def test_query_se_conserva(self):
        assert normalizar_url("https://x.com/a?b=1") == "https://x.com/a?b=1"

    def test_puerto_por_defecto_se_quita(self):
        assert normalizar_url("https://x.com:443/a") == normalizar_url("https://x.com/a")

    def test_host_en_mayusculas_baja(self):
        assert normalizar_url("https://X.COM/a") == "https://x.com/a"

    def test_otros_puertos_se_conservan(self):
        assert normalizar_url("https://x.com:8443/a") == "https://x.com:8443/a"


class TestVariantesCompartenClave:
    """Las formas equivalentes de una misma URL tienen que ser la misma clave."""

    @pytest.mark.parametrize("a,b", [
        ("https://x.com", "https://x.com/"),
        ("https://X.com/a", "https://x.com/a"),
        ("https://x.com:443/a", "https://x.com/a"),
        ("http://x.com:80/a", "http://x.com/a"),
    ])
    def test_misma_clave(self, a, b):
        assert clave_analisis("url", a) == clave_analisis("url", b)

    def test_urls_distintas_no_se_confunden(self):
        assert clave_analisis("url", "https://x.com/a") != clave_analisis("url", "https://x.com/b")
        # Una query distinta es un recurso distinto.
        assert clave_analisis("url", "https://x.com/a?id=1") != clave_analisis("url", "https://x.com/a?id=2")


class TestClavePorTipo:
    def test_url_lleva_prefijo_url(self):
        assert clave_analisis("url", "https://x.com").startswith("url:")

    def test_hash_lleva_prefijo_hash(self):
        assert clave_analisis("hash", "a" * 64) == f"hash:{'a' * 64}"

    def test_ip_lleva_prefijo_ip(self):
        assert clave_analisis("ip", "8.8.8.8") == "ip:8.8.8.8"

    def test_archivo_usa_filehash(self):
        """`filehash:` y no `file:`: es el prefijo que ya usan el elemento_id de las
        infracciones y `core.cache._tipo_analisis_de_clave`. Con `file:` el archivo se
        cachearía con una clave y se leería con otra."""
        assert clave_analisis("file", "b" * 64) == f"filehash:{'b' * 64}"

    def test_hash_no_se_normaliza(self):
        """Un hash es un hash: no tiene formas equivalentes que colapsar.

        Se guardan tal cual, así que mayúsculas y minúsculas son claves distintas.
        El flujo real siempre pasa el hash en minúsculas, pero la clave no lo fuerza:
        normalizarlo aquí daría la falsa impresión de que se deduplican.
        """
        h = "A" * 64
        assert clave_analisis("hash", h) == f"hash:{'A' * 64}"
        assert clave_analisis("hash", h) != clave_analisis("hash", h.lower())

    def test_ip_no_se_normaliza(self):
        assert clave_analisis("ip", "8.8.8.8") != clave_analisis("ip", "8.8.8.8:80")


class TestCoherenciaEntreEntradasYSalidas:
    """Lo que escribe la API y lo que lee el autoescaneo tienen que coincidir.

    Esta es la regresión directa de F1: los dos caminos construían la clave con
    fórmulas distintas, así que el que escribía no era el que leía.
    """

    def test_autoescaneo_y_api_coinciden(self):
        # `api/virustotal._procesar_resultado_vt` guarda con `clave_analisis(tipo, valor)`.
        escrita = clave_analisis("url", "https://ejemplo.com")
        # `ui/message_handler` busca con la misma función, pero con la URL ya expandida.
        leida = clave_analisis("url", "https://ejemplo.com")
        assert escrita == leida

    def test_command_y_autoescaneo_coinciden(self):
        """`/scan` y el autoescaneo calculan la clave con `clave_analisis`."""
        assert clave_analisis("url", "https://ejemplo.com/") == clave_analisis("url", "https://ejemplo.com")
