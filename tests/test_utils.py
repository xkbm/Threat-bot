from core.utils import dominio_en_whitelist, es_hash_valido, tiene_doble_extension, barra_porcentaje, obtener_top_antivirus


class TestDominioEnWhitelist:
    def test_exact_match(self):
        assert dominio_en_whitelist("youtube.com", ["youtube.com"]) is True

    def test_subdomain_match(self):
        assert dominio_en_whitelist("www.youtube.com", ["youtube.com"]) is True

    def test_no_match(self):
        assert dominio_en_whitelist("evil-youtube.com", ["youtube.com"]) is False

    def test_empty_whitelist(self):
        assert dominio_en_whitelist("youtube.com", []) is False

    def test_case_insensitive(self):
        assert dominio_en_whitelist("YouTube.COM", ["youtube.com"]) is True

    def test_multiple_domains(self):
        whitelist = ["youtube.com", "github.com", "discord.com"]
        assert dominio_en_whitelist("github.com", whitelist) is True
        assert dominio_en_whitelist("docs.github.com", whitelist) is True
        assert dominio_en_whitelist("evil.com", whitelist) is False

    def test_strips_whitespace(self):
        assert dominio_en_whitelist("  youtube.com  ", ["youtube.com"]) is True


class TestEsHashValido:
    def test_md5(self):
        assert es_hash_valido("44d88612fea8a8f36de82e1278abb02f") is True

    def test_sha1(self):
        assert es_hash_valido("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True

    def test_sha256(self):
        assert es_hash_valido("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True

    def test_invalid_length(self):
        assert es_hash_valido("abcd1234") is False

    def test_invalid_chars(self):
        assert es_hash_valido("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") is False

    def test_empty(self):
        assert es_hash_valido("") is False

    def test_strips_whitespace(self):
        assert es_hash_valido("  44d88612fea8a8f36de82e1278abb02f  ") is True


class TestTieneDobleExtension:
    def test_malicious_vbs(self):
        assert tiene_doble_extension("photo.jpg.vbs") is True

    def test_malicious_exe(self):
        assert tiene_doble_extension("document.pdf.exe") is True

    def test_malicious_ps1(self):
        assert tiene_doble_extension("image.png.ps1") is True

    def test_safe_single_ext(self):
        assert tiene_doble_extension("photo.jpg") is False

    def test_safe_tar_gz(self):
        assert tiene_doble_extension("archive.tar.gz") is False

    def test_safe_no_ext(self):
        assert tiene_doble_extension("Makefile") is False

    def test_safe_two_parts(self):
        assert tiene_doble_extension("file.txt") is False


class TestBarraPorcentaje:
    def test_zero(self):
        assert barra_porcentaje(0) == "░░░░░░░░░░"

    def test_full(self):
        assert barra_porcentaje(100) == "██████████"

    def test_half(self):
        result = barra_porcentaje(50)
        assert result.count("█") == 5
        assert result.count("░") == 5

    def test_custom_length(self):
        result = barra_porcentaje(75, longitud=4)
        assert result.count("█") == 3
        assert result.count("░") == 1

    def test_over_100(self):
        result = barra_porcentaje(150)
        assert result.count("█") == 15


class TestObtenerTopAntivirus:
    def test_empty(self):
        assert obtener_top_antivirus({}) == []

    def test_known_av(self):
        results = {"Kaspersky": {"category": "malicious"}}
        assert "Kaspersky" in obtener_top_antivirus(results)

    def test_unknown_av(self):
        results = {"SomeUnknownEngine": {"category": "malicious"}}
        assert obtener_top_antivirus(results) == []

    def test_non_malicious(self):
        results = {"Kaspersky": {"category": "harmless"}}
        assert obtener_top_antivirus(results) == []

    def test_max_three(self):
        results = {
            "Kaspersky": {"category": "malicious"},
            "McAfee": {"category": "malicious"},
            "Avast": {"category": "malicious"},
            "Norton": {"category": "malicious"},
        }
        assert len(obtener_top_antivirus(results)) == 3
