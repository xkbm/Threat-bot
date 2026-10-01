"""Migración de `data.json` a SQLite y persistencia en general.

Lo que se fija aquí, en orden de importancia:

1. **La migración no rompe nada.** Si falla, el bot arranca con `data.json`. Perder la
   configuración de los servidores es inaceptable, así que nada de esto borra el
   fichero original.
2. **Es idempotente.** Solo importa si `guild_config` está vacía. Si reimportara siempre,
   sobrescribiría los cambios hechos en SQLite con el estado viejo del JSON.
3. **Un guardado completo no pierde los contadores** de cuota. Antes, `include_runtime`
   era False por defecto y un solo análisis borraba lo que el guardado horario acababa
   de escribir.
"""

import asyncio
import json
import types
from pathlib import Path

import pytest

from core import database as db


@pytest.fixture
def entorno(tmp_path):
    """Redirige `DATA_FILE` y `POOL` a un directorio temporal."""
    anterior_data = db.DATA_FILE
    anterior_pool = db.POOL
    data_file = tmp_path / "data.json"
    db.DATA_FILE = str(data_file)
    db.POOL = db.DatabasePool(str(tmp_path / "analisis.db"), size=1)
    yield data_file, db.POOL
    db.DATA_FILE = anterior_data
    db.POOL = anterior_pool


def _data_json_viejo() -> dict:
    """Un `data.json` con la forma que tenía antes de esta migración."""
    return {
        "1234567890": {
            "silent_mode": False, "strict_mode": True, "auto_scan_enabled": True,
            "log_channel_id": 1111111111, "whitelist": ["discord.com", "miweb.es"],
            "avisar_limpios": True,
            "infracciones": {"555": 4},
            "infracciones_registradas": {"555": ["url:https://a.com", "filehash:abc"]},
        },
        "999": {
            "silent_mode": True, "strict_mode": False, "whitelist": [],
            "infracciones": {}, "infracciones_registradas": {},
        },
        "__api_usage__": {
            "total_requests": {"vtkey": 431},
            "daily_usage": {"vtkey": {"count": 431, "date": "2026-10-01"}},
            "sightengine": {"total_requests": {"seu": 120},
                            "daily_usage": {"seu": {"count": 120, "date": "2026-10-01"}}},
        },
        "__antispam__": {
            "user_scan_history": {"[1234567890, 555]": [1696000000.0]},
            "antispam_scan": {"1234567890": 7},
        },
    }


class TestMigracion:
    @pytest.mark.asyncio
    async def test_importa_los_guilds(self, entorno):
        data_file, pool = entorno
        data_file.write_text(json.dumps(_data_json_viejo()), encoding="utf-8")
        await pool.start()
        try:
            guilds = await db.listar_guilds_db()
            assert set(guilds) == {1234567890, 999}
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_conserva_los_ajustes_de_cada_guild(self, entorno):
        data_file, pool = entorno
        data_file.write_text(json.dumps(_data_json_viejo()), encoding="utf-8")
        await pool.start()
        try:
            config = await db.obtener_config_db(1234567890)
            assert config["silent_mode"] is False
            assert config["strict_mode"] is True
            assert config["whitelist"] == ["discord.com", "miweb.es"]
            assert config["log_channel_id"] == 1111111111
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_las_infracciones_van_a_su_tabla(self, entorno):
        data_file, pool = entorno
        data_file.write_text(json.dumps(_data_json_viejo()), encoding="utf-8")
        await pool.start()
        try:
            elementos = await db.infracciones_de_db(1234567890, 555)
            assert set(elementos) == {"url:https://a.com", "filehash:abc"}
            # Y sale del blob: si se quedara, habría dos fuentes de verdad.
            config = await db.obtener_config_db(1234567890)
            assert "infracciones_registradas" not in config
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_el_estado_de_cuota_tambien_migra(self, entorno):
        data_file, pool = entorno
        data_file.write_text(json.dumps(_data_json_viejo()), encoding="utf-8")
        await pool.start()
        try:
            row = await pool.fetchone("SELECT value FROM runtime WHERE key = ?",
                                      ("__api_usage__",))
            assert row is not None
            assert json.loads(row[0])["total_requests"]["vtkey"] == 431
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_data_json_no_se_borra(self, entorno):
        """El respaldo tiene que seguir ahí. Es lo que permite volver atrás."""
        data_file, pool = entorno
        original = json.dumps(_data_json_viejo())
        data_file.write_text(original, encoding="utf-8")
        await pool.start()
        try:
            await db.listar_guilds_db()
            assert data_file.exists()
            assert json.loads(data_file.read_text(encoding="utf-8"))["999"]
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_no_reimporta_si_ya_hay_datos(self, entorno):
        """Idempotencia: si ya se migró, un segundo arranque no debe pisar los cambios."""
        data_file, pool = entorno
        data_file.write_text(json.dumps(_data_json_viejo()), encoding="utf-8")
        await pool.start()
        try:
            await db.guardar_config_db(1234567890, {"silent_mode": True, "nuevo": "x"})
            # Se fuerza una segunda pasada de la migración.
            pool.config_migrada = False
            await pool._migrar_data_json(pool._conns[0])
            config = await db.obtener_config_db(1234567890)
            assert config.get("nuevo") == "x", "la reimportación pisó un cambio de SQLite"
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_un_json_corrupto_no_impide_arrancar(self, entorno):
        data_file, pool = entorno
        data_file.write_text("{esto no es json", encoding="utf-8")
        await pool.start()
        try:
            assert pool.config_migrada is False
            assert await db.listar_guilds_db() == []
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_sin_data_json_no_falla(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            assert pool.config_migrada is True
        finally:
            await pool.stop()


class TestInfracciones:
    @pytest.mark.asyncio
    async def test_registra_y_deduplica(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            assert await db.registrar_infraccion_db(1, 55, "url:a") is True
            assert await db.registrar_infraccion_db(1, 55, "url:a") is False
            assert await db.contar_infracciones_db(1, 55) == 1
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_elementos_distintos_cuentan_separado(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            await db.registrar_infraccion_db(1, 55, "url:a")
            await db.registrar_infraccion_db(1, 55, "url:b")
            assert await db.contar_infracciones_db(1, 55) == 2
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_ignorar_borra_la_fila(self, entorno):
        """El botón "Ignorar" hace un DELETE real, no resta un número."""
        data_file, pool = entorno
        await pool.start()
        try:
            await db.registrar_infraccion_db(1, 55, "url:a")
            await db.registrar_infraccion_db(1, 55, "url:b")
            await db.borrar_infraccion_db(1, 55, "url:a")
            assert await db.contar_infracciones_db(1, 55) == 1
            assert await db.infracciones_de_db(1, 55) == ["url:b"]
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_ignorar_lo_que_no_existe_no_rompe(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            await db.borrar_infraccion_db(1, 55, "url:fantasma")
            assert await db.contar_infracciones_db(1, 55) == 0
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_guilds_y_usuarios_no_se_mezclan(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            await db.registrar_infraccion_db(1, 55, "url:a")
            await db.registrar_infraccion_db(2, 55, "url:a")
            await db.registrar_infraccion_db(1, 66, "url:a")
            assert await db.contar_infracciones_db(1, 55) == 1
            assert await db.contar_infracciones_db(2, 55) == 1
            assert await db.contar_infracciones_db(1, 66) == 1
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_la_purga_respeta_la_antiguedad(self, entorno):
        """Sin purga, la tabla crece para siempre."""
        import time

        data_file, pool = entorno
        await pool.start()
        try:
            await db.registrar_infraccion_db(1, 55, "vieja", creada=time.time() - 200 * 86400)
            await db.registrar_infraccion_db(1, 55, "nueva", creada=time.time())
            borradas = await db.purgar_infracciones(90)
            assert borradas == 1
            assert await db.infracciones_de_db(1, 55) == ["nueva"]
        finally:
            await pool.stop()


class TestConfig:
    @pytest.mark.asyncio
    async def test_roundtrip(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            config = {"silent_mode": False, "whitelist": ["a.com"], "n": 3}
            await db.guardar_config_db(7, config)
            assert await db.obtener_config_db(7) == config
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_sobrescribe_en_vez_de_duplicate(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            await db.guardar_config_db(7, {"a": 1})
            await db.guardar_config_db(7, {"a": 2})
            assert await db.obtener_config_db(7) == {"a": 2}
            assert await db.listar_guilds_db() == [7]
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_no_guarda_las_infracciones_en_el_blob(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            await db.guardar_config_db(7, {"a": 1, "infracciones_registradas": {"1": ["x"]}})
            assert "infracciones_registradas" not in await db.obtener_config_db(7)
        finally:
            await pool.stop()

    @pytest.mark.asyncio
    async def test_guild_inexistente_devuelve_none(self, entorno):
        data_file, pool = entorno
        await pool.start()
        try:
            assert await db.obtener_config_db(999) is None
        finally:
            await pool.stop()


class TestVolcadoCompleto:
    """El bug de `include_runtime`: un guardado parcial borraba los contadores."""

    @pytest.fixture
    def bot_de_prueba(self, tmp_path):
        anterior_data = db.DATA_FILE
        anterior_bot = db.state.bot
        data_file = tmp_path / "data.json"
        db.DATA_FILE = str(data_file)
        bot = types.SimpleNamespace(
            guilds_data={1: {"silent_mode": True, "whitelist": []}},
            vt_key_total_requests={"k1": 7},
            vt_key_daily_usage={"k1": {"count": 7, "date": "2026-10-01"}},
            se_key_total_requests={"u1": 5},
            se_key_daily_usage={"u1": {"count": 5, "date": "2026-10-01"}},
            user_scan_history={}, antispam_scan={},
        )
        db.state.bot = bot
        db._guardar_datos_task = None
        db._guardar_datos_pendiente = False
        yield bot, data_file
        db.DATA_FILE = anterior_data
        db.state.bot = anterior_bot

    @pytest.mark.asyncio
    async def test_cuota_siempre_en_el_archivo(self, bot_de_prueba):
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)
        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__api_usage__" in guardado
        assert "__antispam__" in guardado
        assert guardado["__api_usage__"]["total_requests"]["k1"] == 7

    @pytest.mark.asyncio
    async def test_un_guardado_repetido_no_borra_nada(self, bot_de_prueba):
        """El bug en su forma más directa: un análisis no puede dejar el archivo vacío."""
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)
        await db.guardar_datos(inmediato=True)
        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__api_usage__" in guardado
        assert "__antispam__" in guardado
        assert guardado["__api_usage__"]["total_requests"]["k1"] == 7

    def test_el_parametro_no_puede_volver(self):
        """Guarda estática: es la causa raíz, no un síntoma."""
        import inspect

        assert "include_runtime" not in inspect.signature(db.guardar_datos).parameters
        assert "include_runtime" not in inspect.signature(db._flush_datos).parameters

    def test_ningun_llamante_lo_pasa(self):
        """Se leen los ficheros como texto: importar `bot.py` crea el cliente."""
        raiz = Path(__file__).resolve().parent.parent
        for nombre in ("bot.py", "core/guild_config.py", "core/config_schema.py",
                       "cogs/configuracion.py", "ui/panel.py", "api/sightengine.py"):
            texto = (raiz / nombre).read_text(encoding="utf-8")
            reales = [l for l in texto.splitlines()
                      if "include_runtime=" in l and not l.lstrip().startswith("#")]
            assert not reales, f"{nombre}: {reales}"


class TestCargaDeDatos:
    @pytest.mark.asyncio
    async def test_el_guild_se_guarda_con_id_entero(self, entorno):
        """Las claves del JSON son strings; en memoria son ints. Si se mezclan, `/settings`
        y `/usercheck` no encuentran el guild."""
        anterior = db.DATA_FILE
        data_file = entorno[0]
        data_file.write_text(json.dumps({"12345": {"silent_mode": True}}), encoding="utf-8")
        anterior_bot = db.state.bot
        bot = types.SimpleNamespace(
            guilds_data={}, vt_key_total_requests={}, vt_key_daily_usage={},
            se_key_total_requests={}, se_key_daily_usage={},
            user_scan_history={}, antispam_scan={}, vt_key_usage={}, se_key_usage={},
        )
        db.state.bot = bot
        try:
            await db.cargar_datos()
            assert 12345 in bot.guilds_data
        finally:
            db.DATA_FILE = anterior
            db.state.bot = anterior_bot
