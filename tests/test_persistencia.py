"""Persistencia de estado: que un guardado no borre lo que otro escribió.

El defecto que fija este archivo: `guardar_datos()` tenía un parámetro
`include_runtime` cuyo default era False, y casi todos los llamantes (`update_stats`,
`registrar_infraccion`, `agregar_dominio`, los comandos de configuración, el propio
`sightengine`) lo llamaban sin pasar la bandera. Cada uno de esos Guardados escribía
`data.json` **sin** `__api_usage__` ni `__antispam__`, borrando los contadores de cuota y
el historial de antispam que el guardado horario acababa de escribir. Bastaba un análisis
entre medias para perderlos.

La causa raíz era el parámetro, así que el primer test es una guarda estática: falla si
alguien vuelve a añadirlo.
"""

import asyncio
import inspect
import json
import os
import pathlib
import types

import pytest

from core import database as db
from core import state


def tmpdir_of(path) -> str:
    return str(pathlib.Path(str(path)).parent)


class TestElParametroNoPuedeVolver:
    def test_guardar_datos_no_tiene_include_runtime(self):
        """Guarda estática: es la causa raíz, no un síntoma."""
        firma = inspect.signature(db.guardar_datos)
        assert "include_runtime" not in firma.parameters

    def test_flush_datos_no_tiene_include_runtime(self):
        firma = inspect.signature(db._flush_datos)
        assert "include_runtime" not in firma.parameters

    def test_ningun_llamante_lo_pasa(self):
        """Aunque alguien lo reintrodujera, nadie debe pasar la bandera.

        Se leen los ficheros como texto y no importándolos: importar `bot.py` crea el
        cliente de Discord y deja tareas vivas.
        """
        import pathlib

        raiz = pathlib.Path(__file__).resolve().parent.parent
        modulos = [
            "bot.py", "core/database.py", "core/guild_config.py", "core/utils.py",
            "api/sightengine.py", "api/virustotal.py", "ui/message_handler.py",
            "cogs/configuracion.py", "cogs/analisis.py", "cogs/stats.py",
        ]
        for nombre in modulos:
            fuente = (raiz / nombre).read_text(encoding="utf-8")
            # Se admite la mención en comentarios y docstrings que explican el
            # defecto; lo que no puede aparecer es una llamada que lo pase.
            llamadas = [
                linea for linea in fuente.splitlines()
                if "include_runtime" in linea and not linea.lstrip().startswith("#")
            ]
            reales = [
                linea for linea in llamadas
                if "include_runtime=" in linea and "Antes tenía" not in linea
            ]
            assert not reales, f"{nombre}: {reales}"


@pytest.fixture
def bot_de_prueba(tmp_path):
    """Un `state.bot` mínimo con los atributos que toca `_flush_datos`."""
    data_file = tmp_path / "data.json"
    bot = types.SimpleNamespace(
        guilds_data={1: {"silent_mode": True, "whitelist": []}},
        vt_key_total_requests={"k1": 7},
        vt_key_daily_usage={"k1": {"count": 7, "date": "2026-01-01"}},
        se_key_total_requests={"u1": 5},
        se_key_daily_usage={"u1": {"count": 5, "date": "2026-01-01"}},
        se_key_monthly_usage={"u1": {"count": 120, "month": "2026-01"}},
        user_scan_history={(1, 42): [1.0, 2.0]},
        antispam_scan={1: 3},
    )
    anterior = state.bot
    state.bot = bot
    db.DATA_FILE = str(data_file)
    # Una tarea debounced de un test anterior seguiría viva y `guardar_datos(inmediato)`
    # intenta cancelarla; con el loop ya cerrado eso revienta.
    db._guardar_datos_task = None
    db._guardar_datos_pendiente = False
    yield bot, data_file
    state.bot = anterior


class TestLasEstadisticasNoSePierden:
    """Regresión grave: `/stats` volvía a cero solo, cada hora.

    Las estadísticas globales viven en `guilds_data["__global__"]` y en ningún otro sitio:
    la tabla `guild_config` de SQLite tiene una fila por servidor, así que el global no
    está respaldado en ninguna parte.

    Y el guardado por defecto (`incluir_guilds=False`, que usan TODOS los llamantes
    salvo un cambio de configuración) escribía solo `__api_usage__` y `__antispam__`.
    Como el volcado es atómico y **reemplaza el fichero entero**, ese `__global__` se
    quedaba fuera y se borraba del disco. El cron horario lo hace cada hora.

    La contradicción era explícita y nadie lo miró: `update_stats` documenta que "las
    persiste el cron horario", y el cron horario era justo quien las borraba.
    """

    @pytest.mark.asyncio
    async def test_un_guardado_normal_no_borra_las_estadisticas(self, bot_de_prueba):
        bot, data_file = bot_de_prueba
        bot.guilds_data["__global__"] = {"total_analisis": 4321, "maliciosos": 7}

        await db.guardar_datos(inmediato=True)          # el camino por defecto, sin flags

        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__global__" in guardado, (
            "un guardado sin incluir_guilds se está llevándose las estadísticas"
        )
        assert guardado["__global__"]["total_analisis"] == 4321

    @pytest.mark.asyncio
    async def test_sobreviven_a_un_guardado_repetido(self, bot_de_prueba):
        """El fallo no era el primero, era cada uno de los siguientes."""
        bot, data_file = bot_de_prueba
        bot.guilds_data["__global__"] = {"total_analisis": 10}

        for _ in range(3):
            await db.guardar_datos(inmediato=True)

        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert guardado["__global__"]["total_analisis"] == 10

    @pytest.mark.asyncio
    async def test_incluir_el_global_no_trae_la_config_de_guild(self, bot_de_prueba):
        """Arreglar esto no puede reintroducir el volcado completo por mensaje."""
        bot, data_file = bot_de_prueba
        bot.guilds_data["__global__"] = {"total_analisis": 5}

        await db.guardar_datos(inmediato=True)

        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__global__" in guardado
        assert "1" not in guardado, "el global no debe arrastrar la config de los servidores"

    @pytest.mark.asyncio
    async def test_sin_stats_todavia_no_hay_global(self, bot_de_prueba):
        """Sin stats todavía no hay global que guardar, y no se crea uno vacío."""
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)
        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert guardado.get("__global__", {}) == {}


class TestElVolcadoEsCompleto:
    @pytest.mark.asyncio
    async def test_cuota_y_antispam_siempre_en_el_archivo(self, bot_de_prueba):
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)

        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__api_usage__" in guardado
        assert "__antispam__" in guardado
        assert guardado["__api_usage__"]["total_requests"]["k1"] == 7
        assert guardado["__antispam__"]["antispam_scan"]["1"] == 3

    @pytest.mark.asyncio
    async def test_el_json_ya_no_lleva_la_config_de_guild(self, bot_de_prueba):
        """SQLite es la fuente de verdad; el JSON solo lleva estado de ejecución.

        Incluir los servidores convertía CUALQUIER guardado en una reescritura completa
        de la configuración de todos ellos. Y como las estadísticas se guardan en cada
        análisis, eso significaba un volcado entero por mensaje.
        """
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)
        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "1" not in guardado
        assert "__api_usage__" in guardado
        assert "__antispam__" in guardado

    @pytest.mark.asyncio
    async def test_incluir_guilds_es_optimo(self, bot_de_prueba):
        """El volcado de emergencia existe para cuando la base no está."""
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True, incluir_guilds=True)
        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert guardado["1"]["silent_mode"] is True

    @pytest.mark.asyncio
    async def test_un_guardado_repetido_no_borra_nada(self, bot_de_prueba):
        """El bug en su forma más directa: un análisis no puede dejar el archivo vacío."""
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)
        # Esto es lo que hacía `update_stats()`: guardar sin la bandera de runtime.
        await db.guardar_datos(inmediato=True)

        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__api_usage__" in guardado, "un segundo guardado borró los contadores"
        assert "__antispam__" in guardado, "un segundo guardado borró el antispam"
        assert guardado["__api_usage__"]["total_requests"]["k1"] == 7

    @pytest.mark.asyncio
    async def test_varios_guardados_seguidos_conservan_el_estado(self, bot_de_prueba):
        bot, data_file = bot_de_prueba
        for _ in range(5):
            bot.vt_key_total_requests["k1"] += 1
            await db.guardar_datos(inmediato=True)
        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert guardado["__api_usage__"]["total_requests"]["k1"] == 12

    @pytest.mark.asyncio
    async def test_el_debounce_tambien_guarda_todo(self, bot_de_prueba):
        """La ruta sin `inmediato` tenía su propia llamada a `_flush_datos()`."""
        bot, data_file = bot_de_prueba
        db._guardar_datos_pendiente = False
        await db.guardar_datos()
        await asyncio.sleep(db._GUARDAR_DEBOUNCE + 0.2)

        guardado = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__api_usage__" in guardado
        assert "__antispam__" in guardado

    @pytest.mark.asyncio
    async def test_el_flujo_real_de_update_stats_no_borra_la_cuota(self, bot_de_prueba):
        """El escenario completo: el cron escribe, llega un análisis, y este es el que
        lo borraba en el código antiguo."""
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)
        primero = json.loads(data_file.read_text(encoding="utf-8"))["__api_usage__"]

        # `update_stats` acaba llamando a `guardar_datos()` sin argumentos.
        await db.guardar_datos()

        segundo = json.loads(data_file.read_text(encoding="utf-8"))
        assert "__api_usage__" in segundo
        assert segundo["__api_usage__"]["total_requests"] == primero["total_requests"]

    @pytest.mark.asyncio
    async def test_la_escritura_es_atomica(self, bot_de_prueba):
        """Se escribe a un temporal y se renombra: nunca queda un archivo a medias."""
        bot, data_file = bot_de_prueba
        await db.guardar_datos(inmediato=True)

        assert data_file.exists()
        assert json.loads(data_file.read_text(encoding="utf-8"))
        # No debe quedar ningún temporal por el camino.
        sobrantes = [n for n in os.listdir(tmpdir_of(data_file)) if n != "data.json"]
        assert sobrantes == [], f"temporales sin limpiar: {sobrantes}"