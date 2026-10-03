"""`/stats` tiene que enseñar TODO lo que el bot cuenta.

Antes de este fichero no había ni un test que tocara `/stats`, y por eso tres de las nueve
categorías-schema handles existían en el código y no aparecían nunca en el embed. Aquí se
mira el embed que se envía de verdad, no la función que lo construye.

El aviso de "sin stats no se Rompe" va al revés que los tests habituales: lo que se fija es
que una categoría **ausente en el embed** es un fallo, para que añadir una no se olvide de
enseñarla.
"""

import types

import pytest


def _bot(stats: dict):
    """Un bot con lo justo que `EstadisticasCog` toca."""
    from core.config import stats_vacias

    base = stats_vacias()
    base.update(stats)
    emojis = [
        "CORRECTO", "INCORRECTO", "ERROR", "WARNING", "LINK", "LUPA", "STATS", "WHITELIST",
        "SHIELD", "FINGERPRINT", "GUARDIAN", "NSFW", "RESTRINGIDO", "PHISHING", "KEY",
        "LOADING", "FILE", "REPLY", "CLEAN", "BAN", "KICK", "GITHUB",
    ]
    bot = types.SimpleNamespace(
        vt_key_count=1, se_key_count=1,
        vt_key_total_requests={}, vt_key_usage={}, vt_key_daily_usage={},
        se_key_total_requests={}, se_key_daily_usage={},
    )
    for e in emojis:
        setattr(bot, f"EMOJI_{e}", "")
    bot.EMOJI_STATS = "[stats]"
    bot.barra_porcentaje = lambda p, longitud=20: "x" * max(1, int(p / 5))
    bot.obtener_stats_globales = lambda: dict(base)
    return bot


async def _embed_de_stats(monkeypatch, stats: dict):
    """Ejecuta `/stats` con un bot falso y devuelve el embed que se envió."""
    import cogs.stats as stats_mod

    enviados = []

    class _Resp:
        async def defer(self):
            return None

        def is_done(self):
            return True

    class _Followup:
        async def send(self, embed=None, **k):
            enviados.append(embed)

    interaction = types.SimpleNamespace(
        response=_Resp(), followup=_Followup(),
        guild=types.SimpleNamespace(id=1), user=types.SimpleNamespace(id=2),
        channel=types.SimpleNamespace(id=3),
    )

    async def _sin_prompt(*a, **k):
        return None

    monkeypatch.setattr(stats_mod, "maybe_send_review_prompt", _sin_prompt)

    cog = stats_mod.EstadisticasCog(_bot(stats))
    # `stats_command` es un `app_commands.Command`, no la coroutine. Y `.callback` es la
    # función SIN ligar, así que hay que pasarle el `self` a mano: sin esto el fallo es
    # "missing 1 required positional argument: 'interaction'", que no lleva a ninguna parte.
    await cog.stats_command.callback(cog, interaction)

    assert enviados, "/stats no envió ningún embed"
    return enviados[0]


class TestStatsEnsenanTodasLasCategorias:
    """Cada categoría que el bot cuenta tiene que salir en el embed.

    El fallo que motivó esto: `restringidos`, `phishing` e `ignorados` se contaban y no se
    enseñaban. Con una base real de 11 phishing y 3 restringidos, `/stats` salía como si no
    hubiera pasado nada. Dos de esas tres son precisamente las que justifican el bot.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("categoria", [
        "total_analisis", "seguros", "sospechosos", "maliciosos", "nsfw",
        "restringidos", "phishing", "ignorados", "errores",
    ])
    async def test_toda_categoria_aparece_en_el_embed(self, monkeypatch, categoria):
        embed = await _embed_de_stats(monkeypatch, {categoria: 7})

        campos = " ".join(f"{f.name} {f.value}" for f in embed.fields)
        assert "**7**" in campos, (
            f"`{categoria}` vale 7 y no sale por ninguna parte del embed: {campos}"
        )

    @pytest.mark.asyncio
    async def test_no_enseña_un_cero_por_valor_faltante(self, monkeypatch):
        """Un `data.json` viejo no trae `phishing`; el embed no puede reventar ni mentir."""
        embed = await _embed_de_stats(monkeypatch, {"total_analisis": 3})
        nombres = {f.name for f in embed.fields}
        assert any("Phishing" in n for n in nombres), nombres
        assert any("Restringidos" in n for n in nombres), nombres


class TestElPorcentajeCuentaTodasLasAmenazas:
    """La barra solo miraba los maliciosos, y con eso el panel minimizaba su propio trabajo."""

    @pytest.mark.asyncio
    async def test_el_porcentaje_incluye_lo_que_no_es_malware(self, monkeypatch):
        """100 análisis con 10 de phishing y nada de malware: 0% antes, 10% ahora."""
        embed = await _embed_de_stats(monkeypatch, {
            "total_analisis": 100, "phishing": 10, "maliciosos": 0,
        })
        deteccion = next(f for f in embed.fields if "Detecciones totales" in f.name)
        assert "10.0%" in deteccion.value, deteccion.value

    @pytest.mark.asyncio
    async def test_suma_todas_las_categorias_de_amenaza(self, monkeypatch):
        embed = await _embed_de_stats(monkeypatch, {
            "total_analisis": 100, "maliciosos": 5, "sospechosos": 5,
            "nsfw": 5, "restringidos": 5, "phishing": 5,
        })
        deteccion = next(f for f in embed.fields if "Detecciones totales" in f.name)
        assert "25.0%" in deteccion.value, deteccion.value

    @pytest.mark.asyncio
    async def test_seguira_diciendo_cuanto_es_solo_malware(self, monkeypatch):
        """Los dos porcentajes conviven: el malware tiene su propia línea."""
        embed = await _embed_de_stats(monkeypatch, {
            "total_analisis": 100, "maliciosos": 8, "phishing": 2,
        })
        solo = next(f for f in embed.fields if "Solo malware" in f.name)
        assert "8.0%" in solo.value, solo.value

    @pytest.mark.asyncio
    async def test_los_ignorados_no_cuentan_como_amenaza(self, monkeypatch):
        """Un moderador que descartó algo no es una amenaza detectada. Sumar eso sería
        inflar el porcentaje con trabajo humano."""
        embed = await _embed_de_stats(monkeypatch, {
            "total_analisis": 100, "maliciosos": 10, "ignorados": 40,
        })
        deteccion = next(f for f in embed.fields if "Detecciones totales" in f.name)
        assert "10.0%" in deteccion.value, deteccion.value


class TestUnaSolaDefinicionDeStatsVacias:
    """Había dos. La de `database.py` tenía 6 claves y la de `guild_config.py` nueve.

    Las tres que faltaban eran justo las que no se enseñaban, así que los dos fallos se
    escondían el uno al otro: el arranque limpio borraba las tres categorías y el embed
    tampoco las miraba.
    """

    def test_database_no_trae_su_propia_copia(self):
        """Si vuelve a hardcodear un dict aquí, esto falla."""
        import ast
        import inspect

        import core.database as db

        # `getsource` sin `cleandoc`: quitar la sangría deja un bloque sin cuerpo y el
        # `ast.parse` revienta antes de llegar a comprobar nada.
        arbol = ast.parse(inspect.getsource(db.cargar_datos))
        literales = [
            n for n in ast.walk(arbol)
            if isinstance(n, ast.Dict) and n.keys
            and any(getattr(k, "value", None) == "total_analisis" for k in n.keys)
        ]
        assert not literales, (
            "cargar_datos vuelve a traer su propio dict de estadísticas. "
            f"Debe usar stats_vacias() de core.config: {len(literales)} literal(es)"
        )

    def test_ambos_modulos_usan_la_misma(self):
        import core.database as db
        from core.config import stats_vacias
        from core import guild_config

        assert guild_config._stats_vacias is stats_vacias
        # Y una categoría nueva añadida en config aparece en ambos sin tocar nada más.
        vacias = stats_vacias()
        assert set(vacias) >= {"restringidos", "phishing", "ignorados"}, sorted(vacias)
        assert db.stats_vacias is stats_vacias

    def test_la_forma_no_tiene_duplicados(self):
        from core.config import stats_vacias

        assert len(stats_vacias()) == 9, stats_vacias()