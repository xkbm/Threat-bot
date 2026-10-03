"""Reacciones y política de aviso.

Dos bugs que se fijan aquí:

- Reacciones: un mensaje con un enlace en whitelist, un `.pdf.exe` y una imagen NSFW
  acababa con tres emojis a la vez. Ahora solo puede haber uno.
- Aviso: `silent_mode` no distinguía "no me digas lo limpio" de "no me digas lo que
  falló".
"""

import pytest

from core import config
from core.aviso import config_aviso_por_defecto, debe_enviar_embed, reacciones_activas, razon_para_embeder
from core.reacciones import MAPA_EMOJI_VEREDICTO, ReactionController, resolver_reaccion
from core.senales import Elemento, Senales
from core.veredictos import Veredicto


def senales_de(*veredictos, **flags) -> Senales:
    s = Senales()
    for v in veredictos:
        s.anadir(Elemento(nombre=f"e-{v.value}", tipo="file", veredicto=v))
    if flags.get("sin_elementos"):
        s.elementos.clear()
    s.cooldown = flags.get("cooldown", False)
    s.omitidos = flags.get("omitidos", 0)
    s.whitelist_omitidos = flags.get("whitelist_omitidos", 0)
    return s


class TestVeredictos:
    def test_alcohol_no_es_nsfw(self):
        """Una cerveza no es pornografía. Compartían veredicto y borrado."""
        assert Veredicto.RESTRINGIDO is not Veredicto.NSFW
        assert Veredicto.RESTRINGIDO.valor if False else Veredicto.RESTRINGIDO.value == "restringido"

    def test_restringido_no_borra_en_modo_estricto(self):
        assert Veredicto.RESTRINGIDO.borra_en_modo_estricto is False

    def test_phishing_no_borra_ni_es_amenaza(self):
        assert Veredicto.PHISHING.borra_en_modo_estricto is False
        assert Veredicto.PHISHING.es_amenaza is False

    def test_solo_malicioso_y_nsfw_borran(self):
        que_borran = {v for v in Veredicto if v.borra_en_modo_estricto}
        assert que_borran == {Veredicto.MALICIOSO, Veredicto.NSFW}

    def test_los_cinco_otros_no_borran(self):
        for v in (Veredicto.SEGURO, Veredicto.SOSPECHOSO, Veredicto.RESTRINGIDO,
                  Veredicto.PHISHING, Veredicto.ERROR):
            assert v.borra_en_modo_estricto is False, v

    def test_phishing_es_hallazgo_pero_no_amenaza(self):
        assert Veredicto.PHISHING.es_hallazgo is True
        assert Veredicto.PHISHING.es_amenaza is False

    def test_desde_literal_antiguo(self):
        assert Veredicto.desde("malicioso") is Veredicto.MALICIOSO
        assert Veredicto.desde("nsfw") is Veredicto.NSFW

    def test_desde_none_es_error_no_seguro(self):
        """El punto del módulo: lo no comprobado nunca es seguro."""
        assert Veredicto.desde(None) is Veredicto.ERROR

    def test_desde_valor_inventado_es_error(self):
        assert Veredicto.desde("inventado") is Veredicto.ERROR

    def test_cada_veredicto_tiene_color_emoji_y_titulo(self):
        for v in Veredicto:
            assert isinstance(v.color, int)
            assert v.emoji
            assert v.titulo

    def test_emojis_de_veredicto_distintos(self):
        emojis = [v.emoji for v in Veredicto if v is not Veredicto.ERROR]
        assert len(emojis) == len(set(emojis))


class TestResolverReaccion:
    def test_mensaje_limpio_verde(self):
        assert resolver_reaccion(senales_de(Veredicto.SEGURO)) == config.EMOJI_CORRECTO

    def test_malicioso_tiene_prioridad_sobre_nsfw(self):
        s = senales_de(Veredicto.NSFW, Veredicto.MALICIOSO)
        assert resolver_reaccion(s) == config.EMOJI_WARNING

    def test_nsfw_sobre_restringido(self):
        s = senales_de(Veredicto.RESTRINGIDO, Veredicto.NSFW)
        assert resolver_reaccion(s) == config.EMOJI_NSFW

    def test_restringido_usa_su_emoji(self):
        assert resolver_reaccion(senales_de(Veredicto.RESTRINGIDO)) == config.EMOJI_RESTRINGIDO

    def test_phishing_usa_su_emoji(self):
        assert resolver_reaccion(senales_de(Veredicto.PHISHING)) == config.EMOJI_PHISHING

    def test_error_no_es_verde(self):
        assert resolver_reaccion(senales_de(Veredicto.ERROR)) == config.EMOJI_ERROR

    def test_cooldown_gana_a_error_pero_no_a_phishing(self):
        assert resolver_reaccion(senales_de(Veredicto.ERROR, cooldown=True)) == config.EMOJI_COOLDOWN
        assert resolver_reaccion(senales_de(Veredicto.PHISHING, cooldown=True)) == config.EMOJI_PHISHING

    def test_sospechoso(self):
        assert resolver_reaccion(senales_de(Veredicto.SOSPECHOSO)) == config.EMOJI_GUARDIAN

    def test_doble_extension_avisa(self):
        """Usa el emoji de aviso, no el de malware.

        Antes devolvía `EMOJI_WARNING`, que es el emoji de `MALICIOSO`: una doble
        extensión, que es la evidencia más débil que hay, se pintaba como malware
        confirmado.
        """
        s = Senales()
        s.anadir(Elemento(nombre="informe.pdf.exe", tipo="file", doble_extension=True))
        assert resolver_reaccion(s) == config.EMOJI_NOMBRE_SOSPECHOSO
        assert resolver_reaccion(s) != config.EMOJI_WARNING
        # Y que ese icono signifique algo: la flecha de "responder" no significa nada
        # aquí. SeJYó porque quedaba libre en la lista, y hay 5 casos igual.
        assert resolver_reaccion(s) != config.EMOJI_REPLY

    def test_el_sospechoso_gana_a_la_senal_de_nombre(self):
        s = Senales()
        s.anadir(Elemento(nombre="informe.pdf.exe", tipo="file", doble_extension=True))
        s.anadir(Elemento(nombre="u", tipo="url", veredicto=Veredicto.SOSPECHOSO))
        assert resolver_reaccion(s) == config.EMOJI_GUARDIAN

    def test_la_whitelist_solo_decide_si_no_se_miro_nada(self):
        """La whitelist solo puede ser el veredicto del mensaje cuando no se comprobó nada.

        Antes bastaba con que hubiera enlaces exentos, y eso convertía la whitelist en
        camuflaje: un atacante ponía `youtube.com` junto a un enlace recién creado que
        VirusTotal aún no conocía, ese salía "limpio", ganaba el sello de whitelist y el
        moderador pasaba de largo. La whitelist significa "esto NO se ha comprobado", así
        que si hubo elementos y todos salieron limpios, el mensaje es "analizado y limpio",
        que es lo que dice el check verde.
        """
        solo_whitelist = senales_de(Veredicto.SEGURO, whitelist_omitidos=2, sin_elementos=True)
        assert resolver_reaccion(solo_whitelist) == config.EMOJI_WHITELIST

        con_elemento_limpio = senales_de(Veredicto.SEGURO, whitelist_omitidos=1)
        assert resolver_reaccion(con_elemento_limpio) == config.EMOJI_CORRECTO, (
            "con un elemento ya analizado, el sello de whitelist miente: sí se miró"
        )

    def test_whitelist_no_contradice_una_amenaza(self):
        """El bug D16: antes salía con whitelist Y malicioso a la vez."""
        s = senales_de(Veredicto.MALICIOSO, whitelist_omitidos=1)
        assert resolver_reaccion(s) == config.EMOJI_WARNING
        assert resolver_reaccion(s) != config.EMOJI_WHITELIST

    def test_caso_real_tres_amenazas_una_solo_reaccion(self):
        """Whitelist + .pdf.exe + NSFW: antes eran tres emojis."""
        s = senales_de(Veredicto.SEGURO, Veredicto.NSFW, whitelist_omitidos=1, )
        s.anadir(Elemento(nombre="informe.pdf.exe", tipo="file", doble_extension=True))
        unico = resolver_reaccion(s)
        assert unico == config.EMOJI_NSFW
        assert unico != config.EMOJI_WHITELIST
        assert unico != config.EMOJI_CORRECTO

    def test_todo_veredicto_tiene_eco_en_el_mapa(self):
        """El mapa tiene que cubrir todo el enum.

        `ignorado` comparte emoji con la whitelist, así que el mapa no lo distingue: se
        comprueba por el emoji, que es como se usa.
        """
        for v in Veredicto:
            if v in (Veredicto.ERROR, Veredicto.SEGURO, Veredicto.IGNORADO):
                continue
            assert v.emoji in MAPA_EMOJI_VEREDICTO


class FakeMessage:
    def __init__(self, mid=1):
        self.id = mid
        self.reacciones = []
        self.removidas = []
        self.autor_bot = object()

    class _Author:
        bot = None

    @property
    def author(self):
        a = FakeMessage._Author()
        a.bot = self.autor_bot
        return a

    async def add_reaction(self, emoji):
        self.reacciones.append(emoji)

    async def remove_reaction(self, emoji, user):
        self.removidas.append(emoji)
        if emoji in self.reacciones:
            self.reacciones.remove(emoji)


class TestReactionController:
    @pytest.mark.asyncio
    async def test_solo_una_reaccion_siempre(self):
        msg = FakeMessage()
        ctrl = ReactionController(msg)
        await ctrl.set(config.EMOJI_CORRECTO)
        await ctrl.set(config.EMOJI_WARNING)
        assert msg.reacciones == [config.EMOJI_WARNING]

    @pytest.mark.asyncio
    async def test_quita_la_anterior_antes_de_poner_la_nueva(self):
        msg = FakeMessage()
        ctrl = ReactionController(msg)
        await ctrl.set(config.EMOJI_CORRECTO)
        await ctrl.set(config.EMOJI_NSFW)
        assert config.EMOJI_CORRECTO in msg.removidas

    @pytest.mark.asyncio
    async def test_no_hace_nada_si_el_veredicto_no_cambia(self):
        msg = FakeMessage()
        ctrl = ReactionController(msg)
        await ctrl.set(config.EMOJI_WARNING)
        await ctrl.set(config.EMOJI_WARNING)
        assert msg.reacciones == [config.EMOJI_WARNING]
        assert msg.removidas == []

    @pytest.mark.asyncio
    async def test_loading_es_ranura_separada(self):
        """El loading es progreso, no veredicto: puede convivir con él."""
        msg = FakeMessage()
        ctrl = ReactionController(msg)
        await ctrl.loading()
        assert config.EMOJI_LOADING in msg.reacciones

    @pytest.mark.asyncio
    async def test_el_veredicto_retira_el_loading(self):
        msg = FakeMessage()
        ctrl = ReactionController(msg)
        await ctrl.loading()
        await ctrl.set(config.EMOJI_WARNING)
        assert config.EMOJI_LOADING not in msg.reacciones
        assert msg.reacciones == [config.EMOJI_WARNING]

    @pytest.mark.asyncio
    async def test_transicion_larga_solo_deja_un_veredicto(self):
        msg = FakeMessage()
        ctrl = ReactionController(msg)
        for emoji in (config.EMOJI_CORRECTO, config.EMOJI_GUARDIAN, config.EMOJI_ERROR, config.EMOJI_WARNING):
            await ctrl.set(emoji)
        veredictos = [e for e in msg.reacciones if e != config.EMOJI_LOADING]
        assert len(veredictos) == 1

    @pytest.mark.asyncio
    async def test_limpiar_no_quita_el_veredicto(self):
        msg = FakeMessage()
        ctrl = ReactionController(msg)
        await ctrl.loading()
        await ctrl.set(config.EMOJI_CORRECTO)
        await ctrl.limpiar()
        assert msg.reacciones == [config.EMOJI_CORRECTO]

    @pytest.mark.asyncio
    async def test_error_al_poner_no_deja_estado_incoherente(self):
        class Roto(FakeMessage):
            async def add_reaction(self, emoji):
                raise RuntimeError("permisos")

        ctrl = ReactionController(Roto())
        await ctrl.set(config.EMOJI_WARNING)
        assert ctrl.veredicto_actual is None




class TestElPanelUsaEmojiQueExisten:
    """`ui.embed` no reexporta todos los emojis: solo los seis que usa para sus embeds.

    El modal de la whitelist y `_guardar` usaban `emb.EMOJI_ERROR` y `emb.EMOJI_CORRECTO`,
    que no existen. Cada rama de `on_submit` reventaba con `AttributeError`: el modal
    abría, escribías el dominio, le dabas a enviar y **no pasaba nada**. Y no era solo el
    modal: `_guardar` es lo que llama cada desplegable y cada botón del panel, así que
    tampoco se guardaba ningún ajuste.

    El síntoma —"no funciona" sin error visible— es justo el que hace que esto sea difícil
    de encontrar: Discord se come la excepción del callback y el usuario solo ve que no
    ocurre nada.
    """

    def test_ningun_emoji_de_panel_esta_roto(self):
        """Guarda contra volver a escribir `emb.EMOJI_*` para algo que no está ahí."""
        import pathlib
        import re
        import sys

        from ui import embed as emb_mod

        raiz = pathlib.Path(__file__).resolve().parent.parent
        fuente = (raiz / "ui" / "panel.py").read_text(encoding="utf-8")

        rotos = set()
        for nombre in set(re.findall(r"emb\.(EMOJI_[A-Z_]+)", fuente)):
            if not hasattr(emb_mod, nombre):
                rotos.add(nombre)
        assert not rotos, (
            f"panel.py usa emb.{sorted(rotos)[0]}... y ui.embed no lo expone. "
            "Los emojis viven en core.config."
        )
