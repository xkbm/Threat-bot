import time
import pytest
from unittest.mock import patch
from core.cache import get_from_cache_mem, set_cache_mem, _cache
import discord


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


@pytest.mark.asyncio
async def test_cache_miss():
    tipo, embed, mal = await get_from_cache_mem("nonexistent")
    assert tipo is None
    assert mal == 0


@pytest.mark.asyncio
async def test_cache_hit():
    embed = discord.Embed(title="test")
    await set_cache_mem("key1", "seguro", embed, 0)
    tipo, result_embed, mal = await get_from_cache_mem("key1")
    assert tipo == "seguro"
    assert mal == 0
    assert result_embed.title == "test"


@pytest.mark.asyncio
async def test_cache_expiry():
    embed = discord.Embed(title="test")
    await set_cache_mem("key2", "seguro", embed, 0)
    with patch("core.cache.time") as mock_time:
        mock_time.time.return_value = time.time() + 7200
        tipo, _, mal = await get_from_cache_mem("key2")
        assert tipo is None
        assert mal == 0


@pytest.mark.asyncio
async def test_cache_overwrite():
    embed1 = discord.Embed(title="first")
    embed2 = discord.Embed(title="second")
    await set_cache_mem("key3", "seguro", embed1, 0)
    await set_cache_mem("key3", "malicioso", embed2, 5)
    tipo, result_embed, mal = await get_from_cache_mem("key3")
    assert tipo == "malicioso"
    assert mal == 5
    assert result_embed.title == "second"


@pytest.mark.asyncio
async def test_cache_multiple_keys():
    embed = discord.Embed(title="test")
    await set_cache_mem("a", "seguro", embed, 0)
    await set_cache_mem("b", "malicioso", embed, 1)
    tipo_a, _, mal_a = await get_from_cache_mem("a")
    tipo_b, _, mal_b = await get_from_cache_mem("b")
    assert tipo_a == "seguro"
    assert mal_a == 0
    assert tipo_b == "malicioso"
    assert mal_b == 1
