import asyncio
import pytest
from core.guild_config import _get_guild_lock, remove_guild_lock, _guild_locks


@pytest.fixture(autouse=True)
def clear_locks():
    _guild_locks.clear()
    yield
    _guild_locks.clear()


@pytest.mark.asyncio
async def test_get_guild_lock_creates():
    lock = await _get_guild_lock(123456)
    assert isinstance(lock, asyncio.Lock)
    assert 123456 in _guild_locks


@pytest.mark.asyncio
async def test_get_guild_lock_reuses():
    lock1 = await _get_guild_lock(123456)
    lock2 = await _get_guild_lock(123456)
    assert lock1 is lock2


@pytest.mark.asyncio
async def test_get_guild_lock_different_guilds():
    lock1 = await _get_guild_lock(111)
    lock2 = await _get_guild_lock(222)
    assert lock1 is not lock2


@pytest.mark.asyncio
async def test_remove_guild_lock():
    await _get_guild_lock(333)
    assert 333 in _guild_locks
    await remove_guild_lock(333)
    assert 333 not in _guild_locks


@pytest.mark.asyncio
async def test_remove_guild_lock_nonexistent():
    await remove_guild_lock(999)
    assert 999 not in _guild_locks


@pytest.mark.asyncio
async def test_concurrent_creation():
    async def create_lock(gid):
        return await _get_guild_lock(gid)

    results = await asyncio.gather(*[create_lock(444) for _ in range(10)])
    assert all(r is results[0] for r in results)
    assert len(_guild_locks) == 1
