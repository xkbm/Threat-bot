import asyncio
from typing import Optional
from discord.ext import commands

bot: Optional[commands.Bot] = None
ANALYSIS_SEMAPHORE = asyncio.Semaphore(20)
