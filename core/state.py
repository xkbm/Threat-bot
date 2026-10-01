import asyncio
from typing import Optional
from discord.ext import commands

bot: Optional[commands.Bot] = None

# Acota la concurrencia de peticiones HTTP *reales* a las APIs externas.
#
# Antes envolvía la llamada completa a `analizar_url` y `analizar_archivo`, que
# duermen 55s entre sondeos de VirusTotal. Sostener un hueco durante el sueño
# bloqueaba el análisis del resto del bot: bastaban ~20 URLs nuevas simultáneas para
# agotar el pool y dejarlo todo parado un par de minutos. Ahora solo envuelve
# operaciones que resuelven en una petición, como el análisis de imagen.
#
# El límite de verdad en VirusTotal lo impone `adquirir_vt()` (4 req/min y 500
# req/día por key), que es el que la API hace cumplir.
ANALYSIS_SEMAPHORE = asyncio.Semaphore(20)
