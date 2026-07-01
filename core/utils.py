import re
import time
import asyncio
import socket
import ipaddress
from typing import Optional
import aiohttp
import discord
import urllib.parse
import logging
from collections import OrderedDict
from discord.ext import commands
from core.config import EMOJI_LOADING, ANTIVIRUS_CONOCIDOS, IMAGE_EXTENSIONS, VT_MAX_ANALYSES_PER_MINUTE

log = logging.getLogger("utils")
_dns_cache: OrderedDict[str, tuple[float, str]] = OrderedDict()
_DNS_CACHE_TTL: float = 300.0
_DNS_CACHE_MAX: int = 5000

async def safe_remove_loading(bot: commands.Bot, msg: discord.Message) -> None:
    try:
        await msg.remove_reaction(EMOJI_LOADING, bot.user)
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass

async def safe_add_reaction(msg: discord.Message, emoji: str) -> None:
    try:
        await msg.add_reaction(emoji)
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass

async def safe_send(msg: discord.Message, embed: discord.Embed, reference: Optional[discord.Message] = None) -> None:
    try:
        if reference:
            await msg.channel.send(embed=embed, reference=reference)
        else:
            await msg.channel.send(embed=embed)
    except (discord.NotFound, discord.Forbidden):
        pass
    except discord.HTTPException:
        try:
            await msg.channel.send(embed=embed)
        except (discord.HTTPException, discord.NotFound, discord.Forbidden):
            pass

def dominio_en_whitelist(dominio: str, whitelist: list[str]) -> bool:
    dominio = dominio.lower().strip()
    for d in whitelist:
        d = d.lower().strip()
        if dominio == d or dominio.endswith("." + d):
            return True
    return False

def es_imagen(archivo: discord.Attachment) -> bool:
    if any(archivo.filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
        return True
    if archivo.content_type and archivo.content_type.startswith('image/'):
        return True
    return False

async def url_es_imagen(url: str, bot: Optional[commands.Bot] = None) -> bool:
    ruta = url.split('?')[0]
    if any(ruta.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
        return True
    if bot is None:
        return False
    try:
        async with bot.session.head(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            ct = resp.headers.get('Content-Type', '')
            return ct.startswith('image/')
    except Exception:
        return False

def obtener_top_antivirus(results: dict) -> list[str]:
    detectados: list[str] = []
    for antivirus in ANTIVIRUS_CONOCIDOS:
        for key, value in results.items():
            if antivirus.lower() in key.lower() and value.get("category") == "malicious":
                detectados.append(key)
                break
        if len(detectados) >= 3:
            break
    return detectados

def barra_porcentaje(porcentaje: float, longitud: int = 10) -> str:
    lleno = int(round(longitud * (porcentaje / 100)))
    vacio = longitud - lleno
    return "█" * lleno + "░" * vacio

async def _resolve_url(url: str) -> tuple[bool, str, str, str]:
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "", "", "URL sin hostname"
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False, "", "", f"IP privada o local: {hostname}"
            return True, hostname, hostname, ""
        except ValueError:
            pass
        ahora = time.time()
        cached = _dns_cache.get(hostname)
        if cached and ahora < cached[0]:
            _dns_cache.move_to_end(hostname)
            return True, hostname, cached[1], ""
        addrs = await asyncio.get_running_loop().getaddrinfo(hostname, 80, type=socket.SOCK_STREAM)
        ips: list[str] = []
        for addr in addrs:
            ip_str = addr[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return False, "", "", f"El hostname {hostname} resuelve a IP privada: {ip_str}"
                ips.append(ip_str)
            except ValueError:
                continue
        if not ips:
            return False, "", "", f"No se pudo resolver {hostname}"
        _dns_cache[hostname] = (ahora + _DNS_CACHE_TTL, ips[0])
        _dns_cache.move_to_end(hostname)
        while len(_dns_cache) > _DNS_CACHE_MAX:
            _dns_cache.popitem(last=False)
        return True, hostname, ips[0], ""
    except Exception as e:
        return False, "", "", f"Error verificando URL: {e}"

async def es_url_segura(url: str) -> tuple[bool, str]:
    segura, _, _, err = await _resolve_url(url)
    return segura, err

def normalizar_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.netloc or "").lower()
    if ":80" in hostname and scheme == "http":
        hostname = hostname[:-3]
    elif ":443" in hostname and scheme == "https":
        hostname = hostname[:-4]
    path = parsed.path.rstrip("/") or "/"
    return urllib.parse.urlunparse((scheme, hostname, path, parsed.params, parsed.query, ""))

async def expandir_url(bot: commands.Bot, url: str) -> str:
    try:
        for _ in range(5):
            segura, hostname, ip, err = await _resolve_url(url)
            if not segura:
                return url
            parsed = urllib.parse.urlparse(url)
            port_part = f":{parsed.port}" if parsed.port else ""
            ip_netloc = f"[{ip}]{port_part}" if ":" in ip else f"{ip}{port_part}"
            url_ip = urllib.parse.urlunparse(parsed._replace(netloc=ip_netloc))
            headers = {"Host": hostname}
            async with bot.session.head(url_ip, allow_redirects=False, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location')
                    if location:
                        url = urllib.parse.urljoin(url, location)
                    else:
                        break
                else:
                    break
    except Exception as e:
        log.error(f"Error expandiendo URL {url}: {e}")
    return url

async def descargar_url_segura(bot: commands.Bot, url: str, max_size: Optional[int] = None) -> tuple[Optional[bytes], Optional[str]]:
    segura, hostname, ip, err = await _resolve_url(url)
    if not segura:
        return None, err
    parsed = urllib.parse.urlparse(url)
    port_part = f":{parsed.port}" if parsed.port else ""
    ip_netloc = f"[{ip}]{port_part}" if ":" in ip else f"{ip}{port_part}"
    url_ip = urllib.parse.urlunparse(parsed._replace(netloc=ip_netloc))
    headers = {"Host": hostname}
    try:
        async with bot.session.get(url_ip, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            if max_size:
                cl = resp.headers.get('Content-Length')
                if cl:
                    try:
                        if int(cl) > max_size:
                            return None, "too_large"
                    except ValueError:
                        pass  # Content-Length malformado, ignorar
                data = await resp.read()
                if len(data) > max_size:
                    return None, "too_large"
                return data, None
            return await resp.read(), None
    except Exception as e:
        return None, str(e)

PATRON_HASH: re.Pattern = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')

def es_hash_valido(valor: str) -> bool:
    return bool(PATRON_HASH.match(valor.strip()))

def tiene_doble_extension(filename: str) -> bool:
    partes = filename.rsplit('.', 2)
    return len(partes) == 3 and partes[1].lower() in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'pdf', 'doc', 'xls', 'exe', 'vbs', 'ps1', 'bat', 'cmd', 'msi', 'scr', 'lnk', 'com', 'gadget', 'docx', 'xlsx', 'ppt', 'pptx', 'jar', 'py']

import random as _random

REVIEW_PROMPT_URL = "https://top.gg/bot/1038186932456390726#reviews"
REVIEW_PROMPT_CHANCE = 0.05

async def maybe_send_review_prompt(bot, channel: discord.abc.Messageable) -> None:
    if _random.random() >= REVIEW_PROMPT_CHANCE:
        return
    embed = discord.Embed(
        description=(
            "Si te gusta Threat, ¡considera [dejar una reseña en Top.gg]"
            f"({REVIEW_PROMPT_URL})!"
        ),
        color=discord.Color(0xff3366)
    )
    try:
        await channel.send(embed=embed)
    except Exception:
        pass

async def check_vt_user_limit(user_id: int) -> bool:
    from core import state
    ahora = time.time()
    history = state.bot.vt_user_requests.setdefault(user_id, [])
    state.bot.vt_user_requests[user_id] = [t for t in history if ahora - t < 60]
    if len(state.bot.vt_user_requests[user_id]) >= VT_MAX_ANALYSES_PER_MINUTE:
        return False
    state.bot.vt_user_requests[user_id].append(ahora)
    return True
