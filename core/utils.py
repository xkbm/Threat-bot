import re
import asyncio
import socket
import ipaddress
import discord
import urllib.parse
import logging
from core.config import EMOJI_LOADING, ANTIVIRUS_CONOCIDOS

log = logging.getLogger("utils")

async def safe_remove_loading(bot, msg):
    try:
        await msg.remove_reaction(EMOJI_LOADING, bot.user)
    except discord.NotFound:
        pass

async def safe_add_reaction(msg, emoji):
    try:
        await msg.add_reaction(emoji)
    except (discord.NotFound, discord.Forbidden):
        pass

async def safe_send(msg, embed, reference=None):
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

def dominio_en_whitelist(dominio: str, whitelist: list) -> bool:
    dominio = dominio.lower().strip()
    for d in whitelist:
        d = d.lower().strip()
        if dominio == d or dominio.endswith("." + d):
            return True
    return False

def es_imagen(archivo: discord.Attachment) -> bool:
    extensiones = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic', '.heif']
    if any(archivo.filename.lower().endswith(ext) for ext in extensiones):
        return True
    if archivo.content_type and archivo.content_type.startswith('image/'):
        return True
    return False

def url_es_imagen(url: str) -> bool:
    ruta = url.split('?')[0]
    return any(ruta.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic', '.heif'])

def obtener_top_antivirus(results):
    detectados = []
    for antivirus in ANTIVIRUS_CONOCIDOS:
        for key, value in results.items():
            if antivirus.lower() in key.lower() and value.get("category") == "malicious":
                detectados.append(key)
                break
        if len(detectados) >= 3:
            break
    return detectados

def barra_porcentaje(porcentaje, longitud=10):
    lleno = int(round(longitud * (porcentaje / 100)))
    vacio = longitud - lleno
    return "█" * lleno + "░" * vacio

async def _resolve_url(url: str) -> tuple:
    """Resuelve DNS en una sola llamada y verifica que no haya IPs privadas.
    Retorna (segura, hostname, ip, mensaje_error)."""
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
        addrs = await asyncio.to_thread(socket.getaddrinfo, hostname, 80, type=socket.SOCK_STREAM)
        ips = []
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
        return True, hostname, ips[0], ""
    except Exception as e:
        return False, "", "", f"Error verificando URL: {e}"

async def es_url_segura(url: str) -> tuple:
    segura, _, _, err = await _resolve_url(url)
    return segura, err

async def expandir_url(bot, url):
    try:
        for _ in range(5):
            segura, hostname, ip, err = await _resolve_url(url)
            if not segura:
                return url
            parsed = urllib.parse.urlparse(url)
            port_part = f":{parsed.port}" if parsed.port else ""
            url_ip = urllib.parse.urlunparse(parsed._replace(netloc=f"{ip}{port_part}"))
            headers = {"Host": hostname}
            async with bot.session.head(url_ip, allow_redirects=False, headers=headers) as resp:
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

async def descargar_url_segura(bot, url, max_size=None):
    """Resuelve DNS, verifica IP y descarga en un solo paso atómico."""
    segura, hostname, ip, err = await _resolve_url(url)
    if not segura:
        return None, err
    parsed = urllib.parse.urlparse(url)
    port_part = f":{parsed.port}" if parsed.port else ""
    url_ip = urllib.parse.urlunparse(parsed._replace(netloc=f"{ip}{port_part}"))
    headers = {"Host": hostname}
    try:
        async with bot.session.get(url_ip, headers=headers) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            if max_size:
                cl = resp.headers.get('Content-Length')
                if cl and int(cl) > max_size:
                    return None, "too_large"
                data = await resp.read()
                if len(data) > max_size:
                    return None, "too_large"
                return data, None
            return await resp.read(), None
    except Exception as e:
        return None, str(e)

PATRON_HASH = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')

def es_hash_valido(valor: str) -> bool:
    return bool(PATRON_HASH.match(valor.strip()))

def tiene_doble_extension(filename):
    partes = filename.rsplit('.', 2)
    return len(partes) == 3 and partes[1].lower() in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'pdf', 'doc', 'xls']
