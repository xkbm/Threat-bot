<p align="center">
  <img src="landing/public/favicon.png" alt="Threat" width="120" />
</p>

<h1 align="center">Threat</h1>

<p align="center">Bot de seguridad para Discord que escanea URLs, archivos, imágenes y más — automáticamente.</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python" />
  <img src="https://img.shields.io/badge/discord.py-%E2%89%A52.3.0-purple.svg" alt="Discord.py" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" />
</p>

---

## Qué hace

Threat vigila tu servidor y detecta cosas malas antes de que se propaguen. Cuando alguien pega un link sospechoso, manda un archivo o comparte una imagen, el bot lo analiza al instante usando VirusTotal y SightEngine.

Si encuentra algo peligroso, avisa. Si activas el modo estricto, elimina el mensaje solo.

## Características

**Análisis automático**
- URLs → expande acortadores, escanea con VirusTotal
- Archivos adjuntos → detecta malware (hasta 32MB)
- Imágenes → detección NSFW (nudity, weapons, alcohol, offensive)
- Hashes → verificación directa de SHA256/MD5
- IPs → análisis de reputación

**Protección activa**
- Modo estricto → elimina mensajes peligrosos automáticamente
- Modo silencioso → notifica solo en el canal de logs
- Whitelist → dominios seguros que configurás por servidor
- Anti-spam → 30 análisis/hora por usuario, cooldown de 10s
- Protección SSRF → valida IPs antes de descargar

## Comandos

| Comando | Qué hace |
|---------|----------|
| `/scan` | Escanea una URL, archivo, hash o IP |
| `/autoscan` | Activa/desactiva el escaneo automático |
| `/silentmode` | Modo silencioso |
| `/strictmode` | Modo estricto (elimina amenazas) |
| `/setlogchannel` | Canal donde se envían los logs |
| `/whitelist` | Dominios que el bot ignora |
| `/usercheck` | Reputación de un usuario |
| `/stats` | Estadísticas globales |
| `/settings` | Configuración del servidor |
| `/help` | Lista de comandos |
| `/about` | Info del bot |

## Logs

Cuando el bot detecta una amenaza, envía un embed al canal configurado con toda la info: qué detectó, cuántos motores lo marcaron, y botones para **Ban**, **Kick** o **Ignore**. Todo en tiempo real.

## Instalación

Necesitás:
- Python 3.10+
- Token de bot de Discord
- API keys de VirusTotal y SightEngine

```bash
git clone <repository-url>
cd threat-bot
pip install -r requirements.txt
```

Creá un archivo `.env` en la raíz:

```env
DISCORD_TOKEN=tu_token_de_discord
OWNER_ID=tu_id_de_usuario

VT_API_KEY=tu_primera_key
# VT_API_KEY_2=segunda_key_opcional
# VT_API_KEY_3=tercera_key_opcional

SIGHTENGINE_API_USER=tu_usuario
SIGHTENGINE_API_KEY=tu_key
# SIGHTENGINE_API_USER_2=usuario2
# SIGHTENGINE_API_KEY_2=key2
```

Y listo:

```bash
python bot.py
```

## Estructura

```
threat-bot/
├── bot.py                 # Entry point
├── api/
│   ├── virustotal.py      # VirusTotal (rotación de keys)
│   └── sightengine.py     # SightEngine (NSFW)
├── cogs/                  # Comandos
│   ├── analisis.py        # /scan
│   ├── configuracion.py   # Config del servidor
│   ├── whitelist.py       # Whitelist
│   ├── stats.py           # Estadísticas
│   ├── help.py            # Ayuda
│   ├── about.py           # Info
│   ├── rep.py             # /usercheck
│   ├── eval.py            # Owner only
│   └── reboot.py          # Reinicio
├── core/
│   ├── config.py          # Configuración global
│   ├── database.py        # Pool SQLite
│   ├── cache.py           # Caché RAM con TTL
│   ├── utils.py           # Utilidades (SSRF, DNS)
│   ├── state.py           # Estado global
│   └── guild_config.py    # Config por servidor
├── ui/
│   ├── message_handler.py # Pipeline de análisis
│   └── views.py           # Botones interactivos
└── data/                  # Datos generados
    ├── analisis.db        # Caché SQLite
    └── data.json          # Config de servidores
```

## Configuración

**Límites:**
- VirusTotal: 500 req/día por key, hasta 3 keys en rotación
- SightEngine: hasta 3 pares de credenciales
- Archivos: 32MB (VT), 2MB (SightEngine)
- Concurrencia: 20 análisis simultáneos
- Caché RAM: 100k entradas, TTL de 1 hora

**Caché:**

| Tipo | Expira en |
|------|-----------|
| URLs | 7 días |
| IPs | 7 días |
| Hashes | 30 días |
| Archivos | 30 días |
| NSFW | 30 días |

**Dominios protegidos** (no se pueden quitar de la whitelist): youtube.com, github.com, discord.com, microsoft.com, y otros más.

## Seguridad

**SSRF:** Resuelve DNS manualmente, verifica que la IP no sea privada/loopback, y descarga por IP con el header `Host` original.

**Anti-spam:** 30 análisis/hora por usuario, cooldown de 10 segundos, tracking persistente.

**Permisos que necesita el bot:** Leer/enviar mensajes, gestionar mensajes (modo estricto), ban/kick (botones de log), embed links, adjuntar archivos.

## Uso rápido

```
/scan url: https://ejemplo.com/archivo.exe
/scan file: [adjuntar archivo]
/scan hash: 44d88612fea8a8f36de82e1278abb02f
/scan ip: 8.8.8.8
```

Después de invitar al bot:
1. `/setlogchannel #canal` — para que avise ahí
2. `/strictmode true` — si querés que elimine mensajes peligrosos
3. `/whitelist add ejemplo.com` — para que ignore dominios seguros

## Licencia

MIT. Ver [LICENSE](LICENSE).

---

Hecho para que las comunidades de Discord duerman un poco más tranquilas.
