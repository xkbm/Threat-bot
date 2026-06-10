# Threat

Bot de seguridad para Discord que escanea URLs, archivos, imágenes y más — automáticamente. Usa VirusTotal y SightEngine para detectar malware, phishing y contenido NSFW antes de que se propague en tu servidor.

<img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python" />
<img src="https://img.shields.io/badge/discord.py-%E2%89%A52.3.0-purple.svg" alt="Discord.py" />
<img src="https://img.shields.io/badge/Licencia-AGPL--3.0-blue.svg" alt="Licencia" />

---

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

---

## Licencia

Este proyecto está licenciado bajo [GNU Affero General Public License v3.0](LICENSE).

---

<p align="center">
  <a href="https://discord.com/oauth2/authorize?client_id=1038186932456390726&permissions=277025745990&scope=bot+applications.commands">Añadir Threat a tu servidor</a> · 
  <a href="https://threat-bot-discord.vercel.app">Sitio web</a>
</p>
