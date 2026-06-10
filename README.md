<p align="center">
  <img src="landing/public/favicon.png" alt="Threat" width="80" />
</p>

<h1 align="center">Threat</h1>

<p align="center">Bot de seguridad para Discord que escanea URLs, archivos, imágenes y más automáticamente.</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/discord.py-2.3+-7289DA?style=for-the-badge&logo=discord&logoColor=white" alt="discord.py" />
  <img src="https://img.shields.io/badge/Licencia-AGPL--3.0-blue?style=for-the-badge" alt="Licencia" />
</p>

---

## Características

### Análisis automático

| Tipo | Qué hace |
|------|----------|
| **URLs** | Expande acortadores y escanea con VirusTotal |
| **Archivos** | Detecta malware (hasta 32MB) |
| **Imágenes** | Detección NSFW — nudity, weapons, alcohol, offensive |
| **Hashes** | Verificación directa de SHA256/MD5 |
| **IPs** | Análisis de reputación |

### Protección activa

| Feature | Descripción |
|---------|-------------|
| **Modo estricto** | Elimina mensajes peligrosos automáticamente |
| **Modo silencioso** | Notifica solo en el canal de logs |
| **Whitelist** | Dominios seguros que configurás por servidor |
| **Anti-spam** | 30 análisis/hora por usuario, cooldown de 10s |

---

## Comandos

| Comando | Descripción |
|---------|-------------|
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

---

## Logs

Cuando el bot detecta una amenaza, envía un embed al canal configurado con toda la info: qué detectó, cuántos motores lo marcaron, y botones para **Ban**, **Kick** o **Ignore**. Todo en tiempo real.

---

## Licencia

[GNU Affero General Public License v3.0](LICENSE)

---

<p align="center">
  <a href="https://discord.com/oauth2/authorize?client_id=1038186932456390726&permissions=277025745990&scope=bot+applications.commands">
    <img src="https://img.shields.io/badge/Añadir_a_Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Añadir a Discord" />
  </a>
  <a href="https://threat-bot-discord.vercel.app">
    <img src="https://img.shields.io/badge/Sitio_web-white?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Sitio web" />
  </a>
</p>
