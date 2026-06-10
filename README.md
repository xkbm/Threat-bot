<img src="landing/public/favicon.png" alt="Threat" width="40" /> **Threat**

Bot de seguridad para Discord que escanea URLs, archivos, imágenes y más automáticamente.

`Python 3.10+` · `discord.py ≥2.3.0` · `AGPL-3.0`

---

## Características

- **URLs** → expande acortadores, escanea con VirusTotal
- **Archivos** → detecta malware (hasta 32MB)
- **Imágenes** → detección NSFW (nudity, weapons, alcohol, offensive)
- **Hashes** → verificación directa de SHA256/MD5
- **IPs** → análisis de reputación
- **Modo estricto** → elimina mensajes peligrosos automáticamente
- **Modo silencioso** → notifica solo en el canal de logs
- **Whitelist** → dominios seguros que configurás por servidor
- **Anti-spam** → 30 análisis/hora por usuario, cooldown de 10s

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

## Licencia

[GNU Affero General Public License v3.0](LICENSE)

---

[Añadir a Discord](https://discord.com/oauth2/authorize?client_id=1038186932456390726&permissions=277025745990&scope=bot+applications.commands) · [Sitio web](https://threat-bot-discord.vercel.app)
