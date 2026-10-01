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
| **Hashes** | Verificación directa de SHA256/MD5, por `/scan` o el menú contextual |
| **IPs** | Análisis de reputación, por `/scan` |
| **Nombres sospechosos** | Doble extensión (`.pdf.exe`) y extensión que no cuadra con el contenido |

Cada adjunto se clasifica por sus **bytes iniciales**, no por su extensión: un
`malware.png` que en realidad es un ejecutable va a VirusTotal, no a la revisión de
contenido. La extensión solo sirve como pista para no descargar de más.

### Veredictos

| Veredicto | Qué significa | ¿Borra en modo estricto? |
|-----------|---------------|---------------------------|
| `seguro` | Nada detectado | no |
| `sospechoso` | Señal débil, sin confirmar | no |
| `restringido` | Alcohol, armas | **no**, avisa y queda registrado |
| `nsfw` | Desnudez, gore, ofensivo | sí |
| `malicioso` | Malware confirmado | sí |
| `phishing` | Suplantación de marca (local, sin gastar cuota) | no |
| `error` | **No se pudo comprobar**: sin cuota, fallo o tamaño | no |

`restringido` existe porque antes el alcohol compartía veredicto y borrado con la
pornografía, y una foto de una cerveza acababa borrada en modo estricto.

**Un elemento que no se pudo comprobar es `error`, nunca `seguro`.** Si falta cuota o la
API falla, el bot lo dice; no afirma estar limpio de algo que nunca miró.

### Protección activa

| Feature | Descripción |
|---------|-------------|
| **Modo estricto** | Elimina mensajes peligrosos automáticamente |
| **Modo silencioso** | Con él activo solo se avisa si hay algo que mirar |
| **Whitelist** | Dominios seguros que configurás por servidor |
| **Anti-spam** | 30 análisis/hora por usuario, cooldown de 10s |
| **Veredicto "sospechoso"** | Los enlaces que VirusTotal marca como *suspicious* pero sin confirmar se informan en ámbar: no se borran ni cuentan como infracción, porque no hay certeza |
| **Anti-phishing** | Detecta `rnicrosoft.com`, `steamcomunnity.ru` o `discord.com.evil.io`. Comprobación local de texto: no gasta cuota y filtra antes de llamar a VirusTotal |
| **Panel `/settings`** | Todos los ajustes en un panel con botones y desplegables, recorrido desde un esquema declarado |
| **Menú contextual** | Clic derecho sobre cualquier mensaje para analizarlo sin copiar la URL |
| **`/history`** | Últimos análisis de un canal. Ahora sí queda registro de qué se escaneó |
| **Una sola reacción** | Cada mensaje lleva la de su peor resultado, no tres contradictorias |
| **Aviso en tres interruptores** | `avisar_limpios`, `avisar_sospechosos` y `avisar_errores` controlan por separado qué llega al canal. `silent_mode` queda como master, y los defaults reproducen el comportamiento anterior: al actualizar el bot no cambia lo que recibe ningún servidor |

`/usercheck` es el único comando restringido a moderadores: el expediente de seguridad de una
persona no es público.

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
| `/settings` | **Panel de configuración**: todo se ajusta ahí, sin comandos aparte |
| `/history` | Últimos análisis de un canal (mods) |
| `/help` | Lista de comandos |

Además, el menú contextual **"Analizar con Threat"** aparece al hacer clic derecho sobre
cualquier mensaje.

## Persistencia

La configuración de cada servidor, las infracciones y el registro de `/history` viven en
SQLite (`analisis.db`), no en un `data.json` reescrito entero. `data.json` se conserva
como respaldo y se migró solo la primera vez; si la migración falla, el bot arranca igual
con el JSON. Las infracciones se purgan a los 90 días y los eventos a los 30.
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
    <img src="https://img.shields.io/badge/Sitio_web-36393f?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Sitio web" />
  </a>
</p>
