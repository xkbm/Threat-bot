--- README.md (原始)
# Threat-bot-

+++ README.md (修改后)
# Threat-bot 🛡️

Bot de Discord para análisis de seguridad que detecta automáticamente malware, URLs maliciosas y contenido NSFW usando VirusTotal y SightEngine.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Discord.py](https://img.shields.io/badge/discord.py-%E2%89%A52.3.0-purple.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## ✨ Características Principales

### 🔍 Análisis Automático
- **URLs**: Expande acortadores y escanea con VirusTotal
- **Archivos adjuntos**: Detecta malware (hasta 32MB)
- **Imágenes**: Detección NSFW con SightEngine (nudity, weapons, alcohol, offensive)
- **Hashes**: Verificación directa de SHA256/MD5
- **IPs**: Análisis de reputación

### 🛡️ Protección Activa
- **Modo estricto**: Elimina automáticamente mensajes peligrosos
- **Modo silencioso**: Suprime notificaciones públicas
- **Whitelist**: Dominios seguros configurables por servidor
- **Anti-spam**: Límite de 30 análisis/hora por usuario
- **Protección SSRF**: Validación de IPs privadas en descargas

### 📊 Comandos Disponibles

| Comando | Descripción |
|---------|-------------|
| `/scan` | Escanea URL, archivo, hash o IP (cooldown 30s) |
| `/silentmode` | Activa modo silencioso |
| `/strictmode` | Activa modo estricto (elimina amenazas) |
| `/setlogchannel` | Configura canal de logs |
| `/whitelist` | Gestiona dominios permitidos |
| `/usercheck` | Verifica reputación de usuario |
| `/stats` | Muestra estadísticas del bot |
| `/settings` | Configuración del servidor |
| `/help` | Muestra ayuda completa |
| `/about` | Información del bot |

### 🔔 Sistema de Logs
- Alertas en tiempo real con embeds detallados
- Botones de acción: **Ban**, **Kick**, **Ignore**
- Registro de infracciones por usuario
- Estadísticas globales y por servidor

## 🚀 Instalación

### Requisitos Previos
- Python 3.10 o superior
- Token de bot de Discord
- API keys de VirusTotal y SightEngine

### Pasos de Instalación

1. **Clonar el repositorio**
```bash
git clone <repository-url>
cd threat-bot
```

2. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

3. **Configurar variables de entorno**

Crear un archivo `.env` en la raíz del proyecto:

```env
# Discord
DISCORD_TOKEN=tu_token_de_discord
OWNER_ID=tu_id_de_usuario

# VirusTotal (hasta 3 keys rotativas)
VT_API_KEY=tu_primera_key
# VT_API_KEY_2=segunda_key_opcional
# VT_API_KEY_3=tercera_key_opcional

# SightEngine (hasta 3 pares rotativos)
SIGHTENGINE_API_USER=tu_usuario
SIGHTENGINE_API_KEY=tu_key
# SIGHTENGINE_API_USER_2=usuario2
# SIGHTENGINE_API_KEY_2=key2
```

4. **Ejecutar el bot**
```bash
python bot.py
```

## 🏗️ Arquitectura del Proyecto

```
threat-bot/
├── bot.py                 # Entry point y configuración principal
├── requirements.txt       # Dependencias de Python
├── .env                   # Variables de entorno (no versionado)
│
├── api/                   # Integraciones con APIs externas
│   ├── virustotal.py      # Cliente VirusTotal (rotación de keys)
│   └── sightengine.py     # Cliente SightEngine (detección NSFW)
│
├── cogs/                  # Módulos de comandos
│   ├── analisis.py        # Comando /scan y lógica principal
│   ├── configuracion.py   # Comandos de configuración
│   ├── whitelist.py       # Gestión de whitelist
│   ├── stats.py           # Estadísticas
│   ├── help.py            # Sistema de ayuda
│   ├── about.py           # Información del bot
│   ├── rep.py             # Reputación de usuarios
│   ├── eval.py            # Comandos de owner (/eval, /reboot)
│   └── reboot.py          # Reinicio controlado
│
├── core/                  # Núcleo del sistema
│   ├── config.py          # Constantes y configuración global
│   ├── database.py        # Pool de conexiones SQLite
│   ├── cache.py           # Caché en RAM con TTL
│   ├── utils.py           # Funciones utilitarias (SSRF, DNS, etc.)
│   ├── state.py           # Estado global del bot
│   └── guild_config.py    # Persistencia de configuración por guild
│
├── ui/                    # Interfaz de usuario
│   ├── message_handler.py # Pipeline de análisis automático
│   └── views.py           # Vistas y botones interactivos
│
└── data/                  # Datos persistentes (generados)
    ├── analisis.db        # Caché SQLite de análisis
    └── data.json          # Configuración de servidores
```

## ⚙️ Configuración Avanzada

### Límites y Cuotas
- **VirusTotal**: 500 req/día por key, rotación automática hasta 3 keys
- **SightEngine**: Rotación de hasta 3 pares de credenciales
- **Archivos**: Máximo 32MB para VT, 2MB para SightEngine
- **Concurrencia**: 20 análisis simultáneos máximos
- **Caché RAM**: 100,000 entradas con TTL de 1 hora

### Tiempos de Expiración de Caché
| Tipo | Duración |
|------|----------|
| URLs | 7 días |
| IPs | 7 días |
| Hashes | 30 días |
| Archivos | 30 días |
| NSFW | 30 días |

### Dominios Protegidos
Los siguientes dominios están en whitelist por defecto y no pueden eliminarse:
- `youtube.com`, `github.com`, `discord.com`, `microsoft.com`, etc.

## 🔒 Seguridad

### Protección SSRF
El bot implementa validación estricta contra Server-Side Request Forgery:
1. Resolución DNS manual de hostnames
2. Verificación de IPs privadas/loopback
3. Descarga mediante IP con header `Host` original

### Anti-Spam
- 30 análisis por hora por usuario
- Cooldown de 10 segundos entre escaneos
- Tracking persistente de uso

### Permisos Requeridos
El bot necesita los siguientes permisos:
- Leer/enviar mensajes
- Gestionar mensajes (modo estricto)
- Ban/Kick miembros (botones de log)
- Embed links
- Adjuntar archivos

## 📝 Uso Típico

### Análisis Manual
```
/scan url: https://ejemplo.com/archivo.exe
/scan file: [adjuntar archivo]
/scan hash: 44d88612fea8a8f36de82e1278abb02f
/scan ip: 8.8.8.8
```

### Configuración Inicial
1. Invita el bot a tu servidor
2. Configura canal de logs: `/setlogchannel #canal`
3. (Opcional) Activa modo estricto: `/strictmode`
4. Añade dominios seguros: `/whitelist add ejemplo.com`

### Interpretación de Resultados

**🟢 Seguro**
```
✅ Resultado: Seguro
🔍 Motores: 0/89 detectaron amenazas
📊 Confianza: Alta
```

**🔴 Malicioso**
```
⚠️ Resultado: MALICIOSO
🦠 Detectado por: 15/89 motores
🏷️ Etiquetas: trojan, ransomware
🔗 Ver en VT: [enlace]
```

**🔞 NSFW**
```
⚠️ Contenido Inapropiado Detectado
📸 Modelos: nudity (92%), weapon (15%)
🎯 Confianza máxima: 92%
```

## 📊 Estadísticas

El bot mantiene estadísticas en tiempo real:
- Análisis totales por tipo (URL, archivo, hash, IP, NSFW)
- Amenazas detectadas
- Uso de APIs (VirusTotal, SightEngine)
- Infracciones por usuario
- Actividad por servidor

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:
1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

**Hecho con ❤️ para comunidades de Discord más seguras**
