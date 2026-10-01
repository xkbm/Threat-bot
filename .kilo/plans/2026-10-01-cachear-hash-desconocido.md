# Cachear el "VirusTotal no conoce este archivo"

## Contexto

Del log de producción del 19:27, al publicar una imagen:

```
19:27:34 db: SQLITE MISS → clave=imgmal:077d18ed999c236c...
19:27:34 virustotal: VT HASH NUEVO → 077d18ed999c236c...
19:27:35 db: SQLITE MISS → clave=imgmal:077d18ed999c236c...   ← el mismo hash
19:27:35 virustotal: VT HASH NUEVO → 077d18ed999c236c...     ← otra request
```

Dos consultas a VirusTotal con el mismo hash en un segundo, las dos "nuevo" (404), y
**ninguna se cachea**. La próxima vez que alguien republica esa misma imagen, el bot
vuelve a pagar la request.

Es el mismo fallo que ya se corrigió para SightEngine ("los fallos no se cachean") pero en
la ruta de malware de imágenes, que se añadió después y se quedó sin el arreglo.

Con el plan gratuito son 500 requests/día de VT, así que una imagen que se repite en la
comunidad drena cuota sin aportar nada. El caso es peor con el "hash nuevo" que con un
404 de red, porque es determinista: el mismo archivo siempre da 404.

## Tarea

### 1. Cachear el resultado negativo

`ui/message_handler.py`, en `_reputacion_de_imagen` (línea ~324). Hoy, cuando
`reputacion_hash` devuelve `"desconocido"`, se hace `return "no_consultado"` sin guardar
nada. Hay que guardarlo con caducidad corta:

```python
    veredicto, detecciones, vt_link, top = await reputacion_hash(content_hash)
    if veredicto == "desconocido":
        # VT no conoce este archivo. Es determinista: mientras nadie lo suba, volverá a
        # decir 404. Sin cachearlo, cada reaparición de la misma imagen gasta una request
        # de la cuota gratuita para volver a aprender lo mismo.
        await guardar_analisis_db(clave, TIPO_HASH_DESCONOCIDO, "desconocido")
        return "no_consultado", 0, None, None
    if veredicto in ("sin_cuota", "error"):
        # estos NO se cachean: son transitorios y volver a preguntar tiene sentido
        return "no_consultado", 0, None, None
```

`sus_cuota`/`error` se dejan sin cachear a propósito: se acaban cuando la cuota se
resetea o la red vuelve, y cachearlos dejaría al bot sin comprobar imágenes de forma
permanente por un fallo pasajero.

### 2. Darle caducidad propia

`core/config.py`, en `EXPIRACION`. La clave nueva necesita vida corta, no los 30 días
de un veredicto: si alguien sube el archivo a VT dentro de ese mes, lo queremos saber.

```python
EXPIRACION: dict[str, int] = {
    ...
    # "VT todavía no ha visto este archivo". Caducidad corta a propósito: el resultado
    # es determinista mientras nadie lo suba, pero en cuanto lo suban ya sí hay algo que
    # mirar. El compromiso es 1 request por imagen y día como máximo, a cambio de
    # poder retrasar como mucho un día la detección de un archivo que otro suba.
    "imgmal_desconocido": 24 * 3600,
}
```

`obtener_analisis_db` ya respeta la columna `expira` (línea 267), así que no hay que
tocar nada más: la entrada desaparece sola y el siguiente repost vuelve a preguntar.

Definir la constante en `ui/message_handler.py` (o `core/config.py`) como
`TIPO_HASH_DESCONOCIDO = "imgmal_desconocido"`, junto a la clave `imgmal:` que ya se usa,
para que las dos rutas sean legibles juntas.

### 3. Tests

`tests/test_features_nuevas.py` o un fichero nuevo, con `_reputacion_de_imagen` fakes:

- Un 404 se cachea: dos llamadas seguidas al mismo hash hacen **una** sola
  `reputacion_hash`.
- `"sin_cuota"` **no** se cachea: dos llamadas seguidas hacen dos requests.
- `"error"` **no** se cachea, por el mismo motivo.
- Un veredicto real (`malicious`/`sospechoso`) se cachea con su caducidad normal de 30
  días.
- La entrada expirada vuelve a preguntar: con el reloj avanzado 24 h+, el mismo hash se
  consulta de nuevo.

Ese último es el que fija la caducidad corta; sin él, alguien subiría el TTL a 30 días
sin darse cuenta de que retrasa la detección.

## Fuera de alcance

- **Los `429 We are being rate limited` que aparecen en el log.** Son de las reacciones
  de Discord, no de las APIs: el bot añade y quita el emoji de progreso en cada mensaje
  y Discord limita eso por canal. Discord.py reintenta solo y el análisis termina bien.
  Reducirlo significa tocar el diseño de las reacciones, no un bug.
- **Los tres procesamientos del mismo mensaje.** `_marcar_procesado` incluye los
  adjuntos en la huella y tiene TTL de 1 hora, así que un reprocesamiento del mismo
  `message.id` se omitiría (saldría "sin cambios, se omite el re-análisis", que no
  aparece en el log). Lo más probable es que fueran mensajes distintos con la misma
  imagen, que es el caso normal y el que este arreglo mejora. Si el usuario confirma que
  fue una sola edición, hay que mirarlo aparte.

## Verificación

```bash
python3 -m pytest tests -q
python3 -m ruff check .
```

Y en producción, republicar dos veces la misma imagen y comprobar en el log que la
segunda vez **no** aparece `VT HASH NUEVO`, sino un acierto de caché.
