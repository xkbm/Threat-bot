# Contribuir a Threat

Gracias por tu interés en contribuir a Threat.

## Reportar errores

Para reportar un error, abrir un [issue](https://github.com/xkbm/Threat-bot/issues) con:

- Descripción clara del problema
- Pasos para reproducir
- Comportamiento esperado vs actual
- Fecha en que se detectó el problema

## Proponer mejoras

Abrir un issue con la etiqueta `enhancement` describiendo:

- Qué problema resuelve
- Cómo se imagina la solución
- Alternativas consideradas

## Enviar código

1. Hacer fork del repositorio
2. Crear una rama (`git checkout -b feature/nombre`)
3. Hacer las modificaciones
4. Verificar que pasan `python -m compileall .`, `ruff check .` y `python -m pytest tests -q`
5. Abrir un Pull Request describiendo el cambio

## Licencia

Al contribuir, el código se licencia bajo [AGPL-3.0](LICENSE).
