# ARDREC P14-R38-R2 · Corrección visual del monitor

## Incidencia

Al seleccionar una etapa, la fila de navegación quedaba resaltada hasta el borde derecho de la terminal, atravesando los paneles DETALLE y ESTADO / AUDITORÍA. La causa era la aplicación de `curses.color_pair(3)` a toda la cadena de texto que contiene los tres paneles.

## Corrección

- Aplicar el atributo de selección **únicamente** a las columnas interiores del panel izquierdo (índices 1..31), preservando los bordes y otros paneles.
- Mantener títulos en cian, avisos de NO-GO en amarillo y usar blanco legible para el texto normal en terminales compatibles; no modificar las preferencias de transparencia de Konsole.
- Conservar navegación, búsqueda, filtro, vista compacta, `--texto`, `--json`, `--tui-clasica` y el contrato de solo lectura.
- Añadir dos pruebas que eviten la regresión del resaltado más allá del límite del panel.

## Alcance y verificación

Interfaz exclusivamente: sin cambios en A1-A10, reglas, estados, procedimientos, A6, persistencia, despacho, VM ni red. Datos importados siguen `ND`, `P8 NO-GO` y `Rf` final no acreditado.

Pruebas unitarias R38 después de la corrección: 21/21 PASS (aisladas). Prueba de arranque / navegación en pseudo-terminal de curses: terminación `0` con `q`. Suite P14 completa y CI: pendientes de ejecutar en el repositorio principal de Prometheus. Con un conjunto de pruebas sin otras modificaciones, el total P14 previsto pasa de 794 a 796.

Los efectos de transparencia del emulador de terminal son configurables fuera de ARDREC.
