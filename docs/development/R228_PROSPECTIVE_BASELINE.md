# R228 - Preparacion prospectiva I2

## Alcance / Scope

Reutiliza R148, R149 y R199 para preparar evaluaciones
iniciales vinculadas a identidades experimentales.

No crea un registro experimental paralelo.
No convierte documentos en autorizaciones operacionales.

## Consulta de posiciones

python -m ardrec estudio --registro REGISTRO \
    --seleccion SELECCION --preparar-i2 --texto

## Calculo documental de una unidad seleccionada

python -m ardrec estudio --registro REGISTRO \
    --seleccion SELECCION --preparar-i2 \
    --entrada-i2 ENTRADA_JSON \
    --soportes-i2 DIRECTORIO_PRIVADO --json

La entrada JSON canonica contiene:

- slot_id
- selection_sha256
- configuration_sha256
- ratings

Cada valoracion ordinal contiene ordinal, support_sha256
y justification. Los soportes se proporcionan como archivos
privados SHA256.bin, vinculados al contenido original.

Se comprueban los seis ordinales de R199, la escala
del comparador estatico, la identidad y la integridad
de las referencias documentales.

Un hash valido no acredita suficiencia semantica,
autorizacion, cronologia previa ni estado fisico.

## Boundary / Frontera

No hay congelamiento operacional, despacho, admision A6,
publicacion A9 ni admision experimental.

P7=DRAFT_NOT_FROZEN.
P8=NO-GO.
