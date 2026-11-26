# R307 — Coordinación de lotes DEV / DEV batch coordination

## Español

El coordinador documental existente incorpora `caso preparar-lote-dev` y
`caso reabrir-lote-dev`. Cada lote contiene de 1 a 54 casos DEV ya abiertos
mediante R302, con valoraciones R303 vinculadas a la huella del caso. No
se fabrican valoraciones ni soportes. Se reutilizan A1, R199/A2, el núcleo
exacto A7, el dictamen A8 y el archivo analítico nativo R304.

El operador proporciona un archivo `batch.json` canónico, privado 0600,
en un directorio 0700, con `schema` igual a `ARDREC-R307-DEV-BATCH-v1` y
`cases` (lista). Cada objeto tiene exactamente las claves de tipo cadena
`case_id`, `origin`, `scenario_pin`, `inputs`, `input_pin`. Los directorios
son absolutos, privados, sin alias ni solapamientos entre casos o con el
archivo común. Los identificadores deben ser únicos. Las huellas fijan
los bytes de `scenario.json` y `ratings.json`, respectivamente.

```
python -m ardrec caso preparar-lote-dev --manifiesto RUTA_BATCH \
  --sha256 HUELLA_BATCH --archivo ARCHIVO_COMUN --texto
python -m ardrec caso reabrir-lote-dev --manifiesto RUTA_BATCH \
  --sha256 HUELLA_BATCH --archivo ARCHIVO_COMUN --json
```

Se valida todo el manifiesto y la valoración de todos los casos antes de
escribir una valoración nueva. El núcleo A7 calcula el lote y sus filas
deben coincidir exactamente con las individuales. El coordinador almacena
las valoraciones y proyecciones nativas, recupera sus referencias y emite
un resultado canónico ordenado por ID. El modo reabrir exige los registros
existentes; no crea nuevas valoraciones ni proyecciones. Los resultados
iguales son reproducibles por bytes. No hay atomicidad de todo el lote:
si falla la escritura o cambia una fuente durante el procesamiento,
pueden quedar casos anteriores persistidos. Se conserva su integridad;
con entradas originales idénticas se puede recuperar y continuar, sin
sobrescribir. No se crea un segundo repositorio analítico.

No se reserva ni despacha intento alguno. A3=ND, A4 sin selección, A5=0,
A6=ND, Rf confirmado ND, sin transición A8 ni generación operacional A9.
El tamaño máximo de 54 es capacidad documental, no una observación ni
admisión experimental. No se enlazan diarios históricos con casos nuevos,
ni se cierra AL-06, AL-07, P7 o P8. P8 permanece NO-GO.

## English

The existing case coordinator prepares or reopens a pinned batch of 1–54
already-open DEV cases, with case-bound documentary ratings. It preflights
all inputs, compares native exact A7 batch rows with individual intervals,
persists existing R303/R304 records, and produces a deterministic report.
Reopen does not create assessments or snapshots. Writes are immutable per
case, not globally atomic; an interruption can leave earlier cases stored,
and identical inputs allow recovery. No second analytical store is used.
There is no dispatch, attempt, causal journal binding, technical evidence
admission, state transition or operational publication. The batch is not
an experimental sample. P8 remains NO-GO.
