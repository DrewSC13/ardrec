# R304 — Persistencia analítica nativa DEV / Native DEV analytical persistence

## Español

`caso archivar-analisis-dev` conserva una proyección analítica nativa del caso
R302 y de su valoración R303 previamente persistida. Reutiliza AnalyticalArchive,
AnalyticalProjection, el resolvedor de siete referencias y el dictamen A8 de
previsualización. El identificador de ejecución tiene sufijo `:documentary` y no
identifica un intento físico. La configuración se vincula por la huella de sus
bytes originales. Los valores candidatos se preservan en los objetos documentales;
los campos congelados y el riesgo confirmado de la proyección permanecen ND.

```
python -m ardrec caso archivar-analisis-dev --origen ORIGEN --archivo ARCHIVO \
  --id ID --sha256 HUELLA_ESCENARIO --valoracion DIRECTORIO \
  --sha256-valoracion HUELLA_RATINGS --texto
```

`reabrir-analisis-dev` recibe los mismos argumentos y no crea archivos de
análisis ausentes. Las fuentes originales se vuelven a verificar. Los siete
objetos y la proyección se conservan en `ID.analytical/` mediante el archivo
nativo, y `ID.snapshot.json` vincula la huella a la valoración. La primera
publicación del índice se realiza después de la lectura nativa verificada.
Si se interrumpe la creación antes de escribir el índice, repetir la misma
operación puede recuperar una instantánea idéntica, sin sobrescribirla.
No se promueven restos temporales ni se sustituyen instantáneas alteradas.
Los permisos y las rutas privadas siguen los contratos existentes.

El dictamen A8 recomienda pausar hasta contar con evidencia autorizada; no
aplica transición. PREPARADO, A6 ND, Rf confirmado ND, cero intentos, P8 NO-GO.
No acredita fuentes documentales, no evalúa la totalidad de A3, no despacha
pruebas, no publica A9 operacional y no cierra AL-06/AL-07.

## English

The normal case CLI stores a native analytical snapshot of the persisted R302
case and R303 assessment, using the existing archive and reference resolver.
Candidate values remain documentary payloads; frozen and confirmed values stay
unknown. The native stop preview recommends holding without applying a state
transition. Reopening requires the original sources and checks all seven
references and the projection. Identical repeats are idempotent. There is no
physical evidence accreditation, dispatch, operational A9 publication or
experimental admission. P8 stays NO-GO.
