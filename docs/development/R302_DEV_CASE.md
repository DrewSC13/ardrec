# R302 — Apertura prospectiva de caso DEV / Prospective DEV case opening

## Español

La CLI `python -m ardrec caso abrir-dev` registra un caso de preparación con
identificador `DEV-` seguido de 32 caracteres hexadecimales. Reutiliza el contrato
R199 y el motor A1; la decisión de permanecer en PREPARADO es exclusiva del
alcance DEV. El directorio R199 debe existir, ser privado (0700) y contener
los cuatro originales (configuración, inventario, escenario y plantilla).
Se exige el SHA-256 de los bytes de `scenario.json`, obtenido de una fuente
confiable. Los originales y el archivo de caso se comprueban al reabrir.
El archivo es exclusivo e idempotente dentro del directorio privado de casos.

`python -m ardrec caso abrir-dev --origen RUTA --archivo RUTA --id DEV-ID --sha256 HUELLA --texto`

`python -m ardrec caso reabrir-dev` usa las mismas opciones. `--json` devuelve
el registro canónico. Los directorios deben ser absolutos, distintos y sin alias.

Los casos no representan un servicio físico autenticado, una autorización de
operación, una publicación A9 ni una observación experimental. No se vinculan
recibos retrospectivos a casos nuevos. Rf y la valoración permanecen ND; P8
permanece NO-GO. AL-06 y AL-07 siguen abiertos: esta capacidad cubre solamente
la preparación, identidad, integridad, decisión DEV y reapertura, no el despacho.

## English

The normal case CLI opens an immutable prospective preparation record using
R199 and the A1 kernel. The case identifier is `DEV-` followed by 32 lowercase
hexadecimal characters. Provide an existing private R199 source directory and a
trusted SHA-256 of the raw scenario.json file; a separate private case directory
is required. Both source and case record are revalidated on reopen. This is
local DEV preparation only, with no execution authorization, physical evidence,
confirmed risk, operational A9 publication or experimental admission. AL-06
and AL-07 remain open; dispatch and retrospective receipt linking are excluded.
