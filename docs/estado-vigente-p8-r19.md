# ARDREC — P8-R19: exploración offline de dependencias ELF sin despacho

**Base:** merge `e1e43c621e28628d004775d888ef5b133debfb52` de R18,
con CI posterior aprobada y sincronización `main` confirmada por el operador.

R18 observó tres ELF de la QCOW2 Debian 13 fijada por R9: `ssh` (5
entradas `DT_NEEDED`), `curl` (3), `smbclient` (23). R19 agrega un
**colector privado de grafo de bibliotecas candidatas**, que comprueba rutas
canónicas y alias de enlaces con guestfish en solo lectura y extrae metadatos
ELF de archivos DSO observados, con límites de nodos, aristas y profundidad.
El lector de ELF no invoca ejecutables. CI ejecuta únicamente el analizador
sintético y la verificación de fuentes versionadas; no usa la imagen QCOW2
ni recibe evidencias privadas.

La adquisición privada del operador es obligatoria para confirmar que el código
funciona frente a la imagen real. No se declara esa adquisición realizada por
esta propuesta. Una vez obtenida, se publicarán solo el hash del recibo y
el resumen de conteos, nunca el recibo privado completo.

La búsqueda de rutas es **candidate-only**; no reproduce el buscador real
del cargador dinámico (cache, prioridades, `glibc-hwcaps`, `LD_*`, RPATH/RUNPATH,
preload, etc.). Una prueba de lectura reproducible no demuestra cierre de
dependencias en runtime, compatibilidad semántica de las CLI ni autorización
privada. Las 29 ranuras R1 mantienen sus 348 campos sin autoridad resuelta.
Las cinco escrituras aún requieren pruebas independientes de limpieza.

Cero perfiles autorizados, cero casos autorizados, cero `argv` ejecutables,
cero despacho. P8 y AL-06/AL-07 abiertos. P9 y A1–A10 no iniciados.

**EN:** Offline guest-ELF candidate dependency graph only; canonicalized library
paths are observed but do not establish effective loader resolution or dispatch.

## Resultado de adquisición offline reportado por el operador

La ejecución privada R19-H1 sobre la QCOW2 fijada por R9 produjo un grafo de **68 bibliotecas candidatas**, **292 relaciones**, **67 relaciones no resueltas**, **0 ambiguas** y **9 indicadores de búsqueda especial**.

SHA-256 del recibo privado R19: `785a85192e42588042467017f4ec65bafed96f4711bb1d42c6f846ede0e1a1cf`.

El recibo permanece fuera del repositorio. La CI pública no reproduce esta observación ni certifica la resolución de dependencias del cargador. Las relaciones no resueltas requieren análisis posterior. Cero autorizaciones y cero despachos.
