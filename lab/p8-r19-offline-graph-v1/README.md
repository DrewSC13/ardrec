# ARDREC P8-R19 — Grafo ELF estático de candidatos (no es la resolución del cargador)

**Base esperada:** `e1e43c621e28628d004775d888ef5b133debfb52` (PR #51).

Instrumentación para leer exclusivamente la QCOW2 fijada por P8-R9, sin ejecutar
los tres binarios candidatos del invitado, sin iniciar las VM de ARDREC y sin
contacto con SSH/FTP/SMB. `guestfish` abre explícitamente `--ro`; su appliance
auxiliar de lectura no equivale a una VM operacional del laboratorio.

1. El colector exige recibo privado R18 con SHA-256
   `90586b0fedd11fad28e9896f75f654fe3ff7558f2510940bd5e48d2171cbb806`.
2. R9 valida antes la QCOW2, el inventario y los binarios. El operador confirma
   que esa imagen base no está conectada a una VM operacional en marcha.
3. Para cada entrada `DT_NEEDED`, se buscan **candidatos** en seis directorios
   convencionales. `guestfish is-file ... followsymlinks:true` y `realpath`
   distinguen ausencias, alias simbólicos y rutas canónicas diferentes.
4. `virt-cat` lee cada DSO candidata única. El analizador ELF64 x86-64 interpreta
   `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH` y la presencia de `PT_INTERP`.
   También se observa el intérprete declarado por los tres binarios originales.
5. Cada archivo leído queda identificado por ruta canónica, tamaño y SHA-256;
   las relaciones forman un grafo dirigido con exploración limitada. Si hay
   más de una ruta canónica válida, **ninguna se elige como la real**.
6. Se revalida SHA-256 de la imagen antes de escribir un recibo privado
   `0600`, bajo directorio privado `0700`, fuera del repositorio público.

## Limitaciones expresas

El inventario de directorios candidatos **no** reproduce `ld.so.cache`,
`ld.so.conf`, `LD_LIBRARY_PATH`, `LD_PRELOAD`, `glibc-hwcaps`, `RPATH/RUNPATH`
ni el orden real de resolución de `ld.so`. Las entradas ausentes o ambiguas
son diagnóstico, no autorización. Aun si el grafo no presenta faltantes, la
resolución efectiva del cargador, ABI/runtime, aislamiento, casos P6,
credenciales, límites y limpieza continúan sin acreditación.

**Resultado siempre:** `runtime_dependency_closure_verified=false`,
`authorized_profiles=0`, `dispatch_allowed=false`. P8 sigue abierto; P9
no inicia y A1–A10 no se ejecutan.

El recibo privado no se publica, no se adjunta a PR y no se comparte íntegro.
Solo se comparte su hash y el resumen del colector.
