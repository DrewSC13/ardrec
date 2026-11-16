# P14 / R58-R — Recibo inmutable de propuesta A3 → A4 (sin transición)

**Base fijada:** `5bb8ce2c3e31de3c74d71e126b8ea556e86805b5`.

Este incremento registra de forma **durable, declarativa y local** las condiciones de transición hipotética `PREPARADO → PENDIENTE` calculadas por R58-Q, sin aplicar ninguna transición a la máquina de estados. Conserva 29 identidades de caso y 25 familias, los controles A3, las guardas trivalentes, las huellas de las fuentes y el resultado de las dos evaluaciones de A4. La identidad proviene del escenario de desarrollo sintético R26 y del catálogo P7 fijado: el recibo **no acredita un entorno físico**.

El estado actual para los 29 casos sigue siendo `PREPARADO`. Con las guardas del escenario de desarrollo, la proyección contrapuesta ofrece ocho posibles `PENDIENTE` SSH; FTP conserva `ND` y SMB `FALSO`, ambos bloqueados. Se preservan los bloqueadores `AUTORIDAD_OPERACIONAL_NO_ACREDITADA`, la no publicación A9, la clasificación A6 `ND`, los intervalos A7 no acreditados y `P8=NO-GO`.

## Contrato durable

- Un archivo JSON canónico por identificador de sesión, nombrado por SHA-256 con separación de dominio; no se usa el ID directamente como nombre de archivo.
- Directorio proporcionado expresamente por el llamador, absoluto, privado (`0700`), propio y sin enlaces simbólicos. Archivo nuevo `0600` con creación exclusiva, `O_NOFOLLOW` cuando esté disponible y `fsync` del archivo/directorio.
- Una repetición byte a byte idéntica devuelve `REPLAY_IDENTICAL`. Cambios de fuente, identidad o contenido devuelven conflicto; no se sobreescribe ni se repara automáticamente un archivo parcial.
- Un lector separado vuelve a ejecutar el verificador R58-Q, verifica SHA-256, origen, esquema, integridad del fichero y contenido canónico. No se confía en el hash por sí solo para acreditar autoridad.
- La CLI crea su único diario **dentro de un directorio temporal**, devuelve JSON y borra sus recibos al salir. El CI ejecuta tests y demostración offline.

**Exclusiones explícitas:** sin transición estatal, sin base de datos operacional, sin lectura/escritura de VM, sin A5 físico, sin importación de evidencia A6 acreditada, sin publicación de generación A9, sin reintentos automáticos y sin cambio de R34/F11/P8.

## Limitaciones y trabajo posterior

Este registro demuestra trazabilidad del *diagnóstico y la propuesta*, no una transición autorizada. El siguiente incremento deberá especificar la autoridad independiente y los precondicionados de transición/commit, con pruebas negativas antes de implementar mutaciones reales. El catálogo P7 sigue sin congelarse y no existen validaciones físicas de las 54 unidades.
