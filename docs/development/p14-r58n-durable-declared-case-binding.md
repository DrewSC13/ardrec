# P14-R58-N — Recibo durable de vinculación A4/A5 (source-only)

ES: El estado de `main` usado como base es `b07f50f3e4aa0764b47024395caab5bb9b6694e5` (R58-M). El diario P9–P12 es íntegro para el fixture local, pero **no contiene** identidad técnica `(servicio, sesión, caso derivado, ventana)` ni autoridad de ejecución.

R58-N construye una vinculación **declarada, no acreditada** a partir del informe A4/A5 de R58-L y de la auditoría de solo lectura R58-M. El recibo guarda la identidad seleccionada, `request_id`, hash del informe, huella del diario completo, fingerprint del request, hash del último evento y estado del intento benigno. El origen técnico de la asociación sigue sin acreditarse; los SHA no son firmas ni certificaciones externas.

Se almacena un único recibo JSON canónico por `request_id` en un **directorio de recibos distinto al diario**, existente, seguro y propiedad del usuario (0700). La primera escritura es exclusiva, con `fsync` de archivo y directorio; la repetición idéntica no escribe; un conflicto, cambio de diario, symlink o alteración se rechaza. No se rebasa la cadena P9. El recibo conserva `A6=ND`, `Rf=None`, A8 solo recomendación conservadora, sin transiciones ni publicación A9 y con `P8=NO-GO`.

**Demostración:**

`PYTHONPATH=src python3 -B scripts/ardrec_p14_r58n_durable_binding_demo.py --synthetic-offline`

La demostración crea exclusivamente en `TemporaryDirectory` un diario de fixture benigno, llama `submit` y `accept` para generar el estado `ACCEPTED`, registra y reproduce una declaración; **no llama `execute` ni `recover`**. En producción este módulo nunca crea, acepta o ejecuta intentos.

**Restricciones y trabajo siguiente:** este recibo es una referencia local de desarrollo, no una autorización para actuar sobre SSH/FTP/SMB. La identidad autoritativa necesitará un contrato específico previo al inicio del intento, con autenticidad independiente y ciclo de autorización antes de conectar la evidencia real a A6/A7. R34 DENY y F11 sin activación física permanecen vigentes.

EN: Immutable, SHA-bound *declared-only* A4/A5 association over a pre-existing benign journal. Single-writer exclusive creation, deterministic idempotent replay and conflict rejection. Never credentialed evidence, VM access, execution, or publication.
