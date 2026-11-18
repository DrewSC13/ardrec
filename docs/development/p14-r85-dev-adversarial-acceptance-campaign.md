# ARDREC R85 — Campaña adversarial para aceptación funcional DEV

**Base exacta:** `2a9fbab577879eb848f9f2b664f7981dec02b4b9` (merge R84). **Alcance:** prueba de contratos de software sintético; ninguna observación física, servicio de red, VM, despacho A5 o habilitación P8.

## Propósito y relación con R84

R84 verifica 13 criterios de coherencia del software DEV, con 6 criterios externos pendientes. R85 añade una campaña **determinista, negativa y reproducible** sobre la matriz R84: para cada perturbación en un documento sintético se reconstruye el contrato `r84.evaluate()` y se exige un rechazo explícito (`R84Error`). Una alteración que no sea rechazada detiene toda la campaña; el resultado no se contabiliza como PASS. Esto comprueba las defensas de la capa contractual, no el comportamiento de SSH, FTP o SMB físicos.

## Cobertura de 156 rechazos exigidos

| Grupo | Perturbaciones | Objetivo |
| --- | ---: | --- |
| A5_BINDING | 25 | Cambiar el identificador del intento, dejando discordante la asociación con el recibo |
| A6_FALSE_ADMISSION | 25 | Declarar veracidad técnica sin testigos válidos |
| A7_FALSE_RF | 25 | Inyectar riesgo final confirmado ficticio |
| A7_OUT_OF_RANGE | 25 | Forzar un escenario contrafactual fuera del dominio unitario con digest recalculado |
| A8_FALSE_APPROVAL | 29 | Cambiar a aprobada una variante previamente denegada, con digest recalculado |
| AUTHORITY_FORGERY | 10 | Falsear autoridad, despacho, estado, aceptación y hallazgos pendientes |
| RECOVERY_FAILURE | 4 | Alterar las garantías de rollback/replay/estado terminal |
| DEV_SESSION_FORGERY | 6 | Alterar las garantías de sesión DEV previa |
| R76_SOURCE_FORGERY | 7 | Falsear el origen de intenciones y admisión documental |
| **Total** | **156** | **Todos deben ser rechazados** |

Se recalcula el SHA del *documento mutado* para los grupos sobre el cruce R83, de modo que la prueba no se limite a detectar un hash obsoleto. El contrato R84 debe rechazar además la discordancia semántica. La prueba no modifica ningún recibo original: aplica cada perturbación a una copia en memoria.

## Reproducibilidad y límites

El CLI `scripts/ardrec_p14_r85_dev_adversarial_campaign.py` permite `--create` y `--verify` usando las carpetas privadas R81, R82, R83 y R84. Antes del informe verifica los originales con sus verificadores anteriores y reconstruye R84 desde sus fuentes. El recibo R85 se guarda en un directorio nuevo privado (0700) con un único `MANIFEST.json` (0600); `--verify` lo reconstruye sin ejecutar A5 ni tocar SQLite.

Los criterios del sistema continúan: `system_functional_acceptance=PENDING`, `experimental_validation=NOT_RUN`, `A6=ND`, `Rf=null`, `P8=NO-GO`. Las poblaciones 54 unidades A2 / 25 familias / 29 variantes no constituyen uniones de identidad experimental acreditadas. AL-06 y AL-07 permanecen abiertos. Los 156 casos son **inyecciones adversariales sintéticas a una función de validación**, no 156 ensayos de intrusión ni una medición de tasas de detección en producción.

## Seguridad y CI

Se incorporan 20 pruebas focales R85, incluido rechazo de una mutación sobreviviente (evita falsos PASS), recibos alterados, permisos inseguros y reproducción. El trabajo se incorpora a CI Python conservando las verificaciones Rust y F11. El ejecutor Prometheus fija hashes del paquete y de los recibos originales, ejecuta la campaña sobre originales de solo lectura, firma el commit y abre PR; el cierre protegido requiere tres checks PASS. Nunca asumir que CI posmerge ya pasó solo porque el PR se fusionó.
