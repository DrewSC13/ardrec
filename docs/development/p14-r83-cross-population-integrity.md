# ARDREC R83 — Conciliación de 25 familias con 29 variantes del modelo

**Base exacta:** `5a51de59eac089887f03472f54c71c84edf8735a` (R82). **Modo:** exclusivamente DEV/offline y sin autoridad operacional. **Objetivo:** cerrar una brecha de integración *de software*, no declarar resultados físicos.

## Decisión de diseño

R81 verifica la ejecución de una nueva sesión DEV y su recorrido A1–A10; R82 verifica los estados y el almacenamiento SQLite transaccional de los *29 casos del modelo* R58. R76/R79 identifican, por otra parte, *25 familias analíticas* (SSH=8, FTP=8, SMB=9), mientras que A2 conserva *54 unidades sintéticas*. Los 29 casos tienen variantes adicionales FTP/SMB y no constituyen automáticamente 29 observaciones de las 25 evaluaciones. Es metodológicamente inválido homologar ambas poblaciones por nombre.

R83 agrega un único **contrato de conciliación por familia de catálogo**. Reusa los verificadores R81/R82 sobre sus recibos privados originales y sus SHA-256 fijados; revalida los informes R76/R79, y reconstruye la denegación R58-S. Para cada familia registra las variantes del modelo, la decisión denegada, la selección exclusivamente simulada de dos casos R82 y los tres valores matemáticos E=0, E=1/2 y E=1. **No confunde coincidencia de familia con identidad de observación:** `cross_population_join=CATALOG_FAMILY_ONLY`, `same_assessment_attested=false`, `cross_population_authoritative_join_count=0`.

Rechaza desalineaciones de familia/servicio/caso, falta o duplicación de variantes, autorización falsificada, replay inconsistente, `Rf` confirmado inventado, modificaciones en A6/A8/A9 y cambios físicos. Verifica los 10 algoritmos, 25 familias, 29 variantes de modelo y 54 unidades A2 *como conjuntos diferentes*. No reejecuta el proceso benigno A5 de R81, no crea una segunda base SQLite ni modifica los registros R82. El único archivo que crea en modo `--create` es el `MANIFEST.json` canónico de un nuevo recibo R83 privado, 0600 y directorio 0700.

## Pruebas y criterios

`lab/tests/test_p14_r83_cross_population_integrity.py` contiene **22 pruebas nuevas** que cubren reconciliación determinista, correspondencia de familias, estados conservadores, duplicados, falsificación de autoridad, corrupción de fuentes y seguridad de archivos. Se mantienen las **211 pruebas focales heredadas** y la CI histórica: total objetivo **233**. El verificador del recibo R83 reconstruye desde los recibos R81/R82 cada dato, y nunca acepta únicamente el SHA-256 autodeclarado de R83.

La prueba local integral que recrea R81+R82 desde cero excedió el tiempo del entorno de preparación. Por eso el ejecutor Prometheus debe verificar los recibos originales y producir/verificar R83 **antes de firmar el commit**. No se atribuye PASS a esa prueba pendiente.

## Ejecución segura

Desde el repositorio canónico de Prometheus en Zsh, el ejecutor del paquete confirma el commit base, hashes y permisos antes de crear la rama. Usa precisamente:

- R81: `/home/cicada/ardrec-lab/r81-demo-20261118T150017Z-17325`, SHA de reporte `e9cdf34c13074ed42b48282c642912c26fc27bf98aaa281c16f1dc29b7188ac5`.
- R82: `/home/cicada/ardrec-lab/r82-demo-20261118T153806Z-6534`, SHA de reporte `d7ec7fe3efde5f04c43e5530ba4f00e0f346ddc843a5c2c330d8ed18b76e66c1`.

Las fases `--create` y `--verify` comparten los mismos argumentos `--r81-receipt`, `--r82-receipt`, `--work-dir`, `--expected-r81-sha256` y `--expected-r82-sha256`. Si falla `--create` y queda un directorio parcial, **no reintentar** sin diagnóstico. En caso de apagado tras commit y apertura de PR utilizar únicamente el ejecutor `CIERRE` incluido.

## Límites no negociables

`A6=ND`, `Rf confirmado=null`, transiciones operacionales=0, generación A9 adicional=0, P8=`NO-GO`, aceptación funcional del sistema=`PENDING`, validación experimental=`NOT_RUN`. Las decisiones de R58-S no acreditan independencia, firma de autorización ni commit del estado operativo. La próxima etapa deberá construir un vínculo de **identidad de evaluación explícito**, con autorización independiente de F11 y soporte técnico real, antes de cualquier transición o actualización de riesgo confirmada.
