# R86 — 25 evaluaciones tipadas, trazas A1–A10 de una sesión DEV

**Estado:** proyección funcional reproducible y conservadora sobre la única sesión sintética R81. No se declara una prueba de penetración real, ni un motor nuevo de estados, ni aceptación integral del sistema.

## Objetivo

R86 reúne los **25 intentos A5 tipados de R76 dentro de la misma sesión DEV R81**. Para cada uno produce una secuencia **A1–A10** de diez registros derivativos, enlazados por SHA-256 y raíz tipada `(session_id,service_id,derived_case_id,assessment_index,attempt_id,intent_sha256)`. Total: **25 cadenas y 250 registros**. Son vistas de software derivadas de hechos documentales y escenarios hipotéticos ya registrados: **no son 250 ejecuciones**.

Los 54 elementos sintéticos A2 son una población independiente y no se pretende demostrar su identidad con estos 25 casos. Los 29 casos del modelo R82 también siguen separados; su enlace por familia representa cobertura de catálogo, no identidad de una misma evaluación acreditada.

## Flujo y límites de cada etapa

- **A1 y A2:** raíz GEN1 y referencia agregada a 54 unidades sintéticas; no equivalen a una observación técnica del caso.
- **A3 y A4:** decisión y selección hipotéticas, sin autorización de despacho.
- **A5:** vinculación inyectiva a un intento tipado; 3 declaraciones `UNVERIFIED_DECLARATION` y 22 `NOT_STARTED`.
- **A6:** `NOT_ADMITTED_ND` para los 25 casos.
- **A7:** intervalo de fracciones exactas sin `Rf` confirmado. Los valores de E son contrafactuales.
- **A8:** `HOLD_NO_AUTHORITY`; sin transición operativa y sin unir identidades de R82.
- **A9:** GEN1 preservada, cero generaciones adicionales.
- **A10:** referencia a presentaciones R80/R81 sin evidencia nueva.

`validate_ledger` comprueba el orden, el hash de cada registro, los vínculos encadenados, la unicidad, la sesión única, las cotas racionales y las guardas de autoridad. `verify` además reconstruye el documento desde los recibos originales, para que una adulteración con hashes recalculados no pueda acreditarse como reproducible.

## Entrada y seguridad

El ejecutable `scripts/ardrec_p14_r86_single_session_trace.py` acepta `--create` o `--verify`, `--work-dir` y rutas explícitas de los recibos R81–R85, además de `--expected-r85-sha256`. El modo create escribe **solo** un manifiesto canónico en una carpeta privada nueva con permisos 0700/0600. Verify no modifica archivos ni inicia A5. Exige usuario no privilegiado en repositorio canónico; rechaza recibos con permisos inadecuados o rutas adulteradas.

El ejecutor para Prometheus fija un SHA de `main`, autentica el ZIP, comprueba la firma, valida los SHA de los recibos R81–R85, aplica exactamente cinco archivos y corre **91 pruebas locales** de R83–R86 más trazabilidad, antes del recibo, commit firmado y PR. El cierre separado verifica las tres CI obligatorias y solo entonces intenta un merge protegido.

## Aceptación

El resultado `PASS_TYPED_LEDGER_CREATED` significa que se verificó la proyección del software DEV. Continúan `system_functional_acceptance=PENDING`, `experimental_validation=NOT_RUN`, `A6=ND`, `Rf` confirmado `NULL`, A8 operacional `0`, y `P8=NO-GO`. Siguen pendientes AL-06/AL-07, F11 físico y los seis criterios externos de R84.
