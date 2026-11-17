# P14-R68 · Cierre algorítmico de A1 (EVALUAR / DECIDIR)

Fuente normativa: tesis ARDREC, revisión 17-11-2026, SHA-256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.
Capítulo III §3.6.1; figura 3.4 (impresa 105, PDF 120) y figura 3.5
(impresa 106, PDF 121).

## Alcance estricto de la aceptación

La evaluación determinista **A1** recibe la tabla, el esquema y el ambiente
congelados y produce un resultado lógico y una salida declarativa. No decide
ni aplica autorización P8; tampoco publica una generación A9.

- R61: cero coincidencias → ND, múltiples verdaderas → error, una verdadera +
  indeterminación → ND, una verdadera determinada → salida declarada.
- R62: conjunto tipado, PERTENECE, SUBCONJUNTO, evidencia de decisión
  propagada a R26 y fuente canónica compartida con R58-P.
- R63: campo opcional ausente → ND; obligatorio ausente → error.
- R64: los siete campos contextuales con recibo inmutable y reproductible.
- R65: estado de servicio derivado de `ConfirmedState`.
- R66: recuperación canónica/privada de `ConfirmedState` con SHA esperado.
- R67: vinculación `GlobalState` con el mismo `ConfirmedState`, sin candidato
  divergente ni intentos pendientes.
- R68: interfaz de aceptación A1 que coteja de nuevo DECIDIR de R17 contra
  la elección recuperada por R67; comprobación de procedencia lógica, fuentes,
  identidades, salida y replay, sin autoridad operacional.

**Corte arquitectónico importante.** Las huellas suministradas por el invocador
no son prueba de quién publicó la generación. La pertenencia de la fuente R17
al *conjunto de configuración global* y la validación de autoridad/persistencia
A9 requieren sus propios criterios A2/A9, no son deducibles de un hash. Estos
campos permanecen falsos en los recibos. No convertirlos en verdaderos para
obtener el 100 % de A1.

## Aceptación de A1 en su alcance

La matriz JSON adjunta fija 18 grupos de condiciones independientes.
El resultado **A1_ALGORITHMIC_ACCEPTANCE=PASS** solo puede emitirse después de:

1. Todos los oráculos A1 R16/R61–R68 y sus regresiones A2/A3/R26/R58-P aprobados.
2. Todas las demostraciones de A1/A2/A3 y del puente R58-P aprobadas.
3. Toda la regresión P14 aprobada, sin exclusiones ni rebajas de oráculos.
4. Verificación de trazabilidad y Rust sin fallos.
5. Commit local firmado GPG `G`, CI sobre el SHA de la rama, PR/merge protegido,
   CI en el SHA exacto de `main` y sincronización local sin dañar R60-E5.

El resultado final acredita el **100 % de los criterios de A1 en esta matriz**,
no el 100 % de A1–A10, no el prototipo físico, no 54 observaciones empíricas.
Un STOP mantiene abierta la aceptación; no adelantar porcentajes.

**EN.** Algorithmic-only A1 closure gate. The read-only R68 entrypoint
cross-checks native R17 decisions with replay from canonical R67 sources.
Externally trusted generation publication, full config-membership and P8
remain outside this algorithmic acceptance scope and are explicitly denied.
