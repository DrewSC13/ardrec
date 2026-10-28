# ADR 0011 — Proyección analítica / Analytical projection

## Español

Estado: componente implementado; aplicación local, CI e integración pendientes.
AL-06 permanece abierto. Base PR #19: `73fc572fb3df8a9d45c300e8264b196d44be0bbd`.
Fuente TESIS ARDREC, SHA256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`;
secciones 3.2.1–3.2.3, 3.2.6–3.2.9, 3.8.1 y 3.9.10.

### Decisión

`ardrec.analytical` representa una proyección inmutable por servicio. Reutiliza
`ServicePhase` y los contratos racionales/ND. No modifica los modelos operacionales,
`DurableStore`, el protocolo 2.0 ni Rust, y no confirma generaciones globales.

| Grupo | Contenido |
| --- | --- |
| Contexto | Registro, invocación, configuración, servicio, generación, estado |
| Congelado | R0, CN y referencia a caracterización |
| Análisis | Et, R0-, U, D, Rf, prioridad |
| Referencias | Evidencia, contadores, objetivos, historial, ventana, controles |

Las ocho magnitudes determinadas usan racionales canónicos de hasta 256 bits en
[0,1]. ND conserva su motivo; no es cero. La prioridad vacía usa
`{"status":"EMPTY"}` y corresponde a `None` en Python. Se distingue de ND y cero.
PREPARADO exige prioridad vacía. En otros estados puede estar vacía; A3/A4 deberán
justificar habilitación y selección. Representar ND no autoriza inicialización,
publicación ni reporte numérico.

Se comparan todos los extremos determinados de R0- ≤ D ≤ R0 ≤ U y
R0- ≤ D ≤ Rf ≤ U, incluso a través de un ND intermedio. Cuando R0/U/D/Rf están
determinados se exige Rf = U + D - R0. Son condiciones necesarias de coherencia,
no cálculo de evidencia, sustituciones, cotas o prioridades desde sus fuentes.
No se implementa A7 ni se acredita consistencia algorítmica completa.

El formato `ardrec-analytical-projection-1` es una decisión de implementación.
Rechaza campos ausentes/desconocidos/duplicados, números aproximados, booleanos
como enteros, racionales no canónicos, versiones desconocidas y entradas de más
de 32768 bytes. La generación admite enteros de 0 a 2^63-1. La escritura es
canónica; la lectura acepta espacios y distinto orden de claves sin dar autoridad.

Cada referencia declara identificador y SHA256 dentro del contexto de la proyección.
No se accede al sistema de archivos para resolverla. Una huella sintáctica no prueba
existencia, pertenencia, integridad ni autorización. Caracterización y repositorios
solo están referenciados; sus contenidos y la reutilización inmutable entre
generaciones requieren modelos y un resolutor posteriores.

`check_frozen_compatibility` compara contexto y datos congelados dentro de la misma
invocación. No valida avance de generación, transiciones, eventos ni historial;
no sustituye A9. La autoridad global no se representa con un booleano del llamador.

### Evidencia y trabajo pendiente

El fixture transcribe las ocho magnitudes del ejemplo 3.9.10: R0=CN=1/2, Et=3/4,
R0-=1/3, U=7/12, D=4/9, Rf=19/36, PA=7/12. Sus hashes e identificadores auxiliares
son sintéticos y no designan evidencia experimental real. Se añaden 21 pruebas de
oráculo, estados, exactitud, ND/EMPTY/cero, dominios, cotas parciales, identidad,
inmutabilidad, congelamiento, contexto y rechazos de formato. La CI Python existente
las descubre; el total esperado es 275, cuya ejecución debe verificarse.

AL-06 sigue abierto: faltan estado global completo, caracterización y contenidos de
repositorios, revisiones, contadores, objetivos, ventanas, controles, guardas desde
fuentes verificadas, publicación integral y recuperación. AL-07 sigue abierto por
referencias externas y procesos. AL-04/AL-05/AL-09 conservan cierres acotados;
AL04-R01/R02/R03 siguen pendientes. Punto 1 en curso, A1–A10 y prototipo no iniciados;
experimentación no ejecutada. La proyección serializada no es un estado confirmado.

## English

This component introduces an immutable per-service projection, not a confirmed
global state. It reuses operational phases and exact rational/ND contracts, preserving
existing operational models, persistence, protocol 2.0 and Rust code.

The projection carries record/execution/configuration/service/generation context,
frozen R0/CN and characterization reference, Et/R0-/U/D/Rf/priority, and references
for evidence, counters, objectives, history, convergence window and controls.
Determined values lie in [0,1]. ND retains its reason. EMPTY priority is separate
from ND and zero and required for PREPARADO. Other empty priorities require future
A3/A4 eligibility decisions; representable ND is not initialization/publication authority.

Known endpoints of both bound chains are checked across ND intermediates. When
known, Rf = U + D - R0 is required. These are necessary consistency checks, not A7
calculation or validation of evidence, substitutions and priorities from their sources.
The versioned JSON contract rejects duplicate/unknown/missing fields, approximate
numbers, noncanonical rationals, invalid types/versions and oversized input.
Encoding is canonical; decoding establishes no authority.

Reference identifiers/hashes are declarations, not resolved/authenticated objects.
Characterization and repository contents, generation membership and immutable reuse
remain future work. Frozen compatibility only compares context/frozen values within
one invocation; it does not validate sequencing, transitions, history or A9.

The synthetic fixture preserves the eight exact thesis-example numbers. Twenty-one
added tests cover the oracle and contract boundaries; the expected Python total is
275 and must be verified. AL-06 remains open for complete global state, repository
models, sourced guards and integral publication/recovery. AL-07 and AL04 residual
obligations remain open. Point 1 is in progress; no algorithms, operational prototype
or experimental validation are claimed.
