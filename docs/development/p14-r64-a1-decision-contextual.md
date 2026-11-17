# ARDREC P14-R64 — DECIDIR: resultado contextual trazable (figura 3.4)

**Tesis:** `Tesis ARDREC(20261117-153848).pdf`, SHA-256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
§3.6.1, figura 3.4, página impresa 105 / PDF 120.
**Base:** `4ba53db366bd461f4b79ef9ad53fce3c2c3c1162` (R63).

La figura 3.4 termina con una estructura que conserva **estado actual, origen,
configuración, servicio, caso, condición y contexto**. Las salidas de R61/R62
habían resuelto la semántica de tablas y la etiqueta de fila ganadora, pero no
ofrecían un recibo A1 de estos siete campos.

## API de alcance explícito

`FrozenRulePreview.evaluate_service_contextual(...)` devuelve un
`ContextualDecision` congelado, en JSON canónico ASCII y con SHA-256.

- `estado`: `ServicePhase` explícita, nunca inferida desde `Truth`;
- `origen`: identificador **declarado** por el invocador;
- `configuracion`: SHA-256 real de la instantánea R17 verificada;
- `servicio`: identidad declarada y confirmada presente en esa configuración;
- `caso`, `condicion` y `contexto`: identificadores declarados, validados;
- `estado_tabla`, `regla_seleccionada`, `salida_declarativa`, `evaluaciones`:
  resultados efectivos del núcleo A1, con `ND` y `FALSO` diferenciados.

`verify(...)` vuelve a evaluar A1 contra la **misma configuración y los mismos
argumentos de contexto** y rechaza recibos manipulados o cambiados.

La **huella no prueba que el origen, el estado o la condición declarados sean
verdaderos**. Los recibos marcan expresamente `procedencia_externa_acreditada:
false`, `autoridad_operacional: false`, `generacion_publicada: false` y
`p8: NO-GO`.

## Compatibilidad y límites de aceptación

La extensión es aditiva: no altera `decide()`, `evaluate()`, `PreviewDecision`,
ni los formatos existentes R26/R58. Mantiene sin cambios las demostraciones,
las 25 familias y los 29 casos sintéticos.

Se añaden 20 oráculos independientes sobre identidad, tablas con y sin
coincidencias, incertidumbre, permutación, firma de configuración, entrada
inválida, recibos manipulados y denegación operativa. CI exige ejecutarlos.

**A1 aún no queda aceptado al 100 % en esta entrega.** Falta acreditar la fuente
real del contexto y su enlace con un estado confirmado y la ruta normal del
coordinador, además de registrar la matriz final de criterios de figuras
3.4–3.5 contra consumidores. Los módulos A2–A10 y validación experimental
siguen procesos independientes.

**EN.** Adds a canonical, reproducible A1 decision envelope binding the seven
Figure 3.4 context fields to a frozen R17 configuration and actual A1 outputs.
Inputs describing provenance are declared, not independently attested. P8 NO-GO.
