# ARDREC — P14-R18: instantánea inicial sintética y acotada de A2

**Base exacta:** `40bc124cd171e0c5bb5beef74b0bd6e5bb23b388` (PR #83 R17).

## Propósito y correspondencia académica

El incremento amplía el núcleo trivalente A1 (R16) y su prevalidación estructural
(R17) mediante una **propuesta inicial inmutable por servicio**, limitada a campos
que pueden comprobarse sin autorización operacional. La referencia principal
es el algoritmo 2, *Validación e inicialización*, figura 3.9 y el marco aplicativo
3.2–3.4 de la tesis; este incremento **no implementa A2 completo**.

1. La propuesta acepta exactamente el conjunto de servicios previamente
   prevalidado con R17 y ancla la huella de sus reglas. Se deniegan servicios,
   casos, argumentos, estados u operaciones adicionales.
2. Los valores `initial_risk` (`R0`) y `normalized_criticality` se expresan
   mediante racionales no negativos canónicos en el intervalo cerrado `[0,1]`.
   Se prohíben `float`, booleanos como enteros y fracciones sin reducir.
3. Por unidad: estado inicial `PREPARADO`, `accumulated_evidence = 0`,
   `recalibrated_risk = initial_risk`, prioridad vacía y ninguna transición
   histórica. Por caso: contador de inicios acreditados igual a cero,
   presupuesto total `1 + max_repetitions`, con `max_repetitions` en `{0,1}`.
4. Se ordenan identidades de servicios y casos para generar JSON canónico,
   una instantánea de bytes independiente de la entrada original y un SHA-256.
   La verificación comprueba huella, origen de reglas y valores reconstruidos.
5. Se puede consultar una guarda A1 asociada al servicio, pero su valor
   `VERDADERO` **no autoriza** ninguna ejecución ni publica un estado.

## Restricciones y pendientes

- El formato R17 limita a 32 servicios configurados. No se afirma que este
  ensayo reproduzca el diseño experimental de 54 unidades ni su catálogo.
- No se validan todavía caracterización integral, referencias a soportes,
  dependencias entre servicios, pesos, exposición, impacto, casos materiales,
  fuente de autorización, ventanas temporales ni configuración completa A2.
- `InitialPreview` **no es** `ConfirmedState`, no representa la generación
  publicada por A9 ni confiere autoridad a A3/A5. La huella es local y carece de
  ancla externa de frescura; no es durabilidad ante fallos físicos.
- `R0` y `Rf` inicial se conservan como valores, sin calcular A7 ni cambiar
  prioridades. No se ha iniciado ni ejecutado A1–A10 integralmente.
- P8 permanece **NO-GO**, 29 perfiles denegados, cero despachos.
  AL-06, AL-07, aceptación funcional y validación experimental siguen abiertos.

## Pruebas

- `lab/tests/test_p14_r18_a2_initial_preview.py`: inicialización y límites,
  rechazo de datos malformados, invariancia del orden, no mutación, enlace
  con R17 y guardas trivalentes, cero autorización.
- `scripts/demo_p14_r18_a2_initial_preview.py`: dos servicios sintéticos,
  magnitudes exactas, contadores, huellas independientes y consulta A1.
- CI: pruebas y demostración adicionales sin servicios systemd ni clientes SSH,
  FTP, SMB; regresiones existentes de Python/Rust se conservan.

**Veredicto:** `R18_A2_INITIAL_PREVIEW=COMPONENT_SCOPE_ONLY`,
`A1_FULL=NOT_CLOSED`, `A2_FULL=NOT_CLOSED`, `P8_OPERATIONAL=NO-GO`.

## English summary

R18 introduces a canonical, immutable, **synthetic** A2 initial-state preview
bound to the R17 rule preflight. Exact rational baselines, zero counters,
prepared state, empty history and conservative case limits are verified.
It neither publishes a confirmed generation nor runs or authorizes operational
profiles. Complete A2, system acceptance and experimental validation remain open.
