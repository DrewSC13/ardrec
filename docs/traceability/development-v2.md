# Trazabilidad vigente / Current traceability

## Español

Base revisada: `228bdedf09d06906ddfa184525e9a7c60f4e2dc6`. Fuente: `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

44 requisitos registrados en la revisión del punto 1; no se afirma cobertura de cada oración de la tesis. Los componentes y pruebas son soporte parcial; los planes conservan la evidencia que falta.

**Lectura:** requisito → algoritmo o responsable → componente → módulo y comprobaciones → evidencia → trabajo pendiente.

Una asociación a una suite identifica soporte parcial del componente; no afirma que cada método pruebe todo el requisito. Los 405 métodos Python incluyen métodos generados dinámicamente. Los 73 métodos Rust y los siete verificadores tienen identidades separadas. La evidencia recibida se atribuye a las suites de la base, no a esta nueva versión ni a resultados individuales.

Los planes TF/TE/TM conservan estado pendiente. Los 51 casos son oráculos de referencia; no son ejecuciones de A1–A10. AL-06 y AL-07 y las siete obligaciones residuales conservan sus condiciones de entrada.

## English

44 requirements registered by point 1 review; not every thesis sentence. Components and tests provide partial support; verification plans retain missing evidence.

Read requirement → algorithm or owner → component → modules/checks → evidence → pending work. Component-suite links indicate partial support, not assertion-level or full-requirement coverage. Baseline suite evidence does not establish execution of this new version or individual tests. Verification plans and full acceptance remain pending; 51 reference oracles are not A1–A10 executions.

## Requisitos / Requirements

| ID | Fuente / Source | Algoritmos / Algorithms | Componentes / Components | Pasos / Steps | Verificación prevista / Planned verification |
| --- | --- | --- | --- | --- | --- |
| AC-01 | 3.9.1 | A10 | STATE, PEER | 9, 10, 13, 23, 27 | TF-01 |
| AC-02 | 3.2.9, 3.9.4 | A1, A2, A7 | NUMERIC, PROTOCOL, MAGNITUDES, PROJECTION | 14, 15, 20, 24, 25 | TF-02 |
| AC-03 | 3.9.3, 3.9.4 | A5 | TRANSPORT, SOCKET_RECONCILIATION, PEER | 10, 12, 27 | TF-03 |
| AC-04 | 3.9.3, 3.9.5, 3.9.6, 3.9.7, 3.9.8, 3.9.9, 3.9.10, 3.9.11 | A5, A6, A9, A10 | PROTOCOL, TEMPORAL, REFERENCES | 10, 12, 18, 19, 22, 23, 25 | TF-04 |
| AC-05 | 3.9.3, 3.10.2 | A5, A9 | RECONCILIATION, JOURNAL, SOCKET_RECONCILIATION | 10, 12, 18, 24 | TF-05 |
| AC-06 | 3.3.2, 3.6 | A1 | REFERENCE_AUDIT | 14, 24 | TF-06 |
| AC-07 | 3.2.1, 3.2.2, 3.2.3, 3.6 | A2 | REFERENCE_AUDIT, PROJECTION, ANCHOR | 15, 24 | TF-07 |
| AC-08 | 3.3.3, 3.4.1, 3.6, 3.9.9 | A3 | Pendiente / Pending | 16, 24 | TF-08 |
| AC-09 | 3.4.1, 3.4.2, 3.4.3, 3.6 | A4 | REFERENCE_AUDIT | 17, 24 | TF-09 |
| AC-10 | 3.4.4, 3.6, 3.9.2 | A5 | STATE, RECONCILIATION, JOURNAL, TEMPORAL, COUNTERS | 7, 8, 9, 10, 18, 24 | TF-10 |
| AC-11 | 3.5.5, 3.9.2, 3.9.3 | A5, A10 | STATE, RECONCILIATION, JOURNAL, SOCKET_RECONCILIATION, TEMPORAL | 9, 10, 11, 12, 18, 23, 24 | TF-11 |
| AC-12 | 3.7, 3.9.2 | A3, A5 | Pendiente / Pending | 7, 8, 9, 10, 11, 27 | TF-12 |
| AC-13 | 3.3.4, 3.6, 3.9.8 | A6 | REFERENCE_AUDIT | 19, 24 | TF-13 |
| AC-14 | 3.2.5, 3.3.4, 3.6, 3.9.9 | A6 | REFERENCE_AUDIT, REFERENCES, ARCHIVE | 19, 24 | TF-14 |
| AC-15 | 3.2.2, 3.2.3, 3.2.4, 3.2.5, 3.2.7 | A2, A7 | REFERENCE_AUDIT, NUMERIC, MAGNITUDES, PROJECTION | 15, 20, 24 | TF-15 |
| AC-16 | 3.2.6, 3.2.8, 3.2.9, 3.6 | A7 | REFERENCE_AUDIT, MAGNITUDES, PROJECTION | 20, 24 | TF-16 |
| AC-17 | 3.2.9, 3.5.7, 3.6 | A7, A8 | PROJECTION | 20, 21, 24 | TF-17 |
| AC-18 | 3.5.2, 3.5.3, 3.5.5, 3.5.6, 3.6 | A8, A10 | STATE | 21, 23, 24 | TF-18 |
| AC-19 | 3.5.4, 3.6, 3.8.1 | A9 | STATE, PROJECTION, REFERENCES, ANCHOR, COUNTERS | 22, 24 | TF-19 |
| AC-20 | 3.6, 3.10.1, 3.10.2 | A9 | PERSISTENCE, MAGNITUDES, ARCHIVE, ANCHOR, COUNTERS | 5, 12, 13, 22, 27, 29 | TF-20 |
| AC-21 | 3.6, 3.10.2 | A5, A9, A10 | PERSISTENCE, RECONCILIATION, JOURNAL, SOCKET_RECONCILIATION, TEMPORAL, ARCHIVE, ANCHOR, COUNTERS | 12, 18, 22, 23, 25 | TF-21 |
| AC-22 | 3.5.2, 3.6, 3.9.9, 3.9.11 | A10 | STATE | 23, 25, 26 | TF-22 |
| AC-23 | 3.8.2, 3.8.3, 3.8.4 | A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 | Pendiente / Pending | 24, 25, 28 | TF-23 |
| AC-24 | 3.7.5, 3.9.1, 3.9.2 | A3, A5, A10 | STATE | 3, 4, 5, 6, 7, 8, 27, 33, 37 | TF-24 |
| AC-25 | Resumen, 3.1, 3.2.1, 3.8.2, 3.9.11 | A10 | Pendiente / Pending | 30, 32, 35, 36, 37, 38, 39 | TE-25 |
| AC-26 | Resumen, 3.8.2 | A10 | Pendiente / Pending | 35, 37, 40, 41, 42 | TE-26 |
| AC-27 | 3.8.2, 3.9.11, 3.10 | A9, A10 | PERSISTENCE, RECONCILIATION, ARCHIVE, ANCHOR, TRACEABILITY_AUDIT | 29, 39, 43, 44, 45, 46 | TF-27 |
| MET-01 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 35, 37, 38, 39 | TM-01 |
| MET-02 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 30, 37, 38 | TM-02 |
| MET-03 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 30, 31, 32, 37, 38 | TM-03 |
| MET-04 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 32, 37, 38 | TM-04 |
| MET-05 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 30, 32, 35, 37, 39 | TM-05 |
| MET-06 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 35, 37, 40 | TM-06 |
| MET-07 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 35, 37, 40, 41, 42 | TM-07 |
| MET-08 | 1.9.3 | Responsable metodológico / Methodological owner | Pendiente / Pending | 35, 37, 39 | TM-08 |
| MET-09 | 1.9.4 | Responsable metodológico / Methodological owner | Pendiente / Pending | 35, 36, 37 | TM-09 |
| MET-10 | 1.9.4 | Responsable metodológico / Methodological owner | Pendiente / Pending | 35, 36, 37, 39 | TM-10 |
| MET-11 | 1.9.4 | Responsable metodológico / Methodological owner | Pendiente / Pending | 35, 37 | TM-11 |
| MET-12 | 1.9.4 | Responsable metodológico / Methodological owner | Pendiente / Pending | 6, 33, 34, 36 | TM-12 |
| MET-13 | 1.9.5 | Responsable metodológico / Methodological owner | Pendiente / Pending | 30, 33, 37, 38, 39 | TM-13 |
| MET-14 | 1.9.5 | Responsable metodológico / Methodological owner | Pendiente / Pending | 31 | TM-14 |
| MET-15 | 1.9.5 | Responsable metodológico / Methodological owner | Pendiente / Pending | 30, 33, 34, 37 | TM-15 |
| MET-16 | 1.9.5 | Responsable metodológico / Methodological owner | Pendiente / Pending | 30, 32, 33, 35 | TM-16 |
| MET-17 | 1.9.5 | Responsable metodológico / Methodological owner | Pendiente / Pending | 29, 37, 38, 39, 43, 46 | TM-17 |

### AC-01

Python decide; Rust ejecuta; el transporte no admite evidencia ni confirma estados. Los permisos impiden escrituras ajenas.

Python decides; Rust executes; transport neither admits evidence nor confirms state. Permissions prevent unauthorized writes.

- Pendiente: Aislamiento y permisos efectivos de actores pendientes.
- Pending: Effective actor isolation and permissions pending.
- Verificación prevista / Planned verification: `TF-01` — Intentar ejecutar desde la capa analítica y publicar desde el ejecutor; ambos accesos se rechazan.
- Planned check: Attempt execution from the analytical layer and publication from the executor; both accesses are rejected.
- Obligaciones / Obligations: AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-02

Racionales reducidos, denominador positivo, tipos exactos y ND explícito conservan su significado entre Python y Rust.

Reduced rationals, positive denominators, exact types and explicit ND preserve their meaning across Python and Rust.

- Pendiente: Paridad de magnitudes y archivo exacto verificados dentro del formato definido; integrar su uso en A1/A2/A7 y verificar el sistema completo.
- Pending: Magnitude parity and exact archive verified within the defined format; integrate use in A1/A2/A7 and verify the complete system.
- Verificación prevista / Planned verification: `TF-02` — Probar cero canónico, límites, booleanos, decimales, fracciones no reducidas y equivalencia entre lenguajes.
- Planned check: Test canonical zero, boundaries, booleans, decimals, unreduced fractions and cross-language equivalence.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-03

Las tramas Unix respetan longitud, UTF-8, límites, lecturas parciales y permisos; un canal defectuoso no provoca otro despacho.

Unix frames enforce length, UTF-8, limits, partial reads and permissions; a faulty channel causes no new dispatch.

- Pendiente: Credenciales PID/UID/GID verificadas en conciliación; falta provisión confiable de política, ciclo de vida y permisos del ejecutor real.
- Pending: PID/UID/GID credentials verified in reconciliation; trusted policy provisioning, lifetime and real-executor permissions remain pending.
- Verificación prevista / Planned verification: `TF-03` — Fragmentar cabeceras y cuerpos, truncar, exceder límites, denegar acceso al socket y perder la conexión.
- Planned check: Fragment headers and bodies, truncate, exceed limits, deny socket access and disconnect.
- Obligaciones / Obligations: AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-04

Todos los mensajes declarados tienen perfiles de éxito, rechazo e incertidumbre aplicables; identidades, versiones y referencias se verifican también semánticamente.

All declared messages have applicable success, rejection and uncertainty profiles; identities, versions and references are also checked semantically.

- Pendiente: Política temporal y resolución estructural implementadas; quedan vínculo físico del reloj y semántica de soportes/perfiles externos.
- Pending: Temporal policy and structural resolution implemented; physical clock binding and external support/profile semantics remain pending.
- Verificación prevista / Planned verification: `TF-04` — Cubrir descubrimiento, ejecución, consulta/respuesta, supervisión, rechazo, estado persistido y cierre; alterar identidad, versión, referencia y productor.
- Planned check: Cover discovery, execution, query/response, supervision, rejection, persisted state and closure; alter identity, version, reference and producer.
- Obligaciones / Obligations: AL-07, AL04-R01, AL04-R03
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-05

Un mensaje idéntico recupera su respuesta durable; un duplicado distinto produce conflicto; cambiar message_id no permite reutilizar attempt_id.

An identical message retrieves its durable response; a changed duplicate conflicts; changing message_id cannot reuse attempt_id.

- Pendiente: Verificar cero ejecuciones físicas extra con ejecutor real.
- Pending: Verify zero extra physical executions with the real executor.
- Verificación prevista / Planned verification: `TF-05` — Repetir mensajes antes y después de reiniciar; cambiar contenido o contexto; comprobar cero ejecuciones adicionales.
- Planned check: Repeat messages before and after restart; change content or context; verify zero additional executions.
- Obligaciones / Obligations: AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-06

La evaluación tipada es determinista; solo VERDADERO habilita acciones; ND no equivale a FALSO ni a cero.

Typed evaluation is deterministic; only TRUE enables actions; ND is neither FALSE nor zero.

- Pendiente: A1 no implementado.
- Pending: A1 not implemented.
- Verificación prevista / Planned verification: `TF-06` — Tablas completas de operadores y decisiones, campos ausentes, tipos inválidos, reglas ambiguas y orden de entrada permutado.
- Planned check: Complete operator and decision tables, missing fields, invalid types, ambiguous rules and permuted input order.
- Obligaciones / Obligations: AL-06
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-07

La configuración válida se congela; identidades son únicas; se verifican referencias, pesos, dependencias y límites. Et inicia en cero, Rf en R0, Q en PREPARADO e historia de transiciones vacía.

Valid configuration is frozen; identities are unique; references, weights, dependencies and limits are checked. Et starts at zero, Rf at R0, Q at PREPARADO and transition history empty.

- Pendiente: El contrato preserva valores congelados entre instantáneas ancladas; A2 y la validación completa de configuración siguen pendientes.
- Pending: The contract preserves frozen values across anchored snapshots; A2 and complete configuration validation remain pending.
- Verificación prevista / Planned verification: `TF-07` — Configuración válida y variantes con duplicados, ciclos no permitidos, pesos inválidos, referencias ausentes y cambio posterior de configuración.
- Planned check: Valid configuration and variants with duplicates, forbidden cycles, invalid weights, missing references and later configuration changes.
- Obligaciones / Obligations: AL-06, AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-08

Los controles respetan origen, autorización, precedencia y consumo único. Los planes potenciales son finitos y operan sobre copias sin crear evidencia real.

Controls preserve origin, authorization, precedence and single consumption. Potential plans are finite and operate on copies without creating real evidence.

- Pendiente: A3 y controles verificados no implementados.
- Pending: A3 and verified controls not implemented.
- Verificación prevista / Planned verification: `TF-08` — Guardas VERDADERO/FALSO/ND, dependencias, control consumido, planes cíclicos y comprobación de que la simulación no altera el estado original.
- Planned check: TRUE/FALSE/ND guards, dependencies, consumed controls, cyclic plans and verification that simulation leaves original state unchanged.
- Obligaciones / Obligations: AL-06, AL-07
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### AC-09

Solo se seleccionan candidatos autorizados del servicio PENDIENTE y con presupuesto; se minimiza la clave (-PA, precedencia, id_servicio, id_caso).

Only authorized candidates from PENDIENTE services with remaining budget are selected; minimize (-PA, precedence, service_id, case_id).

- Pendiente: A4 no implementado; oráculos no son ejecución del motor.
- Pending: A4 not implemented; oracles are not engine execution.
- Verificación prevista / Planned verification: `TF-09` — Enumerar candidatos como oráculo independiente; probar empates, entrada permutada, prioridad alta no autorizada y conjunto vacío.
- Planned check: Enumerate candidates as an independent oracle; test ties, permuted input, unauthorized high priority and an empty set.
- Obligaciones / Obligations: AL-06
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-10

La intención y la decisión son durables; aceptación no acredita inicio. El contador aumenta una vez al incorporar inicio verificado; no inicio verificable no consume ejecución.

Intent and decision are durable; acceptance does not prove start. The counter increases once when verified start is incorporated; verified non-start consumes no execution.

- Pendiente: Contadores contrastados con recibos incorporados; falta supervisión física, catálogo, presupuestos y autorización de repetición.
- Pending: Counters checked against incorporated receipts; physical supervision, catalog, budgets and repeat authorization remain pending.
- Verificación prevista / Planned verification: `TF-10` — Aceptar sin iniciar, acreditar inicio, repetir el evento y restaurar sesiones; comprobar reserva, contador y límite de una o dos ejecuciones autorizadas.
- Planned check: Accept without starting, prove start, repeat the event and restore sessions; check reservation, counter and the one-or-two authorized execution limit.
- Obligaciones / Obligations: AL-06, AL-07, AL04-R01
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-11

Solo existe una acción técnica pendiente de conciliación; inicio, terminación o limpieza inciertos bloquean nuevos despachos y no causan reejecución automática.

Only one technical action awaits reconciliation; uncertain start, termination or cleanup blocks new dispatch and never causes automatic re-execution.

- Pendiente: Conciliación física y limpieza real no integradas.
- Pending: Physical reconciliation and actual cleanup not integrated.
- Verificación prevista / Planned verification: `TF-11` — Perder respuesta antes/después del inicio, exceder esperas y fallar limpieza; consultar la identidad original y agotar conciliación sin fabricar confirmación.
- Planned check: Lose responses before/after start, exceed waits and fail cleanup; query the original identity and exhaust reconciliation without fabricating confirmation.
- Obligaciones / Obligations: AL-07, AL04-R01, AL04-R02, AL04-R03
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-12

El ejecutor aplica perfiles congelados, argumentos separados sin shell, alcance y límites. Conserva soportes y limpia únicamente artefactos previstos; código cero no acredita evidencia.

The executor enforces frozen profiles, separate arguments without a shell, scope and limits. It preserves supporting artifacts and cleans only intended artifacts; zero exit code does not prove evidence.

- Pendiente: Ejecutor real y perfiles autorizados no integrados.
- Pending: Real executor and authorized profiles not integrated.
- Verificación prevista / Planned verification: `TF-12` — Destinos/argumentos no autorizados, timeout, salida truncada, hijos activos y limpieza fallida; verificar conservación de archivos ajenos y referencias protegidas.
- Planned check: Unauthorized targets/arguments, timeout, truncated output, live children and failed cleanup; verify unrelated files remain intact and references are protected.
- Obligaciones / Obligations: AL-07, AL04-R01, AL04-R02
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### AC-13

Cada condición se clasifica por soportes, procedencia, parámetros y reglas; se distinguen POSITIVO_VALIDO, NEGATIVO_VALIDO, INCONCLUSO, INCIDENCIA, INVALIDO y NO_ADMITIDO.

Each condition is classified using supporting artifacts, provenance, parameters and rules; distinguish POSITIVO_VALIDO, NEGATIVO_VALIDO, INCONCLUSO, INCIDENCIA, INVALIDO and NO_ADMITIDO.

- Pendiente: A6 y clasificación efectiva no implementados.
- Pending: A6 and effective classification not implemented.
- Verificación prevista / Planned verification: `TF-13` — Casos de cada clasificación, soportes alterados o faltantes, salida cero sin prueba y varias condiciones en un intento.
- Planned check: Cases for every classification, altered or missing artifacts, zero exit without proof and multiple conditions in one attempt.
- Obligaciones / Obligations: AL-06, AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-14

Una condición conserva clave, revisiones y soportes; duplicados no inflan evidencia. Las contradicciones bloquean conclusiones dependientes y solo resoluciones verificadas cambian vigencia.

A condition preserves its key, revisions and artifacts; duplicates do not inflate evidence. Contradictions block dependent conclusions and only verified resolutions change validity.

- Pendiente: A6 y repositorio analítico de revisiones no implementados.
- Pending: A6 and analytical revision repository not implemented.
- Verificación prevista / Planned verification: `TF-14` — Duplicar soportes, contradecir perfiles y retirar el máximo; probar resolución autorizada, no autorizada e indicadores de aceptación sin respaldo.
- Planned check: Duplicate artifacts, contradict profiles and withdraw the maximum; test authorized/unauthorized resolutions and unsupported acceptance flags.
- Obligaciones / Obligations: AL-06, AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-15

Normalizaciones, criticidad y contribuciones reproducen las ecuaciones; Et es el máximo vigente, no una suma. Sustituciones negativas autorizadas no alteran R0 ni anulan positivos vigentes.

Normalizations, criticality and contributions reproduce the equations; Et is the current maximum, not a sum. Authorized negative substitutions neither alter R0 nor cancel valid positives.

- Pendiente: A7 no implementado; cálculo de referencias no es cálculo de producción.
- Pending: A7 not implemented; reference calculation is not production calculation.
- Verificación prevista / Planned verification: `TF-15` — Oráculos racionales independientes, extremos ordinales, evidencia vacía/negativa/positiva, retiro de vigencia y sustituciones incompatibles.
- Planned check: Independent rational oracles, ordinal extremes, empty/negative/positive evidence, withdrawal and incompatible substitutions.
- Obligaciones / Obligations: AL-06
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-16

Prioridad y riesgo se calculan con sus fórmulas respectivas; ajustes simultáneos cumplen R0- <= D <= Rf <= U <= 1. No hay redondeo interno ni uso de Rref.

Priority and risk use their respective formulas; simultaneous adjustments satisfy R0- <= D <= Rf <= U <= 1. No internal rounding or use of Rref occurs.

- Pendiente: A7 y validación de derivados no implementados.
- Pending: A7 and derived-value validation not implemented.
- Verificación prevista / Planned verification: `TF-16` — Comparar resultados exactos con cálculo independiente; extremos, ajustes simultáneos, ND, pesos principales y variantes operacionales válidas.
- Planned check: Compare exact results against independent calculations; extremes, simultaneous adjustments, ND, main weights and valid operational alternatives.
- Obligaciones / Obligations: AL-06
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-17

La ventana contiene solo actualizaciones computables; retransmisiones no cuentan. Reinicios conservan historia y prevalecen según configuración; estabilidad numérica sola no permite cierre.

The window contains only computable updates; retransmissions do not count. Resets preserve history and follow configuration precedence; numeric stability alone cannot close a service.

- Pendiente: A7/A8 y ventana analítica no implementados.
- Pending: A7/A8 and analytical window not implemented.
- Verificación prevista / Planned verification: `TF-17` — Tres variaciones admisibles, ventana incompleta, duplicados, contradicción, reanudación y reinicio coincidente con actualización.
- Planned check: Three admissible variations, incomplete window, duplicates, contradiction, resumption and reset coinciding with an update.
- Obligaciones / Obligations: AL-06
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-18

Se verifican ES, SA, CV y LE completos; se registran todos los criterios verdaderos y prevalece ES > SA > CV > LE. Seguridad y controles conservan su precedencia; estados terminales no se reabren.

Full ES, SA, CV and LE predicates are checked; all true criteria are recorded with ES > SA > CV > LE. Safety and controls preserve their precedence; terminal states never reopen.

- Pendiente: Orden de criterios representado; cálculo y soporte de criterios A8 pendientes.
- Pending: Criterion ordering represented; A8 criterion calculation and support pending.
- Verificación prevista / Planned verification: `TF-18` — Cada criterio, coincidencias, contraejemplos, incertidumbre y pausa externa conciliada; intentar reabrir CERRADO/DETENIDO.
- Planned check: Each criterion, simultaneous criteria, counterexamples, uncertainty and reconciled external pause; attempt reopening CERRADO/DETENIDO.
- Obligaciones / Obligations: AL-06, AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-19

La transición comprueba origen, configuración, espacio, historia, estado, derivados e integridad sobre una copia; el rechazo conserva íntegramente la generación anterior.

Transition checks origin, configuration, scope, history, state, derived values and integrity on a copy; rejection preserves the entire previous generation.

- Pendiente: Transición operacional, identidad estructural y anclaje cubiertos; A9, fuentes de guardas e invariantes analíticos completos pendientes.
- Pending: Operational transition, structural identity and anchoring covered; A9, guard sources and complete analytical invariants pending.
- Verificación prevista / Planned verification: `TF-19` — Alterar por separado cada grupo de invariantes; comprobar rechazo, ausencia de mutación y confirmación íntegra del candidato válido.
- Planned check: Alter each invariant group separately; verify rejection, no mutation and complete confirmation of a valid candidate.
- Obligaciones / Obligations: AL-06, AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-20

Exclusión de escritura, generaciones inmutables, manifiestos y sincronización aseguran publicación íntegra; la autoridad se obtiene del puntero verificado, no de marcas aisladas.

Writer exclusion, immutable generations, manifests and synchronization ensure complete publication; authority comes from the verified pointer, not isolated markers.

- Pendiente: Archivo, instantánea, recibo y generación anclados y recuperables; otras seis cargas, custodia de frescura y garantías físicas del laboratorio pendientes.
- Pending: Archive, snapshot, receipt and generation bound and recoverable; other six payloads, freshness custody and physical laboratory guarantees pending.
- Verificación prevista / Planned verification: `TF-20` — Inyectar fallos de escritura, sincronización y reemplazo; intentar dos escritores y corromper manifiesto/puntero; conservar una generación verificable o detener recuperación.
- Planned check: Inject write, synchronization and replacement failures; attempt two writers and corrupt manifest/pointer; preserve a verifiable generation or stop recovery.
- Obligaciones / Obligations: AL-06, FRESHNESS-CUSTODY, FILESYSTEM-POWER-LOSS
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-21

La recuperación distingue decisión, intención, resultado durable, generación escrita y puntero publicado; reprocesar el resultado no repite la herramienta ni duplica efectos.

Recovery distinguishes decision, intent, durable result, written generation and published pointer; replaying a result neither reruns the tool nor duplicates effects.

- Pendiente: Recuperación de anclaje y contadores cubierta por SIGKILL; recuperación del ejecutor real y del motor A1-A10 pendientes.
- Pending: Anchor and counter recovery covered by SIGKILL; real-executor and A1-A10 recovery pending.
- Verificación prevista / Planned verification: `TF-21` — Interrumpir en cada frontera y reiniciar repetidamente; comparar identidad, contador, efectos y autoridad con una ejecución sin interrupción.
- Planned check: Interrupt at every boundary and restart repeatedly; compare identity, counter, effects and authority against an uninterrupted run.
- Obligaciones / Obligations: AL-06, AL-07, FRESHNESS-CUSTODY, FILESYSTEM-POWER-LOSS, AL04-R01, AL04-R03
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-22

El coordinador integra A1-A9; la supervisión registra intervenciones autorizadas. FINALIZADA/PAUSADA/DETENIDA son salidas distintas de los estados del servicio y refieren una generación confirmada.

The coordinator integrates A1-A9; supervision records authorized interventions. FINALIZADA/PAUSADA/DETENIDA differ from service states and refer to a confirmed generation.

- Pendiente: Salidas de invocación modeladas; A10 e interfaz operativa pendientes.
- Pending: Invocation outcomes modeled; A10 and operational interface pending.
- Verificación prevista / Planned verification: `TF-22` — Recorridos completos, pausa/reanudación, parada de seguridad, intervención inválida y salida de emergencia; verificar motivos, referencias y asuntos sin conciliar.
- Planned check: Complete flows, pause/resume, safety stop, invalid intervention and emergency exit; verify reasons, references and unreconciled matters.
- Obligaciones / Obligations: AL-06, AL-07
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-23

Mismo estado, configuración y eventos producen mismas decisiones y resultados. El avance consume recursos finitos o termina; con M combinaciones, ejecuciones <= 2M y esperas externas acotadas.

The same state, configuration and events produce the same decisions and results. Progress consumes finite resources or terminates; with M combinations, executions <= 2M and external waits are bounded.

- Pendiente: A1-A10, terminación integral y medición de costes pendientes.
- Pending: A1-A10, integrated termination and cost measurement pending.
- Verificación prevista / Planned verification: `TF-23` — Reordenar entradas, reproducir eventos, buscar ciclos sin progreso y escalar casos/evidencias; medir costes frente al análisis sin inventar un umbral de rendimiento.
- Planned check: Reorder inputs, replay events, seek non-progress cycles and scale cases/evidence; measure costs against the analysis without inventing a performance threshold.
- Obligaciones / Obligations: AL-06
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### AC-24

El laboratorio SSH/FTP/SMB está autorizado y aislado; límites y perfiles se congelan tras pilotaje. Simulaciones no modifican contadores reales, evidencia experimental ni I7.

The SSH/FTP/SMB laboratory is authorized and isolated; limits and profiles are frozen after piloting. Simulations never modify real counters, experimental evidence or I7.

- Pendiente: Laboratorio controlado y verificación física de aislamiento pendientes.
- Pending: Controlled laboratory and physical isolation verification pending.
- Verificación prevista / Planned verification: `TF-24` — Verificar aislamiento y restauración; pérdida de alcance, cambio material y limpieza insegura detienen acciones; comprobar separación de simulación y experimentación.
- Planned check: Verify isolation and restoration; scope loss, material change and unsafe cleanup stop actions; check simulation/experiment separation.
- Obligaciones / Obligations: AL-07, AL04-R02
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### AC-25

El diseño prevé 54 unidades servicio-escenario, 18 por protocolo; referencia externa y elegibilidad se definen antes de medir. Intentos no aumentan n y exclusiones quedan justificadas.

The design targets 54 service-scenario units, 18 per protocol; external reference and eligibility are defined before measurement. Attempts do not increase n and exclusions are justified.

- Pendiente: Diseño desglosado en MET; instrumentos, muestra y evaluabilidad sin ejecución.
- Pending: Design detailed in MET; instruments, sample and evaluability not executed.
- Verificación prevista / Planned verification: `TE-25` — Auditar manifiesto, referencia congelada, separación de Rref y pares comparables; revisar ausencias, unidades no evaluables y posibles dependencias entre observaciones.
- Planned check: Audit manifest, frozen reference, Rref separation and comparable pairs; review missing data, non-evaluable units and possible dependencies between observations.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### AC-26

Se comparan errores absolutos de R0 y Rf frente a Rref mediante el plan emparejado: MAE, Wilcoxon, alfa 0,05, tamaño del efecto y sensibilidad. El resultado puede no apoyar la hipótesis.

Compare R0 and Rf absolute errors against Rref using the paired plan: MAE, Wilcoxon, alpha 0.05, effect size and sensitivity. Results may not support the hypothesis.

- Pendiente: Contraste, potencia y análisis por ejecutar tras congelamiento.
- Pending: Test, power analysis and data analysis require execution under the prespecified protocol.
- Verificación prevista / Planned verification: `TE-26` — Fijar previamente hipótesis, tratamiento de ceros/empates/ausencias y sensibilidad; verificar cálculos con datos sintéticos separados y ejecutar después sobre datos reales trazables.
- Planned check: Predefine hypotheses, zero/tie/missing-data handling and sensitivity; verify calculations on separate synthetic data, then run them on traceable real data.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### AC-27

Un tercero puede reconstruir resultados desde versión, configuración, eventos y soportes conservados; el informe distingue cierre operativo, corrección funcional y resultado experimental.

A third party can reconstruct results from preserved version, configuration, events and artifacts; the report distinguishes operational closure, functional correctness and experimental outcome.

- Pendiente: Reproducción de componentes disponible; reproducción independiente del sistema y experimento pendiente.
- Pending: Component reproduction available; independent system and experiment reproduction pending.
- Verificación prevista / Planned verification: `TF-27` — Instalar desde entorno limpio, reproducir el análisis y comparar resultados; comprobar huellas, referencias y discrepancias documentadas.
- Planned check: Install in a clean environment, replay the analysis and compare results; check hashes, references and documented discrepancies.
- Obligaciones / Obligations: AL-06, AL-07, FRESHNESS-CUSTODY, FILESYSTEM-POWER-LOSS
- Evidencia / Evidence: EV-MAIN26-CI: suites de componentes / component suites

### MET-01

Comparación emparejada por servicio-escenario bajo condiciones equivalentes.

Paired service-scenario comparison under equivalent conditions.

- Pendiente: Protocolo de comparación y registros I1/I8.
- Pending: Comparison protocol and I1/I8 records.
- Verificación prevista / Planned verification: `TM-01` — Protocolo de comparación y registros I1/I8.
- Planned check: Comparison protocol and I1/I8 records.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-02

Congelar el método estático antes de pruebas técnicas y de conocer salidas ARDREC; conservar originales de correcciones justificadas.

Freeze the static method before technical tests and before seeing ARDREC outputs; preserve originals of justified corrections.

- Pendiente: I2 con versión, fecha, fuentes, responsable y cierre.
- Pending: I2 with version, date, sources, responsible person and closure.
- Verificación prevista / Planned verification: `TM-02` — I2 con versión, fecha, fuentes, responsable y cierre.
- Planned check: I2 with version, date, sources, responsible person and closure.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-03

Rúbrica independiente y verificación mínima común definidas sin resultados ni reglas internas de los métodos.

Independent rubric and common minimum verification defined without method outputs or internal rules.

- Pendiente: I4 validada y paquete uniforme de evidencia.
- Pending: Validated I4 and uniform evidence package.
- Verificación prevista / Planned verification: `TM-03` — I4 validada y paquete uniforme de evidencia.
- Planned check: Validated I4 and uniform evidence package.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-04

Cegar al evaluador cuando sea viable; documentar información disponible y medidas si no lo es.

Blind the evaluator where feasible; otherwise document available information and mitigation.

- Pendiente: Registro de acceso y condiciones de valoración.
- Pending: Access and assessment-condition record.
- Verificación prevista / Planned verification: `TM-04` — Registro de acceso y condiciones de valoración.
- Planned check: Access and assessment-condition record.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-05

Demostración mínima suficiente; no aplicable, inconcluso y ausencia de evidencia no se convierten automáticamente en puntuaciones.

Minimum sufficient demonstration; inapplicability, inconclusive outcomes and missing evidence do not automatically become scores.

- Pendiente: Reglas previas y registros de incidencias.
- Pending: Predefined rules and incident records.
- Verificación prevista / Planned verification: `TM-05` — Reglas previas y registros de incidencias.
- Planned check: Predefined rules and incident records.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-06

Wilcoxon emparejado unilateral, dirección menor error absoluto ARDREC y alfa 0,05.

One-sided paired Wilcoxon, direction of lower ARDREC absolute error and alpha 0.05.

- Pendiente: Plan estadístico previo, software y verificación con datos sintéticos separados.
- Pending: Prespecified statistical plan, software and verification using separate synthetic data.
- Verificación prevista / Planned verification: `TM-06` — Plan estadístico previo, software y verificación con datos sintéticos separados.
- Planned check: Prespecified statistical plan, software and verification using separate synthetic data.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-07

Informar dirección, magnitud, tamaño del efecto, consistencia y relevancia; separar análisis secundarios preespecificados.

Report direction, magnitude, effect size, consistency and relevance; separate prespecified secondary analyses.

- Pendiente: Plantilla de análisis; comparador contextual y ablaciones congelados sin ajuste por Rref.
- Pending: Analysis template; contextual comparator and ablations frozen without Rref-driven tuning.
- Verificación prevista / Planned verification: `TM-07` — Plantilla de análisis; comparador contextual y ablaciones congelados sin ajuste por Rref.
- Planned check: Analysis template; contextual comparator and ablations frozen without Rref-driven tuning.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-08

Predefinir ceros, empates, ausencias, atípicos, exclusiones y repeticiones; ningún descarte por favorecer la hipótesis.

Predefine zeros, ties, missing data, outliers, exclusions and repeats; no exclusions to favor the hypothesis.

- Pendiente: Reglas de evaluabilidad y registro de decisiones.
- Pending: Evaluability rules and decision record.
- Verificación prevista / Planned verification: `TM-08` — Reglas de evaluabilidad y registro de decisiones.
- Planned check: Evaluability rules and decision record.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-09

Planificar 54 unidades: 18 SSH, 18 FTP y 18 SMB; selección intencional sin generalización probabilística automática.

Plan 54 units: 18 SSH, 18 FTP and 18 SMB; purposive sampling without automatic probabilistic generalization.

- Pendiente: Manifiesto congelado de identidades y diferencias técnicas.
- Pending: Frozen manifest of identities and technical differences.
- Verificación prevista / Planned verification: `TM-09` — Manifiesto congelado de identidades y diferencias técnicas.
- Planned check: Frozen manifest of identities and technical differences.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-10

Repeticiones técnicas no aumentan n; unidades excluidas conservan identidad y registros; no reemplazar ni ampliar muestra tras congelamiento por resultados.

Technical repeats do not increase n; excluded units retain identity and records; do not replace or expand the frozen sample in response to results.

- Pendiente: Censo planificado/analizado y causas de exclusión.
- Pending: Planned/analyzed census and exclusion reasons.
- Verificación prevista / Planned verification: `TM-10` — Censo planificado/analizado y causas de exclusión.
- Planned check: Planned/analyzed census and exclusion reasons.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-11

Justificar potencia objetivo 0,80 con efecto mínimo, supuestos sobre diferencias/ceros, herramienta y resultado; 54 no garantiza potencia.

Justify target power 0.80 using minimum effect, assumptions on differences/zeros, tool and result; 54 does not guarantee power.

- Pendiente: Análisis de potencia previo sin datos definitivos.
- Pending: Prospective power analysis without definitive data.
- Verificación prevista / Planned verification: `TM-11` — Análisis de potencia previo sin datos definitivos.
- Planned check: Prospective power analysis without definitive data.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-12

Pilotaje separado de las 54 unidades; corregir antes del congelamiento y no incorporar datos piloto a la muestra principal.

Pilot separately from the 54 units; correct before freezing and exclude pilot data from the main sample.

- Pendiente: Manifiesto y datos piloto separados.
- Pending: Separate pilot manifest and data.
- Verificación prevista / Planned verification: `TM-12` — Manifiesto y datos piloto separados.
- Planned check: Separate pilot manifest and data.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-13

I1-I8 tienen finalidad distinta y el mismo identificador de servicio-escenario; la matriz no reemplaza registros originales.

I1-I8 have distinct purposes and share service-scenario identity; the matrix does not replace originals.

- Pendiente: Instrumentos versionados y procedencia de cada dato.
- Pending: Versioned instruments and per-datum provenance.
- Verificación prevista / Planned verification: `TM-13` — Instrumentos versionados y procedencia de cada dato.
- Planned check: Versioned instruments and per-datum provenance.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-14

Al menos tres especialistas pertinentes revisan independientemente claridad, coherencia, relevancia y suficiencia.

At least three relevant specialists independently assess clarity, coherence, relevance and sufficiency.

- Pendiente: I5, perfiles, valoraciones individuales, cambios y discrepancias conservados.
- Pending: I5, profiles, individual ratings, changes and disagreements preserved.
- Verificación prevista / Planned verification: `TM-14` — I5, perfiles, valoraciones individuales, cambios y discrepancias conservados.
- Planned check: I5, profiles, individual ratings, changes and disagreements preserved.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-15

Pilotar todos los instrumentos; fijar versión, fecha, instrucciones, responsable y reglas de incidencias/correcciones.

Pilot every instrument; specify version, date, instructions, responsible person and incident/correction rules.

- Pendiente: Instrumentos estables aprobados antes de recolección.
- Pending: Stable instruments approved before data collection.
- Verificación prevista / Planned verification: `TM-15` — Instrumentos estables aprobados antes de recolección.
- Planned check: Stable instruments approved before data collection.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-16

Con varios observadores verificar concordancia según plan; con uno no atribuir confiabilidad interobservador.

With multiple observers assess agreement as planned; with one do not claim inter-rater reliability.

- Pendiente: Diseño y resultado de evaluación de concordancia cuando corresponda.
- Pending: Agreement-assessment design and result where applicable.
- Verificación prevista / Planned verification: `TM-16` — Diseño y resultado de evaluación de concordancia cuando corresponda.
- Planned check: Agreement-assessment design and result where applicable.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

### MET-17

Conservar originales, transformaciones y huellas; ningún cambio manual silencioso de datos o matriz definitiva.

Preserve originals, transformations and hashes; no silent manual changes to data or the final matrix.

- Pendiente: Cadena de procedencia y reconstrucción independiente.
- Pending: Provenance chain and independent reconstruction.
- Verificación prevista / Planned verification: `TM-17` — Cadena de procedencia y reconstrucción independiente.
- Planned check: Provenance chain and independent reconstruction.
- Obligaciones / Obligations: Plan específico del requisito / Requirement verification plan
- Evidencia / Evidence: Sin ejecución acreditada / No execution evidence

## Componentes y comprobaciones / Components and checks

### NUMERIC

Racionales exactos y ND tipado; no evalúa reglas A1 ni calcula A7.

Exact rationals and typed ND; no A1 evaluation or A7 calculation.

- Requisitos / Requirements: AC-02, AC-15
- Módulos / Modules: `src/ardrec/contracts/__init__.py`
- Comprobaciones / Checks: 12; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### PROTOCOL

Perfiles y correlación de mensajes; referencias externas y autorización operacional pendientes.

Message profiles and correlation; external semantics and operational authorization pending.

- Requisitos / Requirements: AC-02, AC-04
- Módulos / Modules: `src/ardrec/messages.py`, `src/ardrec/messages_v1.py`, `src/ardrec/messages_v2.py`, `crates/ardrec-executor/src/messages.rs`, `crates/ardrec-executor/src/messages/v1.rs`, `crates/ardrec-executor/src/messages/v2.rs`, `crates/ardrec-executor/src/messages/json.rs`
- Comprobaciones / Checks: 59; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### TRANSPORT

Tramas y límites del canal; no ejecuta herramientas.

Framing and channel bounds; does not execute tools.

- Requisitos / Requirements: AC-03
- Módulos / Modules: `src/ardrec/transport.py`, `crates/ardrec-executor/src/transport.rs`
- Comprobaciones / Checks: 16; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### STATE

Estados operacionales y guardas suministradas; no produce guardas analíticas.

Operational states and supplied guards; does not produce analytical guards.

- Requisitos / Requirements: AC-01, AC-10, AC-11, AC-18, AC-19, AC-22, AC-24
- Módulos / Modules: `src/ardrec/state.py`
- Comprobaciones / Checks: 44; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### RECONCILIATION

Conciliación de resultados y recibos durables; ejecución física pendiente.

Durable result and receipt reconciliation; physical execution pending.

- Requisitos / Requirements: AC-05, AC-10, AC-11, AC-21, AC-27
- Módulos / Modules: `src/ardrec/reconciliation.py`
- Comprobaciones / Checks: 35; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### PERSISTENCE

Generaciones, diario y HEAD; aceptación física del almacenamiento pendiente.

Generations, journal and HEAD; physical storage acceptance pending.

- Requisitos / Requirements: AC-20, AC-21, AC-27
- Módulos / Modules: `src/ardrec/persistence/__init__.py`
- Comprobaciones / Checks: 40; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### JOURNAL

Diario técnico Rust; registrar no acredita ejecución real.

Rust technical journal; recording does not establish real execution.

- Requisitos / Requirements: AC-05, AC-10, AC-11, AC-21
- Módulos / Modules: `crates/ardrec-executor/src/journal.rs`, `crates/ardrec-executor/src/journal/model.rs`, `crates/ardrec-executor/src/journal/storage.rs`
- Comprobaciones / Checks: 37; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### SOCKET_RECONCILIATION

Consulta de intentos por socket sin nuevo despacho automático.

Socket attempt queries without automatic redispatch.

- Requisitos / Requirements: AC-03, AC-05, AC-11, AC-21
- Módulos / Modules: `src/ardrec/reconciliation_transport.py`, `crates/ardrec-executor/src/reconciliation_transport.rs`
- Comprobaciones / Checks: 26; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### MAGNITUDES

Formato exacto y archivo de magnitudes; no confirma A7.

Exact magnitude format and archive; does not establish A7.

- Requisitos / Requirements: AC-02, AC-15, AC-16, AC-20
- Módulos / Modules: `src/ardrec/persistence/magnitudes.py`, `crates/ardrec-executor/src/magnitudes.rs`
- Comprobaciones / Checks: 26; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### TEMPORAL

Reloj monotónico, duración y política temporal; vínculo con supervisor físico pendiente.

Monotonic timing, duration and temporal policy; physical supervisor binding pending.

- Requisitos / Requirements: AC-04, AC-10, AC-11, AC-21
- Módulos / Modules: `src/ardrec/temporal.py`, `crates/ardrec-executor/src/timing.rs`, `crates/ardrec-executor/src/messages/temporal.rs`
- Comprobaciones / Checks: 17; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### PROJECTION

Contrato de proyección y restricciones acotadas; no calcula estado analítico completo.

Projection contract and scoped constraints; does not compute full analytical state.

- Requisitos / Requirements: AC-02, AC-07, AC-15, AC-16, AC-17, AC-19
- Módulos / Modules: `src/ardrec/analytical.py`
- Comprobaciones / Checks: 21; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### REFERENCES

Resolución por hash, identidad y generación; no valida semántica de las otras seis cargas.

Hash, identity and generation resolution; does not validate the other six payload semantics.

- Requisitos / Requirements: AC-04, AC-14, AC-19
- Módulos / Modules: `src/ardrec/analytical_references.py`
- Comprobaciones / Checks: 27; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### ARCHIVE

Archivo inmutable; integridad no demuestra frescura ni resistencia a corte eléctrico.

Immutable archive; integrity does not establish freshness or power-loss durability.

- Requisitos / Requirements: AC-14, AC-20, AC-21, AC-27
- Módulos / Modules: `src/ardrec/persistence/analytical_archive.py`
- Comprobaciones / Checks: 27; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### ANCHOR

Instantánea anclada a generación; SIGKILL no equivale a pérdida eléctrica.

Snapshot bound to generation; SIGKILL is not power loss.

- Requisitos / Requirements: AC-07, AC-19, AC-20, AC-21, AC-27
- Módulos / Modules: `src/ardrec/persistence/__init__.py`, `src/ardrec/analytical_references.py`
- Comprobaciones / Checks: 25; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### COUNTERS

Contadores contrastados con recibos incorporados; catálogo y presupuestos pendientes.

Counters checked against incorporated receipts; catalog and budgets pending.

- Requisitos / Requirements: AC-10, AC-19, AC-20, AC-21
- Módulos / Modules: `src/ardrec/analytical_counters.py`, `src/ardrec/persistence/__init__.py`
- Comprobaciones / Checks: 31; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### PEER

Credenciales PID/UID/GID al conectar; provisión confiable de política y ciclo de vida pendientes.

PID/UID/GID at connection; trusted policy provisioning and lifetime pending.

- Requisitos / Requirements: AC-01, AC-03
- Módulos / Modules: `src/ardrec/peer_identity.py`, `crates/ardrec-executor/src/peer_identity.rs`
- Comprobaciones / Checks: 24; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### REFERENCE_AUDIT

Auditoría de oráculos independientes; no ejecuta A1-A10.

Independent reference-oracle audit; does not execute A1-A10.

- Requisitos / Requirements: AC-06, AC-07, AC-09, AC-13, AC-14, AC-15, AC-16
- Módulos / Modules: `tests/fixtures/model-reference-v1.json`, `tests/fixtures/selection-precedence-invalid-v1.json`
- Comprobaciones / Checks: 8; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

### TRACEABILITY_AUDIT

Enlaces de la matriz histórica; no acredita aceptación funcional.

Historical matrix links; does not establish functional acceptance.

- Requisitos / Requirements: AC-27
- Módulos / Modules: `scripts/verificar_trazabilidad.py`
- Comprobaciones / Checks: 10; identidades y comandos en `development-v2.json`.
- Evidencia de base / Baseline evidence: EV-MAIN26-CI

## Mantenimiento / Maintenance

Español: al cambiar un requisito o componente, actualizar sus vínculos, huellas, pruebas y evidencia en una revisión identificable. Registrar una comprobación pendiente cuando aún no exista. Conservar v1 y el cierre del punto 1. Ejecutar `python3 scripts/verificar_trazabilidad_actual.py` y la suite Python; CI repite la validación.

English: when a requirement or component changes, update links, hashes, checks and evidence in an identifiable revision. Keep missing checks explicitly planned. Preserve v1 and point 1 closure. Run the current traceability checker and Python suite; CI repeats validation.
