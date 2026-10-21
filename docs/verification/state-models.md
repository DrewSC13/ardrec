# Verificación de modelos de estado / State model verification

## Español

### Objetivo y alcance

Verificar los contratos operacionales del servicio, intento e invocación definidos en
`../adr/0004-modelos-de-estado.md`, conforme a TESIS ARDREC. La implementación está en
`src/ardrec/state.py`; la suite independiente, en `tests/unit/test_state.py`.

Las 44 pruebas utilizan los mensajes sintéticos existentes de protocolo 2.0. La tabla de
transiciones esperadas se declara en la prueba, sin importarla de la implementación.
Se contrastan 88 pares de origen y variante de transición: ocho estados por once
variantes, contando separadamente las dos rutas de T5. Esta exploración no es una
prueba formal exhaustiva del sistema completo.

| Requisito de TESIS ARDREC | Verificación representativa | Alcance comprobado |
|---|---|---|
| 3.5.1–3.5.3: estados y rutas | `test_all_service_edges_and_forbidden_origins` | Orígenes permitidos y prohibidos |
| 3.3.2 y 3.5.3: ND no habilita | `test_false_and_nd_never_enable_guards` | Cada guarda requerida, falsa y desconocida |
| 3.5.4: candidato separado | `test_complete_path_remains_candidate` | Conservación de generación y bloqueo de publicación pendiente |
| 3.5.2: terminalidad | `test_terminal_services_never_reopen` | Rechazo de reapertura en la misma observación |
| 3.5.5: incertidumbre no es pausa | `test_uncertainty_cannot_close_pause_or_continue` | Bloqueo de cierre, pausa y controles ordinarios |
| 3.5.3: nuevo permiso al reanudar | `test_resume_requires_a_new_authorization_reference` | Autorización distinta y espera identificada |
| 3.5.6: criterios ordinarios | `test_closure_records_all_criteria_and_declared_priority` | Registro ES/SA/CV/LE sin calcularlos |
| 3.9.2 y 3.9.6: aceptación ≠ inicio | `test_acceptance_does_not_start_service_or_increment_count` | Ausencia de ejecución ficticia |
| 3.9.1: una reserva global | `test_two_pending_attempts_are_invalid_even_on_distinct_services` | Exclusión entre servicios |
| 3.9.6: limpieza y conciliación | `test_cleanup_pending_unknown_failed_block_validation` | Bloqueo hasta resolución técnica |
| 3.9.3: duplicados | `test_replay_is_idempotent_and_conflict_rejected` | Identidad estable y conflicto de contenido |
| 3.9.3: consulta original | `test_queries_require_correlation_and_identity` | Asociación solicitud–consulta–respuesta |
| 3.4: contabilidad confirmada | `test_counter_needs_confirmed_incorporation` | Inicio consumido una sola vez; no inicio vale cero |
| 3.9.2: simulación | `test_simulation_does_not_enter_real_state_or_counters` | Separación de datos de prueba y recibos reales |
| 3.8.1: origen y configuración | `test_wrong_context_or_scope_rejected` | Rechazo de contexto, generación o alcance ajenos |
| 3.9.11: salida global separada | `test_stop_invocation_does_not_fabricate_service_stop` | Detención de invocación sin modificar servicios |
| 3.10.2: conservar autoridad | `test_unverified_authority_stops_only_invocation` | Bloqueo de despacho con autoridad desconocida |

También se prueban la conservación de hechos acreditados, cronología y diario;
los duplicados después de una pérdida de conexión; identidades de intentos provenientes
de otra invocación; límites enteros exactos; ausencia de alias mutables; rechazo de
consumo repetido de un evento y prohibición de cargar fases locales como publicadas.

### Ejecución reproducible

Desde la raíz del repositorio:

```bash
.venv/bin/python scripts/verificar_estados.py
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests/unit -p 'test_*.py' -v
```

El verificador exige Python 3.14.7, 44 métodos ejecutados sin omisiones y conservación
de la huella de `tests/fixtures/messages-v2.json`. La CI Python existente descubre
`test_state.py`; no se agregan dependencias, acciones ni permisos al workflow.
La CI de equivalencia Python–Rust continúa ejecutando su conjunto previo.

La preparación local registra en `docs/development/F7-modelos-estado.json` los resultados
observados, el commit base, las versiones y las huellas de archivos de referencia.
Ese registro se crea antes del commit y de la CI remota; sus estados pendientes en
ese instante no deben interpretarse como fallos ni cambiarse retrospectivamente.
La evidencia de CI remota corresponde al commit y al intento de ejecución del PR.

### Tres niveles separados

1. **Implementación:** estructuras y validadores operacionales disponibles.
2. **Verificación funcional del incremento:** los escenarios de esta suite satisfacen
   los resultados esperados; no acredita todos los criterios del sistema.
3. **Validación experimental:** no ejecutada; no se producen observaciones reales ni
   valores de riesgo para comparación externa.

La matriz `docs/acceptance/system-v1.json` y los estados de A1–A10 no se marcan como
aprobados por estas pruebas. Los contratos son infraestructura previa: no implementan
la evaluación de reglas, las ecuaciones, las decisiones adaptativas ni el prototipo
operacional. La recuperación durable y las garantías de publicación se verificarán en
su incremento correspondiente. Las guardas contienen resultados aportados por el
llamador; su verificación física y la integridad de sus soportes quedan fuera de esta suite.

## English

### Objective and scope

Verify service, attempt and invocation contracts from
`../adr/0004-modelos-de-estado.md`, grounded in TESIS ARDREC. Implementation:
`src/ardrec/state.py`. Independent tests: `tests/unit/test_state.py`.

The 44 tests reuse existing synthetic protocol 2.0 messages. The expected transition
table is declared independently in the tests. Eight service states and eleven
transition variants, including both T5 routes, produce 88 origin/transition pairs.
This is not a formal exhaustive proof of the complete system.

| TESIS ARDREC requirement | Representative test | Verified scope |
|---|---|---|
| 3.5.1–3.5.3: states and routes | `test_all_service_edges_and_forbidden_origins` | Allowed and forbidden origins |
| 3.3.2 and 3.5.3: unknown guards | `test_false_and_nd_never_enable_guards` | Every required guard, false and unknown |
| 3.5.4: candidate separation | `test_complete_path_remains_candidate` | Preserved generation and publication blocking |
| 3.5.2: terminality | `test_terminal_services_never_reopen` | No reopening within an observation |
| 3.5.5: uncertainty differs from pause | `test_uncertainty_cannot_close_pause_or_continue` | Ordinary closure, pause and control blocking |
| 3.5.3: resumption authorization | `test_resume_requires_a_new_authorization_reference` | New authorization and identified wait |
| 3.5.6: ordinary criteria | `test_closure_records_all_criteria_and_declared_priority` | ES/SA/CV/LE retained without calculating them |
| 3.9.2 and 3.9.6: acceptance differs from start | `test_acceptance_does_not_start_service_or_increment_count` | No fictional execution |
| 3.9.1: one global reservation | `test_two_pending_attempts_are_invalid_even_on_distinct_services` | Cross-service exclusion |
| 3.9.6: cleanup and reconciliation | `test_cleanup_pending_unknown_failed_block_validation` | Blocking until technical resolution |
| 3.9.3: duplicates | `test_replay_is_idempotent_and_conflict_rejected` | Stable identity and content conflict |
| 3.9.3: original query | `test_queries_require_correlation_and_identity` | Request–query–response association |
| 3.4: confirmed accounting | `test_counter_needs_confirmed_incorporation` | One consumed start; zero for no-start |
| 3.9.2: simulation | `test_simulation_does_not_enter_real_state_or_counters` | Separation from real incorporation receipts |
| 3.8.1: origin and configuration | `test_wrong_context_or_scope_rejected` | Foreign context, generation and scope rejection |
| 3.9.11: separate global outcome | `test_stop_invocation_does_not_fabricate_service_stop` | Invocation stop without changing services |
| 3.10.2: authority preservation | `test_unverified_authority_stops_only_invocation` | Dispatch blocked under unknown authority |

Additional tests cover established facts, chronology, journal continuity, replay after
connection loss, attempt identities across invocations, exact integer bounds, immutable
inputs, duplicate event consumption and rejection of local phases as published state.

### Reproduction and interpretation

Run the two commands in the Spanish section from the repository root. The verifier
requires Python 3.14.7, all 44 methods without skips and unchanged message fixtures.
Existing Python CI discovers `test_state.py`; no dependencies, Actions or permissions
are added. Existing Python–Rust protocol equivalence remains enabled.

`docs/development/F7-modelos-estado.json` records locally observed results, base commit,
versions and reference hashes before commit creation and remote CI. Pending statuses
at record creation are historical, not failures to rewrite retrospectively. Remote
verification must be associated with its exact PR commit and workflow attempt.

Implementation, functional verification of this increment and experimental validation
remain separate. The acceptance matrix and A1–A10 statuses are not promoted to passed.
These contracts do not implement rules, numerical calculations, adaptive decisions or
an operational prototype. Durable recovery, publication guarantees and external proof
verification remain subsequent work. No real experimental observations or risk values
are produced by these tests.
