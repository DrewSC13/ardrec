# Verificación del diario técnico / Technical journal verification

## Español

Fuente del modelo: TESIS ARDREC. El objetivo es comprobar el componente durable,
sin atribuirle ejecución real de herramientas ni aceptación global del sistema.

Desde la raíz del repositorio, con las versiones fijadas:

```bash
.venv/bin/python scripts/verificar_diario_tecnico.py
```

El verificador ejecuta 34 pruebas Rust, compila una sonda local y la usa exclusivamente
sobre directorios temporales con mensajes sintéticos. La sonda no es un servidor ni
una interfaz de ejecución de herramientas. El punto de fallo se activa explícitamente
por la prueba; el módulo de producción no lee variables de entorno para interrumpirse.

| Grupo | Casos ejercitados | Resultado exigido |
| --- | --- | --- |
| Identidad | Solicitudes repetidas, contenido distinto, reutilización de intento | Repetición sin escritura o rechazo de conflicto. |
| Semántica | Aceptación, incertidumbre, ejecución registrada, rechazo, terminales | No inferir inicio ni ausencia; conservar hechos y bloqueo de incertidumbre. |
| Resultado | Mensaje completo, identidad, enteros superiores a 2⁵³, limpieza posterior | Conservar bytes canónicos; no declarar disponibilidad sin resultado. |
| Consulta | Correlación, tiempos, identidad, repetición histórica | Respuesta exacta durable; ninguna autorización de ejecución. |
| Almacenamiento | Corrupción de HEAD y registros, secuencia inválida, operación desconocida | Rechazar recuperación sin retroceder ni reinicializar. |
| Concurrencia | Dos procesos y recuperación del bloqueo tras SIGKILL | Exclusión y apertura posterior sin cambiar registros. |

Se prueban 15 puntos por cada operación: registrar solicitud, registrar observación,
registrar resultado y responder consulta. Total: 60 casos SIGKILL.

Puntos: creación, escritura parcial, escritura completa, sincronización, enlace,
instalación y sincronización del directorio del registro; creación, escritura parcial,
escritura completa, sincronización, antes de sustituir, sustitución y sincronización
de HEAD; frontera anterior al acuse.

Cada hijo anuncia el punto y espera. El padre envía SIGKILL, comprueba la señal de salida,
abre dos veces el diario y verifica la generación anterior o la nueva completa, según
la frontera alcanzada. Después repite la operación: debe instalarse una sola vez o
recuperarse como repetición. También se cubre el enlace temporal huérfano.

El intercambio entre componentes registra una consulta en el almacén Python, obtiene
respuesta y resultado del diario Rust, verifica las correlaciones y los incorpora en
una única publicación Python. Después de reiniciar, exige `READY_FOR_VALIDATION`,
resultado exacto, generación confirmada intacta y cero ejecuciones incorporadas.
Ese estado exige validación posterior; no equivale a aceptar evidencia externa.

La CI añade el paso `Verificar diario técnico / Verify technical journal` al trabajo
Rust. Se mantienen los pasos existentes de transporte, equivalencia del protocolo,
compilación y descubrimiento unitario Python. El informe F9B se crea antes del commit;
los controles que exigen un árbol Git limpio se ejecutan sobre el commit firmado antes
de publicar. Sus resultados posteriores se registran en el PR y en la salida de terminal.

No se prueba pérdida eléctrica, ejecución de herramientas, autenticidad de soportes,
compactación, rendimiento experimental ni aceptación funcional de A1–A10.

## English

Model source: TESIS ARDREC. Verification targets the durable component, without claiming
real tool execution or whole-system acceptance.

Run from the repository root using the pinned toolchains:

```bash
.venv/bin/python scripts/verificar_diario_tecnico.py
```

The verifier runs 34 Rust tests, builds a local probe and uses temporary directories with
synthetic messages. The probe is neither a server nor a tool execution interface. Tests
explicitly activate fault hooks; the production module does not inspect environment
variables to crash itself.

| Group | Exercised cases | Required behavior |
| --- | --- | --- |
| Identity | Duplicate requests, changed content, attempt reuse | No-op replay or conflict rejection. |
| Semantics | Acceptance, uncertainty, recorded start, rejection, terminal phases | No inferred start/absence; retain facts and uncertainty blocking. |
| Outcome | Full message, identity, integers above 2⁵³, later cleanup | Preserve canonical bytes; no availability without the full outcome. |
| Query | Correlation, timestamps, identities, historical replay | Exact durable reply; no execution authorization. |
| Storage | Corrupt HEAD/records, invalid sequence, unknown operation | Reject recovery without rollback or reinitialization. |
| Concurrency | Two processes and SIGKILL lock release | Exclusive access followed by unchanged-state recovery. |

There are 15 crash points for each of four operations: register request, observe, record
outcome and answer. Total: 60 SIGKILL cases. Points span record creation/partial write/full
write/sync/link/install/directory sync; temporary HEAD creation/partial write/full write/sync;
before replacement, after replacement, root directory sync and acknowledgement boundary.

Each child announces its point and waits. The parent sends SIGKILL and checks the exit signal.
Two reopenings must recover either the preceding state or the complete new state. Retrying
the operation must install it once or replay it. Orphan temporary links are covered.

The component exchange durably registers a Python query, retrieves a Rust reply and original
outcome, checks correlations and publishes both atomically in Python. After restart it requires
`READY_FOR_VALIDATION`, exact outcome, unchanged confirmed generation and zero incorporated
executions. This status still requires later validation of external evidence.

CI adds `Verificar diario técnico / Verify technical journal` to the Rust job while retaining
transport, protocol equivalence, build and Python unit discovery. F9B is recorded before commit;
checks requiring a clean Git tree run on the signed commit before publication. Their later
results are recorded in the PR and terminal output.

Power loss, real tools, support authenticity, compaction, experimental performance and
functional acceptance of A1–A10 are outside these tests.
