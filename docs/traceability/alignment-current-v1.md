# Revisión vigente de alineación / Current alignment review

## Español

**Resultado: revisión completada para el alcance enumerado, con hallazgos abiertos. La alineación completa no está acreditada.**

Fuente: **TESIS ARDREC**, SHA256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`. Base: `526276d382798cf5d0cda1d1966b9e0c49ad4d24`.
Se conservan la revisión de PR13, la matriz histórica, los resultados literales y el código de producción.
La copia revisada contiene 118 archivos conocidos. El aplicador verifica sus huellas y detecta fuentes seguidas por Git fuera del contexto antes de crear cambios. Los restantes archivos no revisados se enumeran; no se certifican por transitividad.
La CI de main comunicada por el usuario sirve como antecedente identificado, no como evidencia del nuevo incremento ni como validación experimental.

### Los cinco ámbitos

- **CONTRACTS** (3.2.9, 3.9.2, 3.9.3, 3.9.4): Contratos exactos Python, tramas y validadores operacionales de ambos lenguajes presentes. La identidad sintáctica no acredita artefactos ni causalidad física.
- **STATES** (3.5, 3.8.1, 3.9.10, 3.9.11): Se representan ocho estados del servicio, intento e invocación; incertidumbre y terminalidad tienen controles. El estado analítico completo y los productores de guardas no están implementados.
- **PERSISTENCE** (3.9.10, 3.10.1, 3.10.2): Hay diarios, exclusión, integridad, generaciones y recuperación operacional. La publicación analítica completa y las garantías del sistema de archivos del laboratorio necesitan validación adicional.
- **ACCEPTANCE** (1.9.3, 1.9.4, 1.9.5, 3.8, 3.9, 3.10): Se conservan los 27 criterios y 15 invariantes históricos. Una vista actual separa soporte de componentes, verificación integral y experimentación; desglosa obligaciones metodológicas vigentes.
- **REFERENCE_CASES** (3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.10): Los 51 casos son oráculos de referencia: 16 numéricos auditados por cálculo independiente y 35 casos semánticos documentados. No constituyen 51 pruebas contra algoritmos implementados ni cobertura exhaustiva de la tesis.

### Hallazgos y condiciones de cierre

| ID | Estado de la revisión | Condición de cierre |
| --- | --- | --- |
| AL-01 | RESOLVED_IN_REVIEW | Cada evidencia debe identificar fuente y commit examinados. |
| AL-02 | RESOLVED_IN_REVIEW | La trazabilidad siguiente debe vincular métodos de prueba y evidencia por requisito. |
| AL-03 | RESOLVED_IN_PR13 | A4 deberá contrastarse con los oráculos y rechazar el dominio inválido. |
| AL-04 | OPEN | Probar inversión temporal, ajuste UTC, duración, reinicio y lectura de diarios previos. Una comparación UTC aislada no debe autorizar ni repetir ejecución. |
| AL-05 | OPEN | Demostrar ida y vuelta exacta, fronteras, motivos ND, integridad, interrupciones y compatibilidad/migración sin pérdida. |
| AL-06 | OPEN | Cubrir caracterización congelada, R0/CN/Et/R0-/U/D/Rf/PA, evidencia, revisiones, contadores por caso, objetivos, historial, ventana y controles; comprobar guardas con sus fuentes. |
| AL-07 | OPEN | Probar par no autorizado, referencia cruzada/ausente/alterada, permisos, cambio de artefacto y perfiles congelados. Rechazar antes de ejecutar. |
| AL-08 | RESOLVED_IN_SPECIFICATION | Validar instrumentos, pilotar por separado y congelar protocolo, análisis y versiones antes de medir. |
| AL-09 | OPEN | Añadir un contrato numérico compartido o delimitar y justificar el intercambio; probar canonicidad, magnitudes límite y ND entre lenguajes. |

AL-02 y AL-08 quedan resueltos únicamente como actualización de especificación/cobertura. Sus requisitos funcionales y experimentales permanecen pendientes. AL-04, AL-05, AL-06, AL-07 y AL-09 siguen abiertos; registrarlos no corrige el código.

### Política temporal y compatibilidad

La secuencia causal exigida por la tesis no puede inferirse solo comparando fechas UTC. El contrato 2.0 actual impone algunas comparaciones UTC, pero admite resultados cuyo inicio precede a la fecha de solicitud. Un ajuste de reloj también puede producir una inversión sin alterar el orden físico. Falta decidir el contrato y su compatibilidad; no se declara corregido este hallazgo.
Antes de integrar el ejecutor, una decisión de ingeniería debe especificar reloj para plazos y duraciones, registro de ajustes UTC, identidad de la sesión de reloj y orden durable de eventos. Debe tratar reinicios y diferencias entre procesos sin restar valores monotónicos de dominios distintos. Estas decisiones son diseño pendiente, no reglas adicionales atribuidas a la tesis.
No se endurece silenciosamente el lector 2.0: la recuperación vuelve a validar registros almacenados. Se debe elegir y probar versión/migración o lectura histórica separada de admisión nueva, conservando bytes y procedencia. No se inventan tiempos para reparar registros.

### Estado analítico, persistencia y referencias

El estado objetivo de 3.9.10 requiere caracterización congelada, R0, CN, Et, línea sustituta, U, D, Rf, PA, repositorio de evidencia, contadores por caso, objetivos, historia, ventana y controles. La representación operacional existente es un componente válido pero insuficiente para publicar ese estado completo.
El límite de 256 bits del contrato Python y el límite de 64 bits de enteros operacionales son decisiones de implementación, no cotas matemáticas enunciadas por la tesis. El codec debe ampliarse mediante formato analítico versionado y rechazo explícito de desbordamientos, sin usar flotantes ni convertir ND en cero.
Las referencias válidas sintácticamente deben resolverse con identidad, existencia, pertenencia e integridad. Los diarios operacionales no sustituyen esa verificación ni la autenticación del proceso par. Las guardas del estado se reciben del llamador: A1/A3/A8/A9 deberán aportar comprobaciones efectivas.

### Criterios y metodología

La vista [current-coverage-v1.json](../acceptance/current-coverage-v1.json) cubre los 27 criterios sin modificar la matriz histórica. Los archivos enumerados son soporte parcial, no pruebas suficientes de aceptación integral. Los 17 requisitos MET siguientes complementan AC-25 a AC-27 y AC-24 cuando corresponde; no congelan el protocolo experimental.

- **MET-01** (1.9.3): Comparación emparejada por servicio-escenario bajo condiciones equivalentes. Evidencia exigida: Protocolo de comparación y registros I1/I8.
- **MET-02** (1.9.3): Congelar el método estático antes de pruebas técnicas y de conocer salidas ARDREC; conservar originales de correcciones justificadas. Evidencia exigida: I2 con versión, fecha, fuentes, responsable y cierre.
- **MET-03** (1.9.3): Rúbrica independiente y verificación mínima común definidas sin resultados ni reglas internas de los métodos. Evidencia exigida: I4 validada y paquete uniforme de evidencia.
- **MET-04** (1.9.3): Cegar al evaluador cuando sea viable; documentar información disponible y medidas si no lo es. Evidencia exigida: Registro de acceso y condiciones de valoración.
- **MET-05** (1.9.3): Demostración mínima suficiente; no aplicable, inconcluso y ausencia de evidencia no se convierten automáticamente en puntuaciones. Evidencia exigida: Reglas previas y registros de incidencias.
- **MET-06** (1.9.3): Wilcoxon emparejado unilateral, dirección menor error absoluto ARDREC y alfa 0,05. Evidencia exigida: Plan estadístico previo, software y verificación con datos sintéticos separados.
- **MET-07** (1.9.3): Informar dirección, magnitud, tamaño del efecto, consistencia y relevancia; separar análisis secundarios preespecificados. Evidencia exigida: Plantilla de análisis; comparador contextual y ablaciones congelados sin ajuste por Rref.
- **MET-08** (1.9.3): Predefinir ceros, empates, ausencias, atípicos, exclusiones y repeticiones; ningún descarte por favorecer la hipótesis. Evidencia exigida: Reglas de evaluabilidad y registro de decisiones.
- **MET-09** (1.9.4): Planificar 54 unidades: 18 SSH, 18 FTP y 18 SMB; selección intencional sin generalización probabilística automática. Evidencia exigida: Manifiesto congelado de identidades y diferencias técnicas.
- **MET-10** (1.9.4): Repeticiones técnicas no aumentan n; unidades excluidas conservan identidad y registros; no reemplazar ni ampliar muestra tras congelamiento por resultados. Evidencia exigida: Censo planificado/analizado y causas de exclusión.
- **MET-11** (1.9.4): Justificar potencia objetivo 0,80 con efecto mínimo, supuestos sobre diferencias/ceros, herramienta y resultado; 54 no garantiza potencia. Evidencia exigida: Análisis de potencia previo sin datos definitivos.
- **MET-12** (1.9.4): Pilotaje separado de las 54 unidades; corregir antes del congelamiento y no incorporar datos piloto a la muestra principal. Evidencia exigida: Manifiesto y datos piloto separados.
- **MET-13** (1.9.5): I1-I8 tienen finalidad distinta y el mismo identificador de servicio-escenario; la matriz no reemplaza registros originales. Evidencia exigida: Instrumentos versionados y procedencia de cada dato.
- **MET-14** (1.9.5): Al menos tres especialistas pertinentes revisan independientemente claridad, coherencia, relevancia y suficiencia. Evidencia exigida: I5, perfiles, valoraciones individuales, cambios y discrepancias conservados.
- **MET-15** (1.9.5): Pilotar todos los instrumentos; fijar versión, fecha, instrucciones, responsable y reglas de incidencias/correcciones. Evidencia exigida: Instrumentos estables aprobados antes de recolección.
- **MET-16** (1.9.5): Con varios observadores verificar concordancia según plan; con uno no atribuir confiabilidad interobservador. Evidencia exigida: Diseño y resultado de evaluación de concordancia cuando corresponda.
- **MET-17** (1.9.5): Conservar originales, transformaciones y huellas; ningún cambio manual silencioso de datos o matriz definitiva. Evidencia exigida: Cadena de procedencia y reconstrucción independiente.

### Verificación reproducible y paso a trazabilidad

Ejecutar `python scripts/verificar_alineacion_actual.py` con Python 3.14.7. Verifica documentos, cobertura y huellas; reproduce los dos problemas observados con entradas sintéticas. Con `--rust-probe RUTA` contrasta el caso temporal contra una sonda Rust compilada del mismo árbol. No ejecuta herramientas técnicas contra servicios.
Salida 0 significa auditoría completada y observaciones coincidentes con esta base; nunca conformidad completa. `--require-conformance` devuelve 2 mientras existan hallazgos abiertos. Un fallo de integridad, cobertura o ejecución devuelve 1. La sonda es un diagnóstico de brechas, no una prueba de aceptación que premie comportamientos incorrectos.
La próxima etapa puede construir la trazabilidad con estados pendientes explícitos. Para cada requisito: fuente vigente, algoritmo o responsabilidad de infraestructura, módulo, método de prueba, evidencia por commit, estado y hallazgo. La trazabilidad completa no convierte pendientes en cumplidos.
No se inicia A1–A10 ni el prototipo. Las implementaciones posteriores deben cerrar las condiciones anteriores mediante cambios y pruebas revisables.

## English

**Result: review complete for the listed scope, with open findings. Full alignment is not established.**

Source: **TESIS ARDREC**, SHA256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`. Baseline: `526276d382798cf5d0cda1d1966b9e0c49ad4d24`.
The PR13 review, historical matrix, literal reference outcomes and production code are preserved. The reconstructed copy contains 118 known files. The installer checks hashes and rejects additional Git-tracked implementation/protocol/test/script files before mutation. Other unreviewed files are listed and remain outside certification.
User-reported main CI is identified historical evidence, not evidence for this increment or experimental validation.

### Five reviewed domains

- **CONTRACTS** (3.2.9, 3.9.2, 3.9.3, 3.9.4): Exact Python contracts, frames and operational validators in both languages are present. Syntactic identity proves neither artifacts nor physical causality.
- **STATES** (3.5, 3.8.1, 3.9.10, 3.9.11): Eight service states, attempts and invocation outcomes are represented; uncertainty and terminality are controlled. Complete analytical state and guard producers are not implemented.
- **PERSISTENCE** (3.9.10, 3.10.1, 3.10.2): Journals, exclusion, integrity, generations and operational recovery exist. Complete analytical publication and laboratory filesystem guarantees need further validation.
- **ACCEPTANCE** (1.9.3, 1.9.4, 1.9.5, 3.8, 3.9, 3.10): The 27 historical criteria and 15 invariants are preserved. A current view separates component support, system verification and experimentation, and details current methodological obligations.
- **REFERENCE_CASES** (3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.10): The 51 cases are reference oracles: 16 numerical cases audited by independent calculation and 35 documented semantic cases. They are neither 51 tests against implemented algorithms nor exhaustive thesis coverage.

### Findings and closure gates

| ID | Review status | Closure condition |
| --- | --- | --- |
| AL-01 | RESOLVED_IN_REVIEW | Each evidence item must identify its reviewed source and commit. |
| AL-02 | RESOLVED_IN_REVIEW | The next traceability stage must link test methods and evidence per requirement. |
| AL-03 | RESOLVED_IN_PR13 | A4 must be checked against the oracles and reject the invalid domain. |
| AL-04 | OPEN | Test reversed timestamps, UTC adjustments, duration, restart and old journal readability. An isolated UTC comparison must not authorize or repeat execution. |
| AL-05 | OPEN | Demonstrate exact round trips, boundaries, ND reasons, integrity, interruptions and lossless compatibility/migration. |
| AL-06 | OPEN | Cover frozen characterization, R0/CN/Et/R0-/U/D/Rf/PA, evidence, revisions, per-case counters, objectives, history, window and controls; verify guards against their sources. |
| AL-07 | OPEN | Test unauthorized peers, cross-context/missing/altered references, permissions, artifact changes and frozen profiles. Reject before execution. |
| AL-08 | RESOLVED_IN_SPECIFICATION | Validate instruments, run a separate pilot and freeze protocol, analysis and versions before measurement. |
| AL-09 | OPEN | Add a shared numerical contract or delimit and justify interchange; test canonical form, boundary magnitudes and ND across languages. |

AL-02 and AL-08 are resolved only as specification/coverage updates. Functional and experimental requirements remain pending. AL-04, AL-05, AL-06, AL-07 and AL-09 remain open; recording them does not correct code.

### Timing and compatibility

Thesis-required causal order cannot be inferred from UTC comparisons alone. The current 2.0 contract imposes some UTC ordering but accepts outcomes starting before their request timestamp. Clock adjustments may also invert UTC ordering without changing physical order. Contract and compatibility decisions remain pending.
Before executor integration, an engineering decision must define deadline/duration clocks, UTC adjustment records, clock-session identity and durable event order. It must handle restart and process boundaries without subtracting monotonic values from different clock domains. These are pending engineering decisions, not extra thesis requirements.
Do not silently tighten the 2.0 reader: recovery revalidates stored records. Choose and test explicit versioning/migration or separate historical reading from new admission, retaining bytes and provenance. Do not fabricate corrected timestamps.

### Analytical state, storage and references

Section 3.9.10 requires frozen characterization, R0, CN, Et, substituted baseline, U, D, Rf, PA, evidence repository, per-case counters, objectives, history, window and controls. Current operational state is useful but insufficient to publish the complete analytical state.
The Python 256-bit component limit and operational 64-bit integer limit are implementation decisions, not mathematical thesis bounds. Extend storage with a versioned analytical format and explicit overflow rejection, without floats or ND-to-zero conversion.
Syntactically valid references require identity, existence, ownership and integrity verification. Operational journals replace neither these checks nor peer authentication. State guards come from the caller; A1/A3/A8/A9 must supply effective checks.

### Acceptance and methodology

[current-coverage-v1.json](../acceptance/current-coverage-v1.json) covers all 27 criteria without editing the historical matrix. Listed files provide partial support, not sufficient system acceptance evidence. The following 17 MET requirements supplement AC-25 through AC-27 and AC-24 where applicable; they do not freeze the experimental protocol.

- **MET-01** (1.9.3): Paired service-scenario comparison under equivalent conditions. Required evidence: Comparison protocol and I1/I8 records.
- **MET-02** (1.9.3): Freeze the static method before technical tests and before seeing ARDREC outputs; preserve originals of justified corrections. Required evidence: I2 with version, date, sources, responsible person and closure.
- **MET-03** (1.9.3): Independent rubric and common minimum verification defined without method outputs or internal rules. Required evidence: Validated I4 and uniform evidence package.
- **MET-04** (1.9.3): Blind the evaluator where feasible; otherwise document available information and mitigation. Required evidence: Access and assessment-condition record.
- **MET-05** (1.9.3): Minimum sufficient demonstration; inapplicability, inconclusive outcomes and missing evidence do not automatically become scores. Required evidence: Predefined rules and incident records.
- **MET-06** (1.9.3): One-sided paired Wilcoxon, direction of lower ARDREC absolute error and alpha 0.05. Required evidence: Prespecified statistical plan, software and verification using separate synthetic data.
- **MET-07** (1.9.3): Report direction, magnitude, effect size, consistency and relevance; separate prespecified secondary analyses. Required evidence: Analysis template; contextual comparator and ablations frozen without Rref-driven tuning.
- **MET-08** (1.9.3): Predefine zeros, ties, missing data, outliers, exclusions and repeats; no exclusions to favor the hypothesis. Required evidence: Evaluability rules and decision record.
- **MET-09** (1.9.4): Plan 54 units: 18 SSH, 18 FTP and 18 SMB; purposive sampling without automatic probabilistic generalization. Required evidence: Frozen manifest of identities and technical differences.
- **MET-10** (1.9.4): Technical repeats do not increase n; excluded units retain identity and records; do not replace or expand the frozen sample in response to results. Required evidence: Planned/analyzed census and exclusion reasons.
- **MET-11** (1.9.4): Justify target power 0.80 using minimum effect, assumptions on differences/zeros, tool and result; 54 does not guarantee power. Required evidence: Prospective power analysis without definitive data.
- **MET-12** (1.9.4): Pilot separately from the 54 units; correct before freezing and exclude pilot data from the main sample. Required evidence: Separate pilot manifest and data.
- **MET-13** (1.9.5): I1-I8 have distinct purposes and share service-scenario identity; the matrix does not replace originals. Required evidence: Versioned instruments and per-datum provenance.
- **MET-14** (1.9.5): At least three relevant specialists independently assess clarity, coherence, relevance and sufficiency. Required evidence: I5, profiles, individual ratings, changes and disagreements preserved.
- **MET-15** (1.9.5): Pilot every instrument; specify version, date, instructions, responsible person and incident/correction rules. Required evidence: Stable instruments approved before data collection.
- **MET-16** (1.9.5): With multiple observers assess agreement as planned; with one do not claim inter-rater reliability. Required evidence: Agreement-assessment design and result where applicable.
- **MET-17** (1.9.5): Preserve originals, transformations and hashes; no silent manual changes to data or the final matrix. Required evidence: Provenance chain and independent reconstruction.

### Reproducible audit and traceability handoff

Run `python scripts/verificar_alineacion_actual.py` under Python 3.14.7. It checks documents, coverage and hashes and reproduces both observed gaps using synthetic inputs. `--rust-probe PATH` compares the timing case with a Rust probe built from the same tree. It launches no technical tools against services.
Exit 0 means audit completion and observations consistent with this baseline, never full conformity. `--require-conformance` returns 2 while findings remain open. Integrity, coverage or execution failures return 1. The probe diagnoses gaps; it is not an acceptance test rewarding incorrect behavior.
Traceability can now be constructed with explicit pending states. Each requirement needs current source, algorithm or infrastructure responsibility, module, test method, commit-bound evidence, status and finding. Completing traceability does not turn pending requirements into fulfilled ones.
A1–A10 and the operational prototype remain unstarted. Later implementations must close the documented conditions through reviewable changes and tests.
