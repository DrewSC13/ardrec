# Alineación de especificación y código / Specification and code alignment

## Español

Fuente vigente revisada: **TESIS ARDREC**, SHA256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.
Base de código: `8b0b889cdd27678cbb8c58eda997a98fa2960305`.

### Alcance y procedencia

Esta revisión compara contratos, estados, persistencia, criterios de aceptación y
casos de referencia con la especificación vigente. Se examinó una reconstrucción de
114 archivos a partir del contexto y del incremento F10 entregado. No constituye
una nueva descarga completa de GitHub. El aplicador verifica las huellas de esos
archivos contra el repositorio local antes de modificarlo; los archivos omitidos y el
registro dinámico F10 quedan fuera de la revisión de contenido.

La huella histórica `da959bd6ab8eb49df5c746f2bfc50df2633794a2c089a2a757ffc65ca39ae9ce` se conserva
en los registros anteriores. La matriz de aceptación describe su punto de partida;
no se reescriben sus estados históricos ni se declara que todo el sistema está alineado.
El catálogo mantiene su fuente original y añade `alignment_review` para identificar
el alcance de esta revisión. Una revisión posterior deberá verificar la cobertura completa.

### Corrección del catálogo

TESIS ARDREC, tabla 3.8, página impresa 136, define precedencias 1, 2, 3 y 4.
Se modifican exclusivamente ocho valores de entrada: REF-S01 pasa de [0,9] a [1,4];
los cuatro ceros de REF-S05 y los dos de REF-S07 pasan a 1. Se conservan los 51 casos,
sus identidades y todos los resultados esperados. REF-S01 sigue comprobando que la
prioridad se compara antes de la precedencia; REF-S05 y REF-S07 conservan sus causas
de inelegibilidad. Las referencias históricas no se convierten en resultados de producción.

Se agregan ocho entradas inválidas en un archivo separado: 0, 5, 9, -1, true, false,
"1" y null. Su resultado esperado pertenece a la auditoría del dominio del catálogo.
Las pruebas rechazan también números de punto flotante y comprueban los cuatro
valores válidos. No implementan selección, evaluación de reglas ni A1–A10.

### Hallazgos y continuidad

| Hallazgo | Situación | Trabajo siguiente |
| --- | --- | --- |
| AL-01, fuente | Procedencia vigente registrada; histórica conservada | Mantener alcance y versiones explícitos |
| AL-02, aceptación | Cobertura histórica anterior a los componentes recientes | Vincular pruebas actuales sin aceptar requisitos completos por pruebas parciales |
| AL-03, precedencia | Dominio de tres casos corregido | Conectar los oráculos al futuro algoritmo |
| AL-04, tiempo | Se aceptan fechas de ejecución anteriores a la solicitud | Definir causalidad, reloj monotónico y tratamiento de ajustes UTC |
| AL-05, persistencia | Enteros del codec limitados a 64 bits; contrato numérico de 256 bits | Definir formato analítico de racionales y ND y su migración |
| AL-06, estado | Representación operacional y guardas suministradas por el llamador | Especificar campos analíticos e invariantes completos |
| AL-07, referencias | La validación estructural no verifica artefactos externos | Resolver autorizaciones, perfiles y soportes y autenticar el par |
| AL-08, experimento | Criterios necesitan mayor desglose | Incorporar requisitos de las secciones 1.9.3–1.9.5 |

Los requisitos metodológicos incluyen contraste emparejado unilateral con alfa 0,05,
potencia objetivo 0,80 justificada, 54 unidades planificadas (18 por protocolo), piloto
separado, ausencia de reemplazos después del congelamiento y validación de contenido
por al menos tres especialistas. Ni el tamaño planificado garantiza la potencia ni una
prueba de software constituye validación experimental. La referencia técnica independiente
no debe utilizarse para ajustar el modelo.

### Verificación y límites

La revisión previa ejecutó 205 pruebas Python y 60 Rust en una reconstrucción aislada,
con resultado satisfactorio. Esta evidencia corresponde a la base, no al nuevo commit.
El aplicador ejecuta la suite Python después de introducir los cambios, registra salida
fuera del repositorio y solo crea el commit firmado si las pruebas concluyen correctamente.
Los archivos de producción, Cargo.lock, uv.lock y la matriz histórica quedan intactos.
La CI del nuevo commit debe verificarse después de su publicación.

Implementación de algoritmos: no iniciada. Prototipo operativo: no iniciado.
Alineación completa y aceptación funcional del sistema: pendientes.
Validación experimental: no ejecutada.

## English

Reviewed current source: **TESIS ARDREC**, SHA256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.
Code baseline: `8b0b889cdd27678cbb8c58eda997a98fa2960305`.

### Scope and provenance

This review compares contracts, states, persistence, acceptance criteria and reference
cases with the current specification. It examined 114 reconstructed files from the
provided context and F10 increment, not a fresh full GitHub checkout. The installer
checks those file hashes against the local repository before changing it. Omitted files
and the dynamic F10 record remain outside this content review.

The historical hash `da959bd6ab8eb49df5c746f2bfc50df2633794a2c089a2a757ffc65ca39ae9ce` is preserved
in previous records. The acceptance matrix describes its original baseline; its historical
statuses are not rewritten and complete system alignment is not claimed. The catalog
retains its original source and adds `alignment_review` to identify this review's scope.
A later review must verify complete coverage.

### Catalog correction

TESIS ARDREC, table 3.8, printed page 136, defines precedence levels 1, 2, 3 and 4.
Only eight input values change: REF-S01 changes [0,9] to [1,4]; four zero values in
REF-S05 and two in REF-S07 become 1. All 51 case identities and expected results are
preserved. REF-S01 still checks that priority precedes precedence; REF-S05 and REF-S07
retain their ineligibility reasons. Historical references do not become production results.

Eight invalid inputs are added separately: 0, 5, 9, -1, true, false, "1" and null.
Their expected outcome belongs to catalog domain auditing. Tests also reject floating
point numbers and check all four valid levels. They implement neither selection nor
rule evaluation nor A1–A10.

### Findings and follow-up

| Finding | Status | Next work |
| --- | --- | --- |
| AL-01, source | Current provenance recorded; historical source retained | Keep scope and versions explicit |
| AL-02, acceptance | Historical coverage predates recent components | Link current tests without accepting entire requirements from partial tests |
| AL-03, precedence | Three reference cases corrected | Connect the oracles to the future algorithm |
| AL-04, time | Execution timestamps before the request are accepted | Define causality, monotonic timing and UTC clock adjustments |
| AL-05, persistence | 64-bit codec integers versus 256-bit numerical contract | Define analytical rational and ND storage and migration |
| AL-06, state | Operational representation and caller-supplied guards | Specify full analytical fields and invariants |
| AL-07, references | Structural validation does not verify external artifacts | Resolve authorization, profiles and supports and authenticate the peer |
| AL-08, experiment | Criteria require further detail | Incorporate requirements from sections 1.9.3–1.9.5 |

Methodological requirements include a paired one-sided test with alpha 0.05, justified
target power 0.80, 54 planned units (18 per protocol), a separate pilot, no replacement
after freezing and content validation by at least three specialists. Planned sample size
does not guarantee power, and software tests do not constitute experimental validation.
The independent technical reference must not be used to tune the model.

### Verification and limits

The prior review ran 205 Python and 60 Rust tests successfully in an isolated reconstruction.
This evidence describes the baseline, not the new commit. The installer runs the Python
suite after applying the changes, stores its output outside the repository and creates
the signed commit only if testing succeeds. Production files, Cargo.lock, uv.lock and
the historical matrix are preserved. CI for the new commit must be checked after publishing.

Algorithm implementation and operational prototype have not started. Full specification
alignment and system functional acceptance remain pending. Experimental validation has not run.
