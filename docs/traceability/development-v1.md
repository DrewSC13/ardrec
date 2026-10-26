# Trazabilidad del desarrollo / Development traceability

## Español

Esta matriz vincula **27 criterios del sistema y 17 obligaciones metodológicas** con sus responsabilidades, módulos, métodos de prueba, oráculos y evidencias. Su base es `e72830432bc1c26cf5f8679752eddf28077e82a0` y la fuente vigente es **TESIS ARDREC**, SHA256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

La matriz histórica conserva su procedencia. Las secciones de los criterios se heredan como localizadores y se complementan con la revisión vigente; no se afirma una auditoría exhaustiva de cada oración de la tesis. Los seis archivos ajenos al contexto anterior siguen fuera del alcance certificado.

**Tener un vínculo no demuestra cumplimiento.** Los 210 métodos Python se inventarían por nombre y archivo; cuatro scripts representan comprobaciones de integración. Las salidas recibidas acreditan el resultado reportado del flujo, no resultados individuales archivados. No se vuelven a ejecutar integraciones Rust por un cambio documental.

Los métodos de auditoría del catálogo comprueban referencias; no implementan A1–A10. Los 51 oráculos conservan `NOT_RUN` frente al motor. Las guardas del estado no son A1, la serialización operacional no es persistencia analítica completa, y la paridad operacional no prueba racionales de 256 bits en Rust.

### Uso y mantenimiento

1. Consultar el requisito en `development-v1.json`; seguir módulos, métodos, casos y hallazgos.
2. Mantener separados implementación, verificación funcional y validación experimental.
3. Al implementar, añadir pruebas completas y evidencias del commit exacto; conservar las fuentes históricas.
4. Para una ejecución futura, archivar comando, entorno, commit, resultado, alcance y huella del registro. No atribuir una ejecución antigua a código nuevo.
5. Actualizar la matriz y sus índices inversos al cambiar identificadores. Una prueba renombrada debe romper el enlace hasta actualizarlo.
6. Ejecutar `python scripts/verificar_trazabilidad.py` y la suite unitaria. El verificador valida enlaces; no ejecuta herramientas ni certifica conformidad.

Las pruebas TF-01–TF-27 permanecen como planes de aceptación integral. TM-01–TM-17 requieren documentos, revisión humana o registros experimentales; no se simula su cumplimiento mediante pruebas unitarias. Los módulos previstos pueden contener solo un README.

### Criterios y vínculos

| Criterio | Algoritmos y pruebas enlazadas | Pendiente |
|---|---|---|
| AC-01 | A10; 2 vínculos; 0 oráculos | Aislamiento y permisos efectivos de actores pendientes. |
| AC-02 | A1, A2, A7; 15 vínculos; 0 oráculos | Paridad numérica completa y persistencia analítica pendientes. |
| AC-03 | A5; 13 vínculos; 0 oráculos | Permisos y autenticación del extremo real pendientes. |
| AC-04 | A5, A6, A9, A10; 39 vínculos; 0 oráculos | Política temporal y resolución externa pendientes. |
| AC-05 | A5, A9; 5 vínculos; 1 oráculos | Verificar cero ejecuciones físicas extra con ejecutor real. |
| AC-06 | A1; 2 vínculos; 9 oráculos | A1 no implementado. |
| AC-07 | A2; 1 vínculos; 6 oráculos | A2 y congelamiento analítico no implementados. |
| AC-08 | A3; 0 vínculos; 0 oráculos | A3 y controles verificados no implementados. |
| AC-09 | A4; 3 vínculos; 7 oráculos | A4 no implementado; oráculos no son ejecución del motor. |
| AC-10 | A5; 5 vínculos; 4 oráculos | Inicio físico y presupuesto completo por caso no integrados. |
| AC-11 | A5, A10; 6 vínculos; 2 oráculos | Conciliación física y limpieza real no integradas. |
| AC-12 | A3, A5; 0 vínculos; 0 oráculos | Ejecutor real y perfiles autorizados no integrados. |
| AC-13 | A6; 2 vínculos; 2 oráculos | A6 y clasificación efectiva no implementados. |
| AC-14 | A6; 2 vínculos; 5 oráculos | A6 y repositorio analítico de revisiones no implementados. |
| AC-15 | A2, A7; 1 vínculos; 17 oráculos | A7 no implementado; cálculo de referencias no es cálculo de producción. |
| AC-16 | A7; 1 vínculos; 5 oráculos | A7 y validación de derivados no implementados. |
| AC-17 | A7, A8; 0 vínculos; 1 oráculos | A7/A8 y ventana analítica no implementados. |
| AC-18 | A8, A10; 3 vínculos; 2 oráculos | Orden de criterios representado; cálculo y soporte de criterios A8 pendientes. |
| AC-19 | A9; 4 vínculos; 5 oráculos | Transición operacional cubierta; A9 e invariantes analíticos pendientes. |
| AC-20 | A9; 8 vínculos; 3 oráculos | Persistencia operacional cubierta por pruebas; estado analítico integral y garantías del laboratorio pendientes. |
| AC-21 | A5, A9, A10; 9 vínculos; 3 oráculos | Recuperación de componentes cubierta; reejecución física y motor analítico aún no integrados. |
| AC-22 | A10; 3 vínculos; 1 oráculos | Salidas de invocación modeladas; A10 e interfaz operativa pendientes. |
| AC-23 | A1, A2, A3, A4, A5, A6, A7, A8, A9, A10; 0 vínculos; 0 oráculos | A1-A10, terminación integral y medición de costes pendientes. |
| AC-24 | A3, A5, A10; 1 vínculos; 0 oráculos | Laboratorio controlado y verificación física de aislamiento pendientes. |
| AC-25 | A10; 0 vínculos; 0 oráculos | Diseño desglosado en MET; instrumentos, muestra y evaluabilidad sin ejecución. |
| AC-26 | A10; 0 vínculos; 0 oráculos | Contraste, potencia y análisis por ejecutar tras congelamiento. |
| AC-27 | A9, A10; 3 vínculos; 0 oráculos | Reproducción de componentes disponible; reproducción independiente del sistema y experimento pendiente. |

### Obligaciones metodológicas

| Obligación | Qué debe comprobarse | Evidencia requerida |
|---|---|---|
| MET-01 | Comparación emparejada por servicio-escenario bajo condiciones equivalentes. | Protocolo de comparación y registros I1/I8. |
| MET-02 | Congelar el método estático antes de pruebas técnicas y de conocer salidas ARDREC; conservar originales de correcciones justificadas. | I2 con versión, fecha, fuentes, responsable y cierre. |
| MET-03 | Rúbrica independiente y verificación mínima común definidas sin resultados ni reglas internas de los métodos. | I4 validada y paquete uniforme de evidencia. |
| MET-04 | Cegar al evaluador cuando sea viable; documentar información disponible y medidas si no lo es. | Registro de acceso y condiciones de valoración. |
| MET-05 | Demostración mínima suficiente; no aplicable, inconcluso y ausencia de evidencia no se convierten automáticamente en puntuaciones. | Reglas previas y registros de incidencias. |
| MET-06 | Wilcoxon emparejado unilateral, dirección menor error absoluto ARDREC y alfa 0,05. | Plan estadístico previo, software y verificación con datos sintéticos separados. |
| MET-07 | Informar dirección, magnitud, tamaño del efecto, consistencia y relevancia; separar análisis secundarios preespecificados. | Plantilla de análisis; comparador contextual y ablaciones congelados sin ajuste por Rref. |
| MET-08 | Predefinir ceros, empates, ausencias, atípicos, exclusiones y repeticiones; ningún descarte por favorecer la hipótesis. | Reglas de evaluabilidad y registro de decisiones. |
| MET-09 | Planificar 54 unidades: 18 SSH, 18 FTP y 18 SMB; selección intencional sin generalización probabilística automática. | Manifiesto congelado de identidades y diferencias técnicas. |
| MET-10 | Repeticiones técnicas no aumentan n; unidades excluidas conservan identidad y registros; no reemplazar ni ampliar muestra tras congelamiento por resultados. | Censo planificado/analizado y causas de exclusión. |
| MET-11 | Justificar potencia objetivo 0,80 con efecto mínimo, supuestos sobre diferencias/ceros, herramienta y resultado; 54 no garantiza potencia. | Análisis de potencia previo sin datos definitivos. |
| MET-12 | Pilotaje separado de las 54 unidades; corregir antes del congelamiento y no incorporar datos piloto a la muestra principal. | Manifiesto y datos piloto separados. |
| MET-13 | I1-I8 tienen finalidad distinta y el mismo identificador de servicio-escenario; la matriz no reemplaza registros originales. | Instrumentos versionados y procedencia de cada dato. |
| MET-14 | Al menos tres especialistas pertinentes revisan independientemente claridad, coherencia, relevancia y suficiencia. | I5, perfiles, valoraciones individuales, cambios y discrepancias conservados. |
| MET-15 | Pilotar todos los instrumentos; fijar versión, fecha, instrucciones, responsable y reglas de incidencias/correcciones. | Instrumentos estables aprobados antes de recolección. |
| MET-16 | Con varios observadores verificar concordancia según plan; con uno no atribuir confiabilidad interobservador. | Diseño y resultado de evaluación de concordancia cuando corresponda. |
| MET-17 | Conservar originales, transformaciones y huellas; ningún cambio manual silencioso de datos o matriz definitiva. | Cadena de procedencia y reconstrucción independiente. |

### Condiciones pendientes

AL-04: política temporal; AL-05: persistencia analítica; AL-06: estado analítico; AL-07: referencias y autoridad externas; AL-09: alcance de la paridad numérica. Los enlaces a estas brechas no son exhaustivos: otros trabajos pendientes figuran en cada criterio.

La revisión documentada está integrada. La alineación completa, aceptación funcional integral y validación experimental siguen pendientes. Algoritmos y prototipo no iniciados.

## English

This matrix links **27 system criteria and 17 methodological obligations** to responsibilities, modules, test methods, reference cases and evidence. The baseline is `e72830432bc1c26cf5f8679752eddf28077e82a0`; the current source is **TESIS ARDREC**, SHA256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

The historical matrix retains its provenance. Criterion section locators are inherited and supplemented by the current review; this does not claim an exhaustive sentence-by-sentence thesis audit. Six files outside the earlier context remain outside the certified scope.

**A link is not proof of compliance.** The inventory identifies 210 Python methods and four integration scripts. Received output reports workflow-level results, not archived individual test outcomes. Rust integrations are not rerun for this documentation change.

Catalog audits check reference data; they do not implement A1–A10. The 51 oracles remain NOT_RUN against the engine. State guards are not A1, operational serialization is not complete analytical persistence, and operational parity does not demonstrate 256-bit rational interchange with Rust.

### Use and maintenance

1. Locate a requirement in `development-v1.json`; follow modules, methods, cases and findings.
2. Keep implementation, functional verification and experimental validation separate.
3. Add complete tests and evidence for the exact implementation commit; retain historical sources.
4. For future runs archive command, environment, commit, outcome, scope and log digest. Never attribute old runs to new code.
5. Update links and reverse indexes when identifiers change. Renamed tests must fail validation until links are updated.
6. Run `python scripts/verificar_trazabilidad.py` and the unit suite. The checker validates links; it neither launches tools nor certifies conformity.

TF-01–TF-27 remain system acceptance plans. TM-01–TM-17 require documents, human review or experimental records; unit tests cannot substitute for them. Planned modules may contain only a README.

### Criteria and links

| Criterion | Algorithms and linked checks | Remaining work |
|---|---|---|
| AC-01 | A10; 2 links; 0 oracles | Effective actor isolation and permissions pending. |
| AC-02 | A1, A2, A7; 15 links; 0 oracles | Full numerical parity and analytical persistence pending. |
| AC-03 | A5; 13 links; 0 oracles | Real endpoint permissions and authentication pending. |
| AC-04 | A5, A6, A9, A10; 39 links; 0 oracles | Temporal policy and external resolution pending. |
| AC-05 | A5, A9; 5 links; 1 oracles | Verify zero extra physical executions with the real executor. |
| AC-06 | A1; 2 links; 9 oracles | A1 not implemented. |
| AC-07 | A2; 1 links; 6 oracles | A2 and analytical freezing not implemented. |
| AC-08 | A3; 0 links; 0 oracles | A3 and verified controls not implemented. |
| AC-09 | A4; 3 links; 7 oracles | A4 not implemented; oracles are not engine execution. |
| AC-10 | A5; 5 links; 4 oracles | Physical start and complete per-case budget not integrated. |
| AC-11 | A5, A10; 6 links; 2 oracles | Physical reconciliation and actual cleanup not integrated. |
| AC-12 | A3, A5; 0 links; 0 oracles | Real executor and authorized profiles not integrated. |
| AC-13 | A6; 2 links; 2 oracles | A6 and effective classification not implemented. |
| AC-14 | A6; 2 links; 5 oracles | A6 and analytical revision repository not implemented. |
| AC-15 | A2, A7; 1 links; 17 oracles | A7 not implemented; reference calculation is not production calculation. |
| AC-16 | A7; 1 links; 5 oracles | A7 and derived-value validation not implemented. |
| AC-17 | A7, A8; 0 links; 1 oracles | A7/A8 and analytical window not implemented. |
| AC-18 | A8, A10; 3 links; 2 oracles | Criterion ordering represented; A8 criterion calculation and support pending. |
| AC-19 | A9; 4 links; 5 oracles | Operational transition covered; A9 and analytical invariants pending. |
| AC-20 | A9; 8 links; 3 oracles | Operational persistence covered by tests; integrated analytical state and laboratory guarantees pending. |
| AC-21 | A5, A9, A10; 9 links; 3 oracles | Component recovery covered; physical reexecution prevention and analytical engine not yet integrated. |
| AC-22 | A10; 3 links; 1 oracles | Invocation outcomes modeled; A10 and operational interface pending. |
| AC-23 | A1, A2, A3, A4, A5, A6, A7, A8, A9, A10; 0 links; 0 oracles | A1-A10, integrated termination and cost measurement pending. |
| AC-24 | A3, A5, A10; 1 links; 0 oracles | Controlled laboratory and physical isolation verification pending. |
| AC-25 | A10; 0 links; 0 oracles | Design detailed in MET; instruments, sample and evaluability not executed. |
| AC-26 | A10; 0 links; 0 oracles | Test, power analysis and data analysis require execution under the prespecified protocol. |
| AC-27 | A9, A10; 3 links; 0 oracles | Component reproduction available; independent system and experiment reproduction pending. |

### Methodological obligations

| Obligation | Required check | Required evidence |
|---|---|---|
| MET-01 | Paired service-scenario comparison under equivalent conditions. | Comparison protocol and I1/I8 records. |
| MET-02 | Freeze the static method before technical tests and before seeing ARDREC outputs; preserve originals of justified corrections. | I2 with version, date, sources, responsible person and closure. |
| MET-03 | Independent rubric and common minimum verification defined without method outputs or internal rules. | Validated I4 and uniform evidence package. |
| MET-04 | Blind the evaluator where feasible; otherwise document available information and mitigation. | Access and assessment-condition record. |
| MET-05 | Minimum sufficient demonstration; inapplicability, inconclusive outcomes and missing evidence do not automatically become scores. | Predefined rules and incident records. |
| MET-06 | One-sided paired Wilcoxon, direction of lower ARDREC absolute error and alpha 0.05. | Prespecified statistical plan, software and verification using separate synthetic data. |
| MET-07 | Report direction, magnitude, effect size, consistency and relevance; separate prespecified secondary analyses. | Analysis template; contextual comparator and ablations frozen without Rref-driven tuning. |
| MET-08 | Predefine zeros, ties, missing data, outliers, exclusions and repeats; no exclusions to favor the hypothesis. | Evaluability rules and decision record. |
| MET-09 | Plan 54 units: 18 SSH, 18 FTP and 18 SMB; purposive sampling without automatic probabilistic generalization. | Frozen manifest of identities and technical differences. |
| MET-10 | Technical repeats do not increase n; excluded units retain identity and records; do not replace or expand the frozen sample in response to results. | Planned/analyzed census and exclusion reasons. |
| MET-11 | Justify target power 0.80 using minimum effect, assumptions on differences/zeros, tool and result; 54 does not guarantee power. | Prospective power analysis without definitive data. |
| MET-12 | Pilot separately from the 54 units; correct before freezing and exclude pilot data from the main sample. | Separate pilot manifest and data. |
| MET-13 | I1-I8 have distinct purposes and share service-scenario identity; the matrix does not replace originals. | Versioned instruments and per-datum provenance. |
| MET-14 | At least three relevant specialists independently assess clarity, coherence, relevance and sufficiency. | I5, profiles, individual ratings, changes and disagreements preserved. |
| MET-15 | Pilot every instrument; specify version, date, instructions, responsible person and incident/correction rules. | Stable instruments approved before data collection. |
| MET-16 | With multiple observers assess agreement as planned; with one do not claim inter-rater reliability. | Agreement-assessment design and result where applicable. |
| MET-17 | Preserve originals, transformations and hashes; no silent manual changes to data or the final matrix. | Provenance chain and independent reconstruction. |

### Open conditions

AL-04: temporal policy; AL-05: analytical persistence; AL-06: analytical state; AL-07: external references and authority; AL-09: numerical parity scope. Links to these gaps are not exhaustive: individual criteria list further unfinished work.

The documented review is integrated. Full alignment, system functional acceptance and experimental validation remain pending. Algorithms and the prototype have not started.
