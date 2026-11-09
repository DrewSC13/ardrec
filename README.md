# ARDREC

> **P8-R13 — gramática simbólica no ejecutable (propuesta):** [`docs/estado-vigente-p8-r13.md`](docs/estado-vigente-p8-r13.md). Validador puro para 29 contratos tipados y cinco obligaciones de limpieza; sin `argv`, flags CLI, destino, credenciales, caso ni despacho. P8 abierto, P9 y A1–A10 sin iniciar. R12 integrado por PR #45.

> **P8-R12 — semántica acotada de manuales (propuesta):** [`docs/estado-vigente-p8-r12.md`](docs/estado-vigente-p8-r12.md). 91 fragmentos clasificados en 7 manuales y vinculados a 29 perfiles. Ninguna opción CLI aprobada, ningún `argv` ni despacho; P8 continúa abierto, P9 y A1–A10 no iniciados. R11 integrado mediante PR #44.

> **P8-R11 — fuentes documentales del runner (propuesta):** [`docs/estado-vigente-p8-r11.md`](docs/estado-vigente-p8-r11.md). 7 manuales con hashes, 4 declaraciones de dependencias y 29 referencias documentales no autorizadas. Ningun flag/argv validado; P8 abierto, P9 y A1–A10 no iniciados. R10 integrado mediante PR #43.

> **P8-R10 — contratos simbólicos por variante (propuesta):** [`docs/estado-vigente-p8-r10.md`](docs/estado-vigente-p8-r10.md). 29 intenciones tipadas no renderizables: sin `argv`, shell remoto, `smbclient -c`, permisos, presupuesto piloto, casos ni despacho. P8-R9 integrado por PR #42; P8 general permanece abierto.

> **P8-R9 — inventario material del runner (propuesta):** [`docs/estado-vigente-p8-r9.md`](docs/estado-vigente-p8-r9.md). 15 ejecutables y 29 correspondencias candidatas, no autorizadas. La propuesta A1-R9 fue cerrada en PR #41 sin integrarse: los algoritmos se implementarán después del punto 13. R8 está integrado en PR #40.

> **P8-R8 — propuesta source-only no integrada:** [`docs/estado-vigente-p8-r8.md`](docs/estado-vigente-p8-r8.md). Puente sintético de estado y diagnóstico P8, siempre `DENY_ALL`; no hay transiciones ni publicación operacional.

> **Propuesta P8-R7 sin integrar:** [`docs/estado-vigente-p8-r7.md`](docs/estado-vigente-p8-r7.md). Diagnóstico sintético compatible Python/Rust, `DENY_ALL`; ninguna autoridad ni ejecución.

> **Propuesta P8-R6 pendiente de integración:** [`docs/estado-vigente-p8-r6.md`](docs/estado-vigente-p8-r6.md) y [`lab/p8-lifecycle-v1/README.md`](lab/p8-lifecycle-v1/README.md). Contrato sintético de invalidación y caducidad, siempre DENY_ALL, sin reloj ni autoridad confiables.

> **Propuesta P8-R5 pendiente de integración:** [`docs/estado-vigente-p8-r5.md`](docs/estado-vigente-p8-r5.md) y [`lab/p8-material-attestation-v1/README.md`](lab/p8-material-attestation-v1/README.md). Solo observa bytes de fixtures sintéticos; no comprueba binarios reales ni autoriza despacho.

> **Propuesta P8-R4 pendiente de integración:** ver [`docs/estado-vigente-p8-r4.md`](docs/estado-vigente-p8-r4.md) y [`lab/p8-binding-contract-v1/README.md`](lab/p8-binding-contract-v1/README.md). La nueva gramática es deny-only; no vincula herramientas ni autoriza despachos.

> **Estado vigente (8 de noviembre de 2026):** consultar [`docs/estado-vigente-p8-r3.md`](docs/estado-vigente-p8-r3.md). La descripción de arranque que sigue se conserva como histórica. P8 tiene 29 perfiles no vinculados y no autoriza despacho.

## Español

Algoritmo de Recalibración Dinámica del Riesgo de Exposición y Compromiso.

### Estado

Base inicial de desarrollo académico.
Los diez algoritmos, el ejecutor y el experimento todavía no están implementados.

### Arquitectura

- Python: reglas, selección, evidencia, riesgo, estados y coordinación.
- Rust: ejecución técnica controlada, resultados, soportes y limpieza.
- Intercambio: contratos JSON y transporte mediante socket Unix local.
- Persistencia: diarios, objetos inmutables y generaciones confirmadas.

### Método de desarrollo

Desarrollo incremental y prototipado evolutivo en el marco de Design Science
Research. PTES orienta las operaciones técnicas. La selección adaptativa
emplea la técnica voraz descrita en la tesis.

Cada incremento debe vincular requisito, implementación, prueba y evidencia.
La existencia de una firma no acredita corrección funcional o científica.

## English

### ARDREC

Algorithm for Dynamic Recalibration of Exposure and Compromise Risk.

#### Status

Initial academic development baseline.
The ten algorithms, executor and experiment have not yet been implemented.

#### Architecture

- Python: rules, selection, evidence, risk, states and coordination.
- Rust: controlled technical execution, results, supporting artifacts and cleanup.
- Exchange: JSON contracts and transport through a local Unix domain socket.
- Persistence: journals, immutable objects and confirmed generations.

#### Development method

Incremental development and evolutionary prototyping within Design Science
Research. PTES guides technical operations. Adaptive selection uses the
greedy technique described in the thesis.

Each increment must link requirements, implementation, tests and evidence.
A signature does not establish functional or scientific correctness.
