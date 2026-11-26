# ADR-0001. Organización inicial de ARDREC

## Español

Estado: decisión vigente, precisada en R314.

### Custodia y directorios (R314)

Un único operador humano desarrolla, administra y custodia ARDREC.
No se presupone personal operacional externo ni se añade gestión
multiusuario. La separación lógica de componentes, identidades de
procesos, privilegios, evidencias y funciones criptográficas se conserva.
Una firma o una clave distinta no acredita otra persona.

El directorio de trabajo es la raíz de ARDREC. Los datos activos privados
se mantienen en `experiments/raw/`, `lab/private/`, `runtime/` y
`local-reports/`, excluidos de Git. `ardrec-patches/` es un archivo hermano
de parches, scripts y evidencias; no es el espacio de trabajo activo.

`python -m ardrec arquitectura --json` declara el modelo, no autentica
al operador ni concede autoridad. R146/R163, las guardas de seguridad,
la admisión A6 y los criterios de aceptación no se modifican. La
validación académica independiente es un requisito metodológico separado
y no se declara satisfecha por autoevaluación. Véase R179.

Se establece un monorepositorio con separación entre el componente analítico
Python, el componente técnico Rust, los contratos y la persistencia.

El componente técnico no calcula riesgo ni admite evidencia.
El componente analítico no invoca herramientas técnicas.
El transporte no interpreta evidencia.
La persistencia no reclasifica resultados.

La separación efectiva de permisos del sistema operativo se implementará
y verificará durante la preparación del laboratorio.

Esta decisión no modifica las ecuaciones ni las reglas del modelo académico.

## English

### ADR-0001. Initial ARDREC organization

Status: current decision, clarified in R314.

### Custody and directories (R314)

A single human operator develops, administers and maintains custody of
ARDREC. No external operational personnel or multi-user management are
assumed. Logical component, process identity, privilege, evidence and
cryptographic-role separation is preserved. Distinct keys do not attest
distinct people.

Work takes place at the ARDREC repository root. Active private data uses
Git-ignored `experiments/raw/`, `lab/private/`, `runtime/` and
`local-reports/`. The sibling `ardrec-patches/` is an archive for patches,
scripts and evidence, not an active workspace.

`python -m ardrec arquitectura --json` declares the model; it neither
authenticates the operator nor grants authority. R146/R163, security
guards, A6 admission and acceptance criteria are unchanged. Independent
academic validation is a separate methodological requirement and is not
satisfied by self-assessment. See R179.

A monorepository is established with separation between the Python analytical
component, the Rust technical component, contracts and persistence.

The technical component does not calculate risk or admit evidence.
The analytical component does not invoke technical tools.
Transport does not interpret evidence.
Persistence does not reclassify results.

Effective separation through operating-system permissions will be implemented
and verified during laboratory preparation.

This decision does not modify the equations or rules of the academic model.
