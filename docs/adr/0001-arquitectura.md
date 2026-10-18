# ADR-0001. Organización inicial de ARDREC

## Español

Estado: decisión inicial de implementación.

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

Status: initial implementation decision.

A monorepository is established with separation between the Python analytical
component, the Rust technical component, contracts and persistence.

The technical component does not calculate risk or admit evidence.
The analytical component does not invoke technical tools.
Transport does not interpret evidence.
Persistence does not reclassify results.

Effective separation through operating-system permissions will be implemented
and verified during laboratory preparation.

This decision does not modify the equations or rules of the academic model.
