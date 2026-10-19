# Casos de referencia del modelo

## Español

Fuente: TESIS ARDREC, identificada por la huella conservada en el catálogo.
Esta entrega contiene 51 casos sintéticos: 16 numéricos, 9 de reglas, 7 de selección,
9 de evidencia y 10 de transiciones. No representan observaciones experimentales.

Las entradas y salidas completas se conservan en
[model-reference-v1.json](../../tests/fixtures/model-reference-v1.json).
Cada resultado esperado es literal, derivado de la especificación; no lo genera
una implementación de ARDREC ni se actualiza automáticamente al fallar una prueba.
La auditoría numérica usa aritmética racional y, para recalibración, una escala
entera común. Verifica los valores de referencia, no una implementación de A7.

### Convenciones y precondiciones

- El perfil numérico principal fija beta a 1/2 y las ternas lambda y w a 1/3.
  Rminus identifica la línea de base sustituida. Las fracciones JSON son canónicas.
- Los casos de reglas prueban DECIDIR con condiciones ya evaluadas. El marcador
  lógico ND del catálogo no sustituye el contrato ND del protocolo. No se define
  aquí un AST ni se implementan los operadores de EVALUAR.
- Las filas de selección siguen candidate_columns. guard representa la evaluación
  conjunta de las restricciones; únicamente true habilita. Los casos se filtran
  antes de aplicar (-PA, precedencia, id_servicio, id_caso). NO_SELECTION no autoriza
  cerrar automáticamente: el coordinador todavía debe evaluar controles y parada.
- Las unidades de proyección de evidencia ya han sido admitidas y clasificadas
  conforme a los hechos del caso; las contribuciones están determinadas. Los demás
  casos comprueban condiciones particulares de admisión, soportes o revisiones.
- Los indicadores de autorización, integridad y publicación son precondiciones
  sintéticas. En producción deben demostrarse mediante registros, soportes y permisos;
  recibir un booleano no demuestra que esas verificaciones hayan ocurrido.
- expected es la proyección observable exigida en cada caso, no el objeto completo
  del futuro motor. Los adaptadores deberán comprobar todos sus campos y las
  invariantes aplicables. Los nombres de este catálogo no congelan la API pública.
- La repetición de un evento se prueba en la capa de recuperación idempotente;
  no se exige volver a invocar TRANSICION con un evento ya incorporado.

### Uso y evidencia

1. Ejecutar la auditoría del catálogo y los enlaces con los criterios de aceptación.
2. Al implementar cada módulo, conectar estos casos con su interfaz real y comparar
   resultados, rechazos y efectos persistidos sin recalcular el esperado desde el motor.
3. Añadir contraejemplos, límites y fallos específicos del módulo. Este corpus inicial
   no cubre todavía todos los operadores, pesos alternativos, estados o puntos de fallo.
4. Comprobar que las pruebas del motor detecten errores deliberados: sumar evidencia,
   ignorar ND, elegir la primera fila, ordenar prioridades al revés, contar aceptación
   como inicio o publicar una generación sin confirmar el puntero.
5. Registrar commit, entorno, comando, resultados y cobertura real. Solo entonces
   actualizar la verificación funcional del criterio correspondiente.

Las comprobaciones de test_model_references.py validan estructura, trazabilidad y
aritmética de referencia. No ejecutan A1-A10 y no certifican corrección funcional
del modelo, recuperación durable ni la hipótesis experimental. Los estados existentes
de aceptación permanecen intactos. No se incorporan datos de laboratorio ni Rref.

### Casos y propósito

| Caso | Criterios | Resultado que protege |
| --- | --- | --- |
| REF-N01 | AC-07, AC-15 | Los mínimos ordinales producen cero. |
| REF-N02 | AC-07, AC-15 | Los máximos ordinales producen uno. |
| REF-N03 | AC-07, AC-15 | (5+1+3-3)/12 = 1/2. |
| REF-N04 | AC-07, AC-15 | max(1,5-1)=4; un extremo contextual no se promedia. |
| REF-N05 | AC-07, AC-15 | Permutar los componentes conserva el resultado. |
| REF-N06 | AC-07, AC-15 | max(3,4-1)=3; normalización (3-1)/4. |
| REF-N07 | AC-15 | T=6/8, S=8/8; e=48/64. |
| REF-N08 | AC-15 | Alcance máximo con respaldo bajo no produce contribución máxima. |
| REF-N09 | AC-15 | Un negativo válido conserva contribución cero con respaldo suficiente. |
| REF-N10 | AC-16 | Et=0 obliga U=R0 aunque Kplus sea mayor; criticidad no es evidencia. |
| REF-N11 | AC-16 | Rf=7/12+4/9-1/2=19/36; prioridad y riesgo son distintos. |
| REF-N12 | AC-16 | Sin evidencia positiva, el ajuste autorizado descendente deja Rf=D. |
| REF-N13 | AC-16 | Sin sustitución negativa D=R0 y Rf=U. |
| REF-N14 | AC-16 | Evidencia positiva pequeña no obliga a aumentar R0. |
| REF-N15 | AC-17 | 1/576 supera 1/1000; redondear antes puede ocultar la diferencia. |
| REF-N16 | AC-15 | La sustitución recalcula componentes y conserva la exposición original. |
| REF-R01 | AC-06 | Existe exactamente una coincidencia y ninguna condición ND. |
| REF-R02 | AC-06 | Ninguna coincidencia devuelve ND, no FALSO. |
| REF-R03 | AC-06 | Una fila indeterminada impide seleccionar incluso con una coincidencia verdadera. |
| REF-R04 | AC-06 | La indeterminación no se convierte en una negación. |
| REF-R05 | AC-06 | Dos coincidencias son ambiguas; no se aplica primera coincidencia. |
| REF-R06 | AC-06 | Salidas iguales no eliminan la ambigüedad de dos filas verdaderas. |
| REF-R07 | AC-06 | La tabla vacía no aporta una determinación. |
| REF-R08 | AC-06 | El entero 1 no sustituye al booleano VERDADERO. |
| REF-R09 | AC-06 | El diagrama comprueba ambigüedad antes del retorno por indeterminación. |
| REF-S01 | AC-09 | La prioridad se compara antes de la precedencia. |
| REF-S02 | AC-09 | En empate de prioridad vence la menor precedencia. |
| REF-S03 | AC-09 | El identificador del servicio precede al del caso. |
| REF-S04 | AC-09 | El identificador del caso resuelve el último empate. |
| REF-S05 | AC-09 | Ni una prioridad máxima compensa guarda falsa/ND, presupuesto agotado o pausa. |
| REF-S06 | AC-09 | El conjunto vacío no permite argmax ni inventar un candidato. |
| REF-S07 | AC-09 | Tener registros no implica disponer de candidatos elegibles. |
| REF-E01 | AC-14, AC-15 | El máximo es 3/4, no la suma 5/4 ni el número de soportes. |
| REF-E02 | AC-15 | El máximo incluye cero cuando no hay unidades vigentes. |
| REF-E03 | AC-15 | Evidencia negativa válida es distinta de ausencia de evidencia aunque Et sea cero. |
| REF-E04 | AC-14, AC-15 | Un negativo no cancela un positivo vigente. |
| REF-E05 | AC-14, AC-15 | Retirar válidamente el máximo permite disminuir Et sin borrar historia. |
| REF-E06 | AC-13 | Un código cero no corrige soportes de integridad inválida. |
| REF-E07 | AC-14 | La revisión mayor no gana automáticamente ni elimina la controversia. |
| REF-E08 | AC-13, AC-15 | q debe ser al menos uno; no basta con calcular un producto numérico. |
| REF-E09 | AC-14, AC-15 | Retransmitir un soporte idéntico no crea otra condición ni otra observación de convergencia. |
| REF-T01 | AC-10, AC-11 | Aceptar no acredita inicio ni publica una generación. |
| REF-T02 | AC-10, AC-19 | La fase local cambia; el contador confirmado espera incorporación durable del evento. |
| REF-T03 | AC-10, AC-19, AC-20 | Una incorporación válida publica k+1 y contabiliza un único inicio. |
| REF-T04 | AC-05, AC-10, AC-21 | La recuperación idempotente no vuelve a ejecutar ni a incorporar el evento. |
| REF-T05 | AC-19 | Un evento de otra generación no autoriza una transición nueva. |
| REF-T06 | AC-19 | La configuración congelada no se reemplaza silenciosamente. |
| REF-T07 | AC-18, AC-19 | Restaurar el laboratorio no reabre la misma observación terminal. |
| REF-T08 | AC-20, AC-21 | Escribir el candidato no publica autoridad; recuperar no autoriza repetir una herramienta. |
| REF-T09 | AC-20, AC-21 | La marca ausente no invalida un puntero nuevo verificado y durable. |
| REF-T10 | AC-11, AC-18, AC-22 | La invocación informa incertidumbre y no fabrica un estado confirmado ni una pausa. |

---

## English

Source: TESIS ARDREC, identified by the hash stored in the catalog. This increment
contains 51 synthetic cases: 16 numeric, 9 rule, 7 selection, 9 evidence and
10 transition cases. They are not experimental observations.

Complete inputs and outputs are stored in
[model-reference-v1.json](../../tests/fixtures/model-reference-v1.json).
Expected results are literals derived from the specification, not generated by an
ARDREC implementation or automatically updated after failures. The numerical audit
uses exact rational arithmetic and a common integer scale for recalibration. It
checks reference values, not an A7 implementation.

### Conventions and preconditions

- The main numeric profile fixes beta at 1/2 and the lambda and w triples at 1/3.
  Rminus denotes the substituted baseline. JSON fractions are canonical.
- Rule cases test DECIDIR with already evaluated conditions. The catalog's logical
  ND marker does not replace the protocol ND contract. No AST or EVALUAR operators
  are defined or implemented here.
- Selection rows follow candidate_columns. guard represents the combined constraint
  evaluation; only true enables a case. Filtering precedes ordering by
  (-PA, precedence, service_id, case_id). NO_SELECTION does not automatically
  authorize closure: the coordinator must still evaluate controls and stopping.
- Evidence projection units have already been admitted and classified according
  to case facts, with determined contributions. Other cases check particular
  admission, supporting-artifact or revision conditions.
- Authorization, integrity and publication flags are synthetic preconditions.
  Production must establish them through records, artifacts and permissions;
  receiving a boolean does not prove that the checks occurred.
- expected is the required observable projection, not the future engine's complete
  object. Adapters must check all expected fields and applicable invariants.
  Catalog names do not freeze the public API.
- Event replay is tested at the idempotent recovery layer; it does not require
  invoking TRANSICION again with an already incorporated event.

### Use and evidence

1. Run the catalog audit and acceptance-link checks.
2. When implementing each module, connect cases to its real interface and compare
   values, rejections and persisted effects without deriving expectations from the engine.
3. Add module-specific counterexamples, boundaries and faults. This initial corpus
   does not yet cover every operator, alternative weight, state or fault boundary.
4. Check that engine tests catch deliberate mistakes: summing evidence, ignoring ND,
   picking the first row, reversing priority order, treating acceptance as start,
   or publishing a generation without confirming the pointer.
5. Record commit, environment, command, results and actual coverage. Only then
   update the corresponding criterion's functional verification.

test_model_references.py checks structure, traceability and reference arithmetic.
It does not execute A1-A10 or certify model correctness, durable recovery or the
experimental hypothesis. Existing acceptance statuses remain unchanged. No laboratory
data or Rref values are introduced.

### Cases and purpose

| Case | Criteria | Protected result |
| --- | --- | --- |
| REF-N01 | AC-07, AC-15 | Ordinal minima produce zero. |
| REF-N02 | AC-07, AC-15 | Ordinal maxima produce one. |
| REF-N03 | AC-07, AC-15 | (5+1+3-3)/12 = 1/2. |
| REF-N04 | AC-07, AC-15 | max(1,5-1)=4; a contextual extreme is not averaged. |
| REF-N05 | AC-07, AC-15 | Permuting components preserves the result. |
| REF-N06 | AC-07, AC-15 | max(3,4-1)=3; normalization (3-1)/4. |
| REF-N07 | AC-15 | T=6/8, S=8/8; e=48/64. |
| REF-N08 | AC-15 | Maximum reach with low support does not produce maximum contribution. |
| REF-N09 | AC-15 | A valid negative retains zero contribution with sufficient support. |
| REF-N10 | AC-16 | Et=0 forces U=R0 even when Kplus is larger; criticality is not evidence. |
| REF-N11 | AC-16 | Rf=7/12+4/9-1/2=19/36; priority and risk differ. |
| REF-N12 | AC-16 | Without positive evidence, the authorized downward adjustment leaves Rf=D. |
| REF-N13 | AC-16 | Without a negative substitution D=R0 and Rf=U. |
| REF-N14 | AC-16 | Small positive evidence does not necessarily increase R0. |
| REF-N15 | AC-17 | 1/576 exceeds 1/1000; early rounding may conceal the difference. |
| REF-N16 | AC-15 | Substitution recomputes components and preserves original exposure. |
| REF-R01 | AC-06 | There is exactly one match and no ND condition. |
| REF-R02 | AC-06 | No match returns ND, not FALSE. |
| REF-R03 | AC-06 | An indeterminate row prevents selection even with one true match. |
| REF-R04 | AC-06 | Indeterminacy is not converted into negation. |
| REF-R05 | AC-06 | Two matches are ambiguous; first-match selection is not applied. |
| REF-R06 | AC-06 | Equal outputs do not remove ambiguity from two true rows. |
| REF-R07 | AC-06 | An empty table provides no determination. |
| REF-R08 | AC-06 | Integer 1 does not replace boolean TRUE. |
| REF-R09 | AC-06 | The diagram checks ambiguity before returning indeterminacy. |
| REF-S01 | AC-09 | Priority is compared before precedence. |
| REF-S02 | AC-09 | With equal priority, lower precedence wins. |
| REF-S03 | AC-09 | Service identifier precedes case identifier. |
| REF-S04 | AC-09 | Case identifier resolves the final tie. |
| REF-S05 | AC-09 | Maximum priority cannot override false/ND guards, exhausted budget or pause. |
| REF-S06 | AC-09 | An empty set permits neither argmax nor an invented candidate. |
| REF-S07 | AC-09 | Having records does not imply having eligible candidates. |
| REF-E01 | AC-14, AC-15 | The maximum is 3/4, not the sum 5/4 or the number of artifacts. |
| REF-E02 | AC-15 | The maximum includes zero when no current units exist. |
| REF-E03 | AC-15 | Valid negative evidence differs from absent evidence even when Et is zero. |
| REF-E04 | AC-14, AC-15 | A negative does not cancel a current positive. |
| REF-E05 | AC-14, AC-15 | Valid withdrawal of the maximum may decrease Et without deleting history. |
| REF-E06 | AC-13 | A zero exit code does not repair invalid artifact integrity. |
| REF-E07 | AC-14 | A higher revision does not automatically win or remove controversy. |
| REF-E08 | AC-13, AC-15 | q must be at least one; calculating a numeric product is insufficient. |
| REF-E09 | AC-14, AC-15 | Retransmitting an identical artifact creates neither another condition nor another convergence observation. |
| REF-T01 | AC-10, AC-11 | Acceptance neither proves start nor publishes a generation. |
| REF-T02 | AC-10, AC-19 | The local phase changes; the confirmed counter awaits durable event incorporation. |
| REF-T03 | AC-10, AC-19, AC-20 | One valid incorporation publishes k+1 and counts one start. |
| REF-T04 | AC-05, AC-10, AC-21 | Idempotent recovery neither re-executes nor reincorporates the event. |
| REF-T05 | AC-19 | An event from another generation does not authorize a new transition. |
| REF-T06 | AC-19 | Frozen configuration is not silently replaced. |
| REF-T07 | AC-18, AC-19 | Restoring the laboratory does not reopen the same terminal observation. |
| REF-T08 | AC-20, AC-21 | Writing the candidate does not publish authority; recovery does not authorize rerunning a tool. |
| REF-T09 | AC-20, AC-21 | A missing marker does not invalidate a verified durable new pointer. |
| REF-T10 | AC-11, AC-18, AC-22 | The invocation reports uncertainty and fabricates neither confirmed state nor pause. |
