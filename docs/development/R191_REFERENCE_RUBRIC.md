# R191 - Rubrica I4 determinista candidata

## Alcance

Motor puro de valoracion de hechos declarados.
No consulta R0, Rf, PA, Rref previo ni motores de ARDREC.
No acredita la autenticidad de los soportes declarados.

## Criterios

- Exposicion: inexistente, limitada o presente.
- Controles de acceso: efectivos, debiles o fallidos.
- Capacidades: ninguna, debilidad verificable o capacidad
  no autorizada verificable.
- Consecuencias: confidencialidad, integridad,
  disponibilidad y alcance contextual.

Cada hecho requiere justificacion e identificadores
de soportes cuando esta determinado.

Los impactos se clasifican como inexistentes, acotados,
relevantes o graves. NA exige justificacion y soporte.
ND indica una condicion sin determinacion suficiente.

Las categorias deben aplicarse respecto de los recursos,
activos y limites definidos antes de la experimentacion.

## Niveles candidatos

| Nivel | Valor | Condicion |
|---|---:|---|
| 0 | 0.00 | Sin exposicion ni capacidad indebida; controles efectivos; consecuencias inexistentes |
| 1 | 0.25 | Exposicion presente o limitada; controles efectivos; sin capacidad indebida ni consecuencia adversa |
| 2 | 0.50 | Debilidad o capacidad indebida; consecuencias inexistentes o acotadas |
| 3 | 0.75 | Capacidad indebida verificable; consecuencia relevante |
| 4 | 1.00 | Debilidad o capacidad indebida; consecuencia grave sustentada |

Se considera la consecuencia mas grave sustentada
entre las dimensiones aplicables.

Las contradicciones, insuficiencias y combinaciones
ambiguas se mantienen como ND, sin puntuacion.

No es necesario provocar consecuencias destructivas.
La calificacion requiere soporte tecnico suficiente.

La asignacion de gravedad sigue siendo una valoracion
del investigador basada en criterios predefinidos.
El motor no autentica automaticamente esa valoracion.

## Evidencia comun

CE01 Identidad y version del servicio.
CE02 Configuracion inicial.
CE03 Exposicion dentro del alcance.
CE04 Autenticacion y controles de acceso.
CE05 Capacidades y permisos.
CE06 Efectividad observable de controles.
CE07 Consecuencias tecnicas justificadas.
CE08 Estado final y restauracion.
CE09 Procedencia e integridad de los soportes.

Los nueve grupos deben estar completos.
NA puede aplicarse justificadamente a subcondiciones,
pero no permite omitir un grupo de evidencia.

## Evidencia adicional

Solo para soporte requerido faltante, contradicciones,
aplicabilidad ambigua o condiciones tecnicas no resueltas.

Debe justificarse antes de solicitarla, permanecer
dentro del alcance autorizado y respetar limites y
criterios de finalizacion establecidos antes del piloto.

No se permiten verificaciones adicionales seleccionadas
a partir de diferencias entre los resultados comparados.

## Escala

Los valores 0, 0.25, 0.50, 0.75 y 1 representan una
codificacion ordinal equidistante propuesta.
No representan probabilidades empiricas de compromiso
ni demuestran distancias iguales entre categorias.

La sensibilidad de esta codificacion se evaluara
mediante alternativas preespecificadas, sin ajustar
el resultado para favorecer un metodo.

## Estado

Candidato no congelado. Requiere revision interna,
operacionalizacion de los indicadores de gravedad y piloto.

Los hechos sinteticos de prueba no son observaciones.
No se acredita validacion externa ni independencia humana.

P7=DRAFT_NOT_FROZEN. P8=NO-GO.
