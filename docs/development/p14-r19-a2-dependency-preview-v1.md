# P14-R19 — Validación acotada de referencias y dependencias en A2

**Base exacta:** `d2a8d46ba18c124e0d07201d79d728ed2911f3c1` (PR #84).
**Estado:** incremento propuesto, sujeto a pruebas Prometheus, PR y CI posmerge.
**No constituye:** implementación completa de A1/A2, autorización de P8, evaluación
experimental, ni publicación de una generación confirmada.

## Contrato implementado

La prevalidación A1/R17 admite **hasta 64 servicios** (antes 32). La prueba heredada R17 que
rechazaba 33 servicios se actualiza a rechazar 65 (misma intención de límite). La cota es técnica,
no el tamaño obligatorio del experimento. R18 valida, sin modificación de comportamiento,
los riesgos racionales exactos, la criticidad, los estados `PREPARADO`, los contadores
cero y el conjunto de casos declarados. R19 valida exclusivamente una relación de
**prerrequisitos locales entre casos de un mismo servicio**, anclada a los hashes
inalterados de R17 y R18. Deniega identidades no declaradas, duplicados,
autodependencias, ciclos, tipos falsos, referencias externas y payloads no admitidos.
Un algoritmo de Kahn con desempate lexicográfico calcula un orden topológico
reproducible para cada servicio. El resultado guarda fuente canónica y SHA-256;
no confiere por sí mismo autenticidad externa, custodia de frescura ni autoridad.

Se demuestra un conjunto **sintético** de 54 servicios con etiquetas distribuidas
18/18/18 entre SSH/FTP/SMB. Esa distribución no verifica los 54 escenarios físicos,
las 25 familias de pruebas ni el cierre de las referencias completas del catálogo.
Los nombres de protocolo son etiquetas de ensayo, no certificación de capacidades.

## Limitaciones explícitas

- A1 conserva pendientes el contraste final de `EVALUAR`/`DECIDIR` y la aceptación
  funcional de AC-06.
- A2 conserva pendientes validación de pesos, condiciones específicas, escenarios,
  controles habilitables, parámetros de autorización y publicación durable de estado.
- Este contrato no modela dependencias entre servicios ni condiciones de ejecución
  de un intento; requerirán su propia especificación y oráculos.
- No cambia P8: 29 perfiles sin habilitar, 348 campos sin vincular, 261 pruebas
  runtime pendientes y cero casos con autorización operacional.
- No modifica cliente, socket, cgroup, PID, herramienta, laboratorio ni procesos.
- La CI ejecuta solo pruebas sintéticas y el demo. Los casos físicos se separan.

## Reproducción

```bash
python3 -B -m unittest discover -s lab/tests -p test_p14_r19_a2_dependency_preview.py -v
python3 -B scripts/demo_p14_r19_a2_dependency_preview.py
```

Los hashes de fuentes, el ZIP, los logs de Prometheus, el commit firmado,
los checks Python/Rust del PR y la CI posmerge se vinculan por SHA-256.
La firma de GitHub del commit de merge se verifica mediante API, no se exige
una clave GPG de GitHub importada localmente.

## English summary

R19 adds a bounded **synthetic per-service local case-dependency graph** to
R17/R18 snapshots and expands the R17 maximum from 32 to 64 services so
54 synthetic units can be demonstrated (18 SSH, 18 FTP, 18 SMB). It validates
references, rejects cycles, and gives deterministic topological order. It is not
operational authorization, the complete A2 configuration, a laboratory run,
or durable generation publication. P8 remains NO-GO; A1/A2 remain incomplete.
