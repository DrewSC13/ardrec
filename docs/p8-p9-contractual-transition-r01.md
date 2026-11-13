# ARDREC — Frontera contractual P8 y desarrollo independiente P9

## Base verificada

P8/R78-R2: `PASS_FINAL_CONTRACTUAL_VERDICT`.

Commit base:
`6e5e8c0904d91d092f538900a63dedaecb2d1edf`.

La implementación contractual P8 tiene 29 perfiles,
25 familias y 215 pruebas Rust aprobadas en el corte R78-R2.

## Condiciones expresamente pendientes de P8

- 348 vinculaciones materiales pendientes.
- 261 comprobaciones operacionales sin acreditar.
- Cinco obligaciones independientes de limpieza.
- Cero revisiones semánticas completas certificadas.
- Cero casos operacionales autorizados.
- AL-06 y AL-07 abiertos.
- P8 operacional: NO-GO.

No se cambia el significado de aceptación operacional
ni se declara P8 completamente cerrado.

## Límite de desarrollo P9-R01

Se admite exclusivamente desarrollo independiente de
supervisión local con procesos benignos de prueba.

El módulo recibe procesos hijos ya creados.
No crea clientes, conexiones o sesiones del laboratorio.
No se conecta con las solicitudes operacionales de P8.

R01 acredita solo terminación, plazo monotónico,
terminación del líder y recolección del líder.

No acredita descendientes, árbol de procesos,
cgroups, namespaces, identidad, capacidades de
seguridad, cancelación remota, pérdida de energía,
ni limpieza de artefactos y recursos externos.

## Puerta operacional

El despacho sigue prohibido hasta verificar
independientemente las condiciones materiales,
la autoridad del caso, el aislamiento, los límites,
el ciclo de vida completo y la recuperación.

El trabajo P9 no convierte automáticamente
ningún perfil P8 en autorizado.
