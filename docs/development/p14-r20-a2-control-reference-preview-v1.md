# P14-R20 — Referencias simbólicas de controles para A2

**Base inmutable:** `0f38df2341278e81b65840f9f75a00a8b0a7b147` (PR #85).
**Alcance:** prevalidación estructural de A2; no se implementa la evaluación
operacional de controles de A3, ni se ejecutan acciones de P8–P12.

## Objetivo acotado

La tesis ARDREC especifica que A2 verifica controles, referencias, dependencias,
precedencia y tablas de decisión antes de inicializar las observaciones. R16–R19
aportan tablas A1, instantánea de reglas, estado inicial sintético y grafo de
casos por servicio. R20 añade un cuarto documento inmutable de **referencias de
controles**, ligado a las huellas de los tres documentos anteriores.

Una entrada por servicio declara únicamente controles simbólicos:
`id`, `guard_rule_id`, `target_case_id`, `precedence` y `requires`. Cada
identificador de regla y caso debe existir en el **mismo servicio**. Las
referencias entre controles son locales; las duplicaciones, ciclos, referencias
externas y autodependencias se rechazan. El orden topológico es estable y la
precedencia desempata solo entre controles elegibles por el grafo. **El orden
calculado no significa permiso ni programación de acciones.**

## Contrato de límites

- Hasta **64 servicios** ya autorizados estructuralmente por R17–R19.
- Hasta **32 controles declarativos por servicio** y 262.144 bytes del documento
  canónico. Precedencia entera exacta entre 0 y 1023 (se rechazan booleanos).
- JSON de claves exactas y sin duplicados; campos `argv`, comandos, permisos,
  destino o ejecución real son rechazados por esquema.
- SHA-256 del documento R20 y referencias exactas a R17, R18 y R19. Una huella
  es integridad de origen local, no firma externa ni publicación durable A9.
- Ninguna fuente mutable del usuario queda vinculada a la vista congelada.

## Verificación

- Pruebas negativas: `lab/tests/test_p14_r20_a2_control_preview.py`.
- Demostración sintética: `scripts/demo_p14_r20_a2_control_preview.py`.
- CI: agrega únicamente las dos comprobaciones Python anteriores; no ejecuta
  clientes externos, systemd, comandos SSH/FTP/SMB ni escenarios físicos.
- Demostración: 54 servicios (18 SSH, 18 FTP, 18 SMB) y 108 controles
  sintéticos, sin autoridad ni despachos. La cobertura de la prueba no cubre la
  totalidad de configuraciones experimentales.

## Límites pendientes

**A1_FULL=NOT_CLOSED, A2_FULL=NOT_CLOSED, A3_FULL=NOT_CLOSED.**
P8 operacional sigue **NO-GO**; casos autorizados=0. Quedan por desarrollar
validación integral de tablas y configuraciones, semántica exacta de controles
(incluido consumo y autoridad), dependencias interservicio, persistencia
transaccional de la generación inicial, separación efectiva de permisos, y
reproducción con el catálogo y las 54 unidades físicas. La aceptación funcional
integral y validación experimental permanecen pendientes.
