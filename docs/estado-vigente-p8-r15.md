# ARDREC — P8-R15: matriz de obligaciones de liberación y decisiones denegadas

**Base protegida:** `62812d92dd89ccf4559d9d2e7219fd96b197d5c6` (P8-R14 integrado por PR #47, CI pre y posmerge confirmadas).

El incremento R15 convierte los 25 límites de riesgo de R14 en un **oráculo estático de bloqueo** que abarca 29 perfiles simbólicos procedentes de R13. La proyección conservadora por familia produce **238 enlaces riesgo-perfil** y distingue explícitamente cinco perfiles con efectos de escritura, que requieren recibo independiente de limpieza y prueba de restauración. Nueve obligaciones comunes de evidencia se mantienen pendientes para cada perfil.

El componente `lab/verify_p8_cli_review_gates.py` valida hashes, identidad, orden, categorías, control de efectos, fuentes, congruencia con R13/R14 y campos autorizables; `assess_request` responde siempre `BLOCKED_REVIEW_GATES_NOT_CLEARED` a entradas sintéticas válidas. Ninguna clasificación constituye una revisión semántica completa ni demuestra relevancia causal de un riesgo en una invocación específica. La cobertura por familia se elige conscientemente conservadora hasta que se validen las opciones reales y su configuración efectiva.

La aprobación de opciones y gramáticas CLI, el renderizador `argv`, la autorización de caso, la identidad del objetivo, el cierre de dependencias, los límites del piloto, los recibos de limpieza y el ejecutor real **continúan fuera del incremento**. Los siete manuales privados no se incorporan a Git; la instalación verifica el informe R14 existente por SHA.

**Gates:** 29 perfiles bloqueados, 25 riesgos no aprobados, 238 referencias conservadoras, 5 escrituras sin ejecutar, 0 opciones/gramáticas CLI/argv aprobados, 0 revisiones semánticas completas, 0 casos y perfiles autorizados, 0 despachos, sin contacto físico o ejecución de guest. P8, AL-06/AL-07 y siete obligaciones abiertas. P9 y A1–A10 no iniciados.

**EN:** P8-R15 provides a deterministic, denial-only CLI review-obligation matrix. It is a static conservative mapping, not executable CLI semantics, proved configuration, a green operational readiness gate, nor permission to dispatch.
