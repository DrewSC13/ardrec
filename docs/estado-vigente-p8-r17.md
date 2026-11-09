# ARDREC — P8-R17: puerta de vinculación material, lectura estática

**Base confirmada:** `b0e805006d6e128f8ebbe3781596a80604e31138`, merge del PR #49 con CI Python/Rust previa y posterior aprobada.

El código `lab/p8_r17_material_closure.py` y la puerta `lab/verify_p8_r17_material_closure.py` inspeccionan en conjunto el catálogo original de P8-R1, los 29 contratos P8-R10, la semántica simbólica P8-R13 y los gates P8-R15, bajo hashes de fuente fijos. No extraen materiales privados. Validan que la identidad, orden, operación, protocolo y limpieza de los perfiles coincidan; que los `argv`, AST remotos y SMB, autorizaciones y presupuestos **no se hayan promocionado** sin contrato; y que las cinco escrituras exijan limpieza independiente y prueba de restauración.

La línea base tiene **29 perfiles bloqueados**, **348 campos de vinculación material sin resolver** (29 × 12), **271 enlaces de obligación documental sin verificar** (29 × 9 + 5 × 2) y 238 enlaces conservadores riesgo-perfil. La observación anterior de hashes binarios R9 constituye sólo material candidato. El modelo de precedencia SSH R16 sigue siendo sintético: no prueba configuración efectiva de OpenSSH.

R17 es un instrumento para controlar un cierre material posterior, **no ese cierre**. Las etapas subsiguientes requieren obtener datos operacionales con autoridad y aislamiento independientes; cuando tales entradas estén disponibles, se creará un contrato de vinculación real nuevo en vez de editar silenciosamente las cuatro fuentes históricas. Cero opciones CLI, gramáticas ejecutables, perfiles autorizados, casos autorizados o despachos. P8 y obligaciones AL-06, AL-07 permanecen abiertos; P9 y A1–A10 no iniciados.

**EN:** 29-profile fail-closed material gap auditor pinned to prior deny-only sources. Historical source artifacts remain immutable; no executable binding or experimental advancement.
