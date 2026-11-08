# ARDREC — Propuesta P8-R7, 8 de noviembre de 2026

**Base integrada verificada:** PR #38 (P8-R6) en `main` `bd3500bfc7310abdbaf9bb1e57042e1c526f25d7`, con firma válida, CI Python/Rust posterior al merge aprobado y sincronización local comunicada. Los documentos de cortes anteriores no se reescriben retrospectivamente.

**Incremento P8-R7:** una gramática de **diagnósticos denegados** y su evaluación compatible en Python y Rust. Los dos validadores reciben exactamente los mismos documentos JSON sintéticos mediante fixtures y una sonda Rust estándar de solo lectura de bytes por `stdin`. La sonda **no** es una API de despacho ni una ruta de socket operacional. La igualdad de las respuestas no acredita autoridad sobre el contexto, los materiales, el emisor, el reloj ni las revisiones.

**Cobertura propuesta:** 106 vectores compartidos más tests de rechazo, 29 posiciones P8, restricciones de bytes y campos, duplicados, identidad cruzada, estado R5/R6, época material, revisión y promoción de autoridad. Toda salida tiene `decision=BLOCKED_UNBOUND_NO_EXECUTION`, `authorized=false`, `dispatch_allowed=false`. El código fuente y sus nuevas pruebas deben superar CI antes de considerar este incremento integrado.

**Limitaciones vigentes:** cero casos reales autorizados, cero binarios verificados operativamente, cero despachos, sin pruebas físicas, sin auditoría de revocación privada, sin transferencia de descriptores entre procesos, sin verificación de aislamiento y sin implementación integral A1–A10. AL-06 y AL-07, más siete obligaciones residuales, permanecen abiertos. El punto P8 general permanece abierto.

**EN:** Proposed P8-R7, synthetic Python/Rust denial diagnostics sharing one strict JSON fixture corpus. Matching denial decisions do not establish runtime, issuer, clock, binary or case authorization. No VM, operational command, real experiment or dispatch is performed.
