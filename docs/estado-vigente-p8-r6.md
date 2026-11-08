# ARDREC — Propuesta P8-R6 (2026-11-08)

**Base comprobada**: PR #37 (P8-R5) integrado en `main`, SHA `61f978a8cda7315dd09f66f4e3d63d99a6d7ee4c`, CI de Python y Rust `SUCCESS`. No reescribir retrospectivamente los registros de P8-R3/R4/R5 que se conservan como historia.

**Objeto de P8-R6**: formalizar un oráculo determinista de **caducidad, revocación e invalidación de identidades por caso**, sin conceder permiso de ejecución. Los datos de R5 que toma como entrada son afirmaciones sintéticas; su origen no se verifica en R6. La comparación exacta de huellas de contexto detecta discrepancias pero no autentica autoridades.

**Límites**: 25 familias, 29 posiciones P8 bloqueadas; cero servicios-escenarios reales registrados, cero casos reales autorizados, cero materiales reales inspeccionados y cero despachos. Las 54 unidades previstas no son evidencia experimental creada. No se inspeccionan archivos del host, no se invocan herramientas ni se interactúa con VM.

**Pendientes**: AL-06 y AL-07 abiertos, siete obligaciones de desarrollo, confianza en emisor y revocación, reloj independiente, transferencia segura de identidad entre observación y uso, garantías del ejecutor Rust, límites de piloto, aislamiento y verificación experimental. P8-R6 no cierra el punto 8 ni implementa todavía A1–A10.

**EN:** Proposed source-only P8-R6. Public synthetic claims are fingerprinted, bounded in a declared UTC interval and invalidated by ordered events; no real issuer, time source, revocation status, binary custody, authorization or dispatch is verified.
