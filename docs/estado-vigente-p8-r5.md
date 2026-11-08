# ARDREC — Estado propuesto P8-R5, 8 de noviembre de 2026

**Base integrada verificada antes de crear este incremento:** `main` `2030ef4fe24e3595cfb365853912548ff3294056` (PR #36, P8-R4), CI de Python y Rust en `main` aprobado. Los registros anteriores conservan su versión temporal; no reescribirlos para simular que se actualizaron retrospectivamente.

**P8-R5 propuesto:** observación de bytes reales **solo de archivos sintéticos temporales de tests**, por FD, con comparaciones de SHA-256, tamaño, propietario, permisos, no-symlink y estabilidad limitada antes/después. Sin ejecutables, auxiliares ni identidad de versiones reales fijados. Sin autoridad sobre pins ni permisos de operación. Ninguna observación se usa para despacho.

**Base académica:** tesis de huella `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, secciones 3.7.5 y 3.9.2. Los datos de prueba son oráculos sintéticos y no registros experimentales.

**Inventario vigente:** 25 familias P7, 29 espacios P8, cero servicios–escenarios reales en P6, cero casos derivados reales, cero binarios operativos fijados, cero autorizaciones verificadas y cero despachos. La meta metodológica de 54 unidades no es un inventario congelado.

**Pendiente:** registro físico y control de confianza de binarios/versiones, resolución no sustituible entre comprobación y uso en Rust, custodia y autoridad privada, revocación, límites del piloto, aislamiento material, AL-06, AL-07 y siete obligaciones residuales. No equivale a cierre general de P8, aceptación funcional o hipótesis validada.

**EN:** Proposed, source-only P8-R5. Temporary synthetic file bytes are read and checked, but an untrusted declared digest and matching bytes cannot establish real binary provenance, authority, immutable future identity or runtime execution rights. No real assets, laboratory actions or experimental outcomes.
