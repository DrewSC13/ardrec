# ARDREC — Estado P8-R10 (propuesta source-only)

**Base protegida exacta:** `4290e759842fa090a0fb13979501dd8a8cc7d760` (P8-R9 integrado por PR #42, CI de ready y posmerge verificados).

**Alcance:** punto 8 — definir perfiles de ejecución autorizados. P8-R10 agrega 29 **contratos semánticos tipados y no ejecutables**; no implementa argumentos ejecutables finales, no despacha, no crea casos experimentales ni comienza P9 o A1–A10. Los 15 hashes de P8-R9 siguen siendo observaciones de la imagen, no pines de ejecución viva.

El verificador contrasta el contrato con los datos originales P8 (29 perfiles bloqueados) y P8-R9 (observación material). Comprueba identidad de familia/variante, operación semántica explícita, referencias simbólicas requeridas, controles declarativos, cinco políticas de limpieza exigidas y ausencia de materialización del comando. La gramática separa una intención estructural de cualquier cadena para `ssh` remoto o `smbclient -c`. Un intento de rellenar campos de autorización, presupuesto, `argv` o comandos falla antes de publicar el resultado.

**Sin atribución indebida:** no se validaron las capacidades reales de 29 operaciones, no se fijaron las opciones reales de las herramientas ni las rutas privadas, no existe autorización emitida/revocación verificada, los escenarios P6 siguen sin casos y el piloto no determinó presupuestos. Los contratos no convierten un `ND` en `VERDADERO`.

**Pendiente P8:** capacidad comprobada por operación y versión, gramáticas/serialización segura, decisiones de herramientas auxiliares, manejo protegido de credenciales, ambiente y trabajo, límites finitos en piloto, origen confiable de materiales, vinculación a casos y destinos, autorizaciones y revocación y recibos de limpieza; límites efectivos y supervisión siguen en P9. AL-06/AL-07 y siete obligaciones abiertas. Cero despacho, cero casos reales, cero perfiles autorizados y cero validaciones experimentales.

**Estado de publicación:** este documento refleja una **propuesta** hasta verificar CI, firma e integración mediante el proceso protegido.

**EN:** P8-R10 proposes source-only symbolic per-variant intent contracts. All 29 remain blocked. No command serialization, process start, private authority, pilot bounds, experimental data or algorithm implementation is claimed.
