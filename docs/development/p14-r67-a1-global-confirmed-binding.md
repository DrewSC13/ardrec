# ARDREC P14-R67 — Enlace de GlobalState / ConfirmedState con A1

**Base local:** `4d4774f6b38003cb101ce26e8463497e0a4837d4` (R66), rama `feat/p14-r65-a1-confirmed-model-binding`, sin push/PR/merge.

**Tesis:** ARDREC 17-11-2026, §3.6.1, figuras 3.4–3.5. Se conserva la semántica de `EVALUAR` y `DECIDIR`; no se añade autoridad operacional.

## Implementación

`src/ardrec/rules/global_binding.py` utiliza el códec canónico existente para reconstruir dos tipos ARDREC: `GlobalState` y `ConfirmedState`. Requiere sus bytes y pines SHA-256 *separados*; comprueba que `global.confirmed` coincida por contenido y codificación con la segunda fuente. Rechaza diferencias entre estados candidatos (`global.services`) y confirmados, así como intentos pendientes. Invoca el motor efectivo R66 para recomputar A1 contra el estado confirmado enlazado. Produce recibo inmutable y verificable mediante reproducción completa.

Existen rutas de evaluación desde bytes o desde **dos archivos privados distintos**; las lecturas de archivos reutilizan el guardián R66, sin escrituras ni subprocessos. No se alteran los modelos, los estados ni las filas A1.

Los datos de `global.authority` son **declaraciones internas del modelo**, no acreditación operacional. Las dos referencias SHA-256 verifican integridad de bytes, pero no prueban quién las emitió ni una generación A9 publicada. Tampoco prueban todavía que `ConfirmedState.configuration_sha256` corresponda a la configuración global ni que esta integre la instantánea de reglas R17. Por tanto se mantienen explícitamente `external_pin_authority_attested=false`, `a9_published_generation_attested=false`, `global_configuration_rules_binding_attested=false`, `operational_dispatch=false` y `p8_operational=NO-GO`.

## Oráculo y aceptación

Archivo: `lab/tests/test_p14_r67_a1_global_binding.py`, 32 pruebas sobre códec, identidad de dos fuentes, trivalencia, desacuerdo de generación, pinning, entradas inválidas, control de lectura privada, integridad, replay, falsificación y P8.

La reproducción aislada usó sustitutos del estado y del códec, por lo que **no acredita por sí sola el código real de Prometheus**. Allí se ejecutarán R67 y las regresiones focalizadas R66-R16/R17/R18/R22/R26/R58. La regresión total P14, CI y publicación se difieren a la aceptación final de A1, según la regla acordada por el propietario.

**Pendiente para A1 al 100 %:** vínculo con el recuperador durable real y su referencia de generación A9, verificación de procedencia/autenticidad externa de los pines y correspondencia entre configuración global y fuente de reglas R17, matriz de aceptación integral y pruebas P14/CI final.

**EN.** R67 recovers canonical GlobalState and ConfirmedState, verifies content equality, rejects unconfirmed candidates and pending attempts, re-evaluates A1 through R66, and records an independently replayable, deny-only report. No external provenance or A9 authority is claimed. Local-only development.
