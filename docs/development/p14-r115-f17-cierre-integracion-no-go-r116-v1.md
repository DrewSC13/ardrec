# R115-F17 — Cierre de integración verificable, sin aceptación operacional

**Estado propuesto del PR:** listo para revisión e incorporación del **código fuente de R115-F1 a F17**, siempre que CI, firmas y protecciones de la rama principal aprueben. **No significa A3=VERDADERO, ejecución FTP-T01 real, A6 admitido ni P8=GO.**

## Alcance terminado en R115

- 54 unidades de caso y catálogo **25 familias** (SSH 8, FTP 8, SMB 9) preservados; el catálogo P7 permanece en `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`.
- Lecturas de configuración y aislamiento F11/R34, incluido el ciclo apagado y la topología física de **5 vínculos DENY activos + 1 ausencia por VM SMB apagada** para la etapa FTP. No se atribuye ese estado a la sesión actual si los invitados están apagados.
- Procedimientos de arranque único SSH → runner → FTP con autorización firmada, vigencia, revocación y recibos durables. No se ha ejecutado la cadena física durante F1–F16.
- Lector limitado FTP-T01, presupuesto de llamadas de recepción, reserva única previa a conexión, relectura de recibos y puente de clasificación A5→A6. Sus resultados offline son candidatos **NO_ADMITIDO**, no evidencias independientes.
- Requisitos de aprobación externa, separación de firmantes, ventana P8 firmada y contrato excepcional de piloto P7 de 60 s; no se han proporcionado firmas, raíces de confianza independientes ni permiso efectivo de tráfico.
- R115-F17 incorpora los 428 tests R115 históricos más pruebas de este cierre a CI y fija los 58 archivos de F1–F16 por SHA-256.

## Criterio de aceptación del PR

**Sí se puede incorporar:** código, modelos de autorización, validadores, pruebas, CLI de revisión, contratos de presupuesto, y evidencias de NO-GO. El merge conserva el historial de commits locales firmados; no debe modificar las VM ni el cortafuegos ni atribuir resultados físicos inexistentes.

**No se ha completado:** piloto físico P7, catálogo ejecutable, permiso real A3, recuperación autónoma de DENY para ventana 60 s en topología 5/1, controlador físico de red P8, admisión A6 de pruebas reales, recalibración A7–A8, publicación durable A9, y ejecución integrada A1–A10 con TUI. Esos objetivos no se pueden declarar aprobados.

La verificación de cierre prueba integridad estática y comportamiento conservador, **no sustituye** un experimento del laboratorio ni una autorización de un responsable externo. No se simularán recibos, certificados, permisos o resultados de riesgo para habilitar GO.

## Próximo hito: R116 — piloto físico y vertical funcional

1. Acreditar propietarios y raíces de confianza de alcance, arranque y piloto; firmar autorizaciones distintas con revocación y vigencia verificables.
2. Implementar y probar ayudante raíz de ventana FTP-T01 ≤60 s, con recuperación DENY autónoma, topología 5/1 y fallo seguro; ensayar recuperación antes de abrir tráfico.
3. Activar SSH → runner → FTP bajo autorizaciones separadas, comprobar enlaces y F11/R34 efectivos, mantener SMB apagada si el plan lo exige.
4. Realizar un piloto autorizado de una conexión y un intento (sin reintentos), con presupuesto finito F10–F13, capturas independientes y restauración DENY.
5. Calibrar y congelar P7 con métricas observadas y evaluación documentada; habilitar P8 solo bajo autorización **nueva**, explícita y válida.
6. Admitir o rechazar evidencia real A6 de forma independiente, integrar A7→A8→A9→A10 con estado durable, repetibilidad y TUI, y extender progresivamente SSH/SMB y las 25 familias.

## Trazabilidad y límites verificables

- Base F16: `3732b0c28926b86e35835972e8b7b256dfe7be13`, firma `G` reportada en Prometheus.
- Fuente del inventario SHA-256: manifiesto F16 (`previous_sha256` para 54 archivos + `new_files` para cuatro), incorporado en `lab/closure/r115-source-merge-gate-v1.json`.
- La evidencia física F16 reportada mantiene las cuatro VM apagadas, sin conexiones, con `P8=NO-GO`. Los recibos privados históricos **no** se incorporan al repositorio.
- La última regresión en Prometheus antes de F17 fue **1.331 PASS**: R115 428, R112 303, R113 350 y R114 250. R115-F17 se verificará de nuevo antes del commit y en CI.
- Ningún merge aumenta el alcance del consentimiento de laboratorio. No se desactivan las verificaciones de rama, hashes, presupuestos, firma o procedencia para conseguir un PASS.

## English — acceptance boundary

R115 may be merged as a **source integration and fail-closed readiness** milestone only. It is **not** acceptance of live P7 calibration, operational P8 dispatch, real A6 admission, or A1–A10 end-to-end validation. R116 owns those remaining, separately authorized tasks and retains `NO-GO` until independently verified.
