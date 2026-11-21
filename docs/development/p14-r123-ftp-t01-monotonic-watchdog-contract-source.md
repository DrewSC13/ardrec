# R123 — FTP-T01: contrato de supervisor DENY, ventana monotónica ≤60 s

**Alcance real:** SOURCE_ONLY, sin instalación de servicios raíz, sin arranques de VM, sin reglas permisivas, sin sockets. Base: `main` fusionado en PR #206, commit `5ca73c52898cfc2bf58e64d998579eefb06e17c5`. El controlador **autónomo físico no está implementado** en esta entrega; R123 constituye el contrato verificable para su integración independiente posterior.

## Problema que resuelve

R122 reconstruye el recibo físico F5 y el expediente A5–A10, pero no establece cómo supervisar una futura ventana excepcional de piloto FTP-T01 sin pérdida de contención ante caída del proceso. R123 define la secuencia de supervisión y sus invariantes de rechazo, enlazada al reporte R122 recompuesto desde sus fuentes originales.

## Contrato y seguridad

- Máximo total: **60 segundos**. Objetivo de restauración: **≤45 segundos**, reservando 15 s para verificación y contingencias. Los tiempos operativos reales deberán constatarse por un supervisor **autónomo e independiente**, no por Python del checkout o un mero temporizador en memoria.
- Eventos de modelo, en orden: `PREPARED → DENY_GUARD_ARMED → SESSION_CLOSED → DENY_READBACK_VERIFIED`, con estampas monotónicas enteras en nanosegundos, ligadas al mismo hash del plan. Se rechazan regresiones, un exceso de 60 s, armar tarde, acciones físicas simuladas como hechos, y secuencias mal formadas.
- El modelo **no acepta** `root_supervisor_proof=True`. Incluso una traza sintética completa retorna `root_supervisor_independently_attested=false`, `physical_deny_reapplied=false`, `A6=ND`, `A9=null`, `P8=NO-GO`.
- El informe R123 se obtiene con `r122.verify(...)`, releyendo fuentes F5/F13/R121, validando coincidencia de HEAD e integridad. Conserva el estado observado, los bloqueos y las salidas no autoritativas; si la evaluación R122 tiene más de 60 s, añade `R122_BOUNDARY_EVALUATION_NOT_FRESH`.
- R115-F15 ya valida autorizaciones documentales firmadas y revocación cuando existen fuentes independientes; `pilot_bundle` es opcional y su revisión no habilita físicamente el piloto, aun cuando `document_status=DOCUMENT_SIGNED`.
- No se modifica `DurableStore`, la política P7 ni P8, los límites de A5 ni las definiciones actuales de SSH/FTP/SMB. No se tocan cierres previos F5B/R117/R118.

## Uso read-only en Prometheus (Zsh)

Desde `/home/cicada/Development/GitHub/ardrec`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r123_guarded_window.py --capabilities | more
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r123_guarded_window.py \
  --inspect --head "$(git rev-parse HEAD)" \
  --capture /home/cicada/ardrec-lab/r115-f5-lifecycle-deny-v1/capture-xgwi5e2_ | more
```

La captura es **histórica** y su único resultado aceptable para operación es un diagnóstico con bloqueos, jamás una autorización. La CLI no abre red, no requiere sudo y no inicia huéspedes.

## Pruebas y rechazo

`lab/tests/test_p14_r123_guarded_window.py` comprueba integridad de F5/R122, manipulación de identidades y riesgos, reloj UTC y monotónico, duración, datos F15 no confiables, conexiones y arranques ficticios, degradación a `NO-GO` y ausencia de subprocess/socket. Se ejecuta junto con las regresiones R122–R117, F13–F16, R58-E, TUI R38 y R69.

## Pendientes para habilitación física

1. Implementación **fuera del checkout no privilegiado** de un supervisor raíz, servicio de denegación de seguridad autónomo, independiente y de un solo uso, con prueba física de caída, persistencia de cierre y confirmación de F11/R34 después de 60 s.
2. Autoridad P7 piloto firmada independiente, revocación fresca y anclaje de identidad; aprobación de alcance A3, arranque atestado F7/F8 y prueba de topología 5/1 DENY.
3. Revalidación justo antes de ejecutar A5, sin reutilizar permisos históricos, con presupuesto y recibos de conexión independientes.
4. Evidencia A6 admitida a partir de testigos reales, A7/Rf confirmado únicamente si corresponde, A8 transacción aplicada y publicación durable global A9 con recuperación tras caída.

**No equiparar las pruebas de modelo R123 con una garantía de seguridad de un supervisor físico.** La presentación de tesis debe etiquetar estos estados como diseño verificado, no como ejecución operacional.
