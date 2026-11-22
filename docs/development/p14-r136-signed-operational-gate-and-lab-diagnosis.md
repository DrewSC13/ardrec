# R136 — Admisión semántica B4/B9 y diagnóstico de VM (solo fuente)

## Identidad de base

- Rama: `feat/ardrec-cierre-operacional-experimental`
- Commit anterior firmado: `f789fb16c5a3295220d17b30bd3f5ac5c1f353ec`
- Árbol Git: `b71e221dbe11ee7c510fe900227a76bce6fa9a7a`
- `main` queda en `95a6d57b8241101c7a8fa3aedc07fb779b088d9f`.

## Funcionalidad

El módulo `r136_operational_semantics.py` usa exclusivamente bytes con SHA-256 fijado de B4/B9 V2 y ejecuta sus validadores originales **puros** (sin invocar métodos host-changing). Verifica las firmas Ed25519 y revocaciones vigentes para el paquete de control DENY de B4, su contrato, autorización de alcance, permiso piloto, ventana/budget y el traspaso F13 de B9, además del grant de tráfico de B9. Vincula `head`, `boot_id`, sesión, caso, destino FTP, presupuestos y hashes.

El módulo **no es el instalador root**, y las fuentes no pueden cargarse desde el checkout mutable en un proceso privilegiado. Los documentos externos que recibe son entradas **no confiables** hasta que un agente root independiente verifique su propietario, permisos, procedencia, anclajes de confianza y vigencia. Una revisión positiva solo demuestra coherencia semántica y validez de firmas frente a las claves suministradas. **No autoriza el tráfico**: el estado sigue `P8=NO-GO`.

La comprobación de la liberación operacional B9 (`release.json`) por el verificador `signed_release` y las guardas de R116/F8 requieren pasos posteriores de integración en el agente root. Por ello, aunque se verifiquen B4 y B9 tráfico/handoff, una decisión de instalación aún no está acreditada. La prueba positiva usa 10 claves Ed25519 efímeras de test, no material operacional.

## Diagnóstico físico

`scripts/ardrec_p14_r136_lab_diagnosis.py --report ARCHIVO_R135.json` interpreta únicamente un informe R135 ya capturado, distingue consultas fallidas, VM desalineadas y redes no consultadas. No realiza llamadas a `virsh`, no arranca VM, no modifica bridges/nftables ni aísla interfaces. El informe interpreta estados; **no demuestra 5/1**, DENY físico ni restauración autónoma.

Se espera para el piloto: `ssh=running`, `ftp=running`, `runner=running`, `smb=shut off`; las redes SSH, FTP y SMB deben responder a consulta `virsh net-info`. Un error en la consulta no se confunde con una VM detenida. No intentar autocorregir el estado mediante este diagnóstico.

## Pruebas

- 18 regresiones de validación semántica B4/B9, incluyendo una ruta con firmas reales de diez claves efímeras; rechazadas las firmas inválidas, la revocación, los cambios de scope, budget, destino y `boot_id`.
- 12 pruebas de la clasificación read-only de la topología declarativa de R135.
- Regresión integral de R130 (75), R132 (20), R133 (32), R134 (20), R135 (44) y R136 (30): **221** pruebas, en Prometheus.

## Cierre pendiente del proyecto

- Provisión independiente de agente root, llaves y revocaciones confiables.
- Validación de liberación B9 completa, commit Git firmado y F8 histórico root.
- Instalador transaccional B4/B9 en destinos operacionales con readback y recuperación real.
- Comprobación física de 5/1, DENY y restauración autónoma.
- Una sola ejecución FTP-T01 autorizada y concatenación de A1–A10.
- Evidencias verificadas de 54 unidades experimentales, sin resultados fabricados.

NO root install, NO network, NO automatic VM start, NO PR/merge. Evidencias privadas fuera del repositorio público.
