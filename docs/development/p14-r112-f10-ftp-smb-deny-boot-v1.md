# R112-F10 — Arranque físico autorizado FTP → SMB; R34 DENY

## Alcance y evidencia de origen

- Rama acumulativa `feat/p14-r111-r114-real-lab`; HEAD base `e57b985db04464991ca7b04dbd4a70fae9d3abe6` (F9).
- Recibo físico F9 raíz: `/home/cicada/ardrec-lab/r112-f9-real-runner-boot-v1/boot-cx9ri8bs/receipt.json`, SHA-256 `88bda990407c0902ff44c731ed8333a52e0adeca533f5d6f93348b2412d9af36`.
- Mantener SSH y runner encendidos y R34 en DENY. No autorizar tráfico ni declarar hallazgos de protocolos.
- El nuevo ejecutor solo permite FTP y SMB, en ese orden, con planes, autorizaciones, leases y recibos distintos.

## F10 — Dos arranques independientes

1. **Instalación de código, pruebas y plan inicial**: autenticar ZIP y SHA de cada payload, comprobar HEAD/rama/worktree limpio, compilar, ejecutar todas las pruebas `test_p14_r112_*.py`, crear commit firmado, generar plan FTP. **Cero arranques** en esta etapa.
2. **FTP**: requiere que SSH y runner sigan ejecutándose y FTP/SMB apagadas; auditar 29 comandos, F11, nwfilter y nftables R34. Verificar recepción F9 mediante replay, ausencia de lease o marcadores FTP, comparar plan con host actual, grabar `boot.once` *antes* de cualquier mutación privilegiada, instalar exactamente un lease FTP root 0600 y ejecutar un único `sudo -n virsh -c qemu:///system start ardrec-r33-dev-ftp`. Auditar estado y XML live y tres fases del hook.
3. **SMB**: no se prepara hasta que el recibo FTP haya sido generado y reproducido; requiere SSH, runner y FTP ejecutándose y SMB apagada. Repetir guardas con ticket y marcadores específicos de SMB; un único inicio SMB. Prohibido reutilizar la autorización FTP.

**Los dos inicios requieren autorizaciones distintas.** Si falla una operación o lectura, detener inmediatamente. No reintentar, no apagar, no borrar marcas o leases ni modificar F11/R34. Guardar evidencia original y diagnóstico posterior sin reinterpretar una falla como éxito.

## Persistencia, reproducibilidad y criterios

Los planes, intentos, tickets, comandos, capturas y recibos permanecen en `/home/cicada/ardrec-lab/r112-f10-real-ftp-smb-boot-v1/` bajo permisos privados. Cada `receipt.json` solo se genera tras verificación de XML, topología, estado del resto de VM, invariantes F11/R34, comando real y marcadores root. El replay del segundo paso encadena el recibo FTP y el original F9.

**Éxito F10** significa únicamente que las cuatro VM están encendidas y aisladas con DENY, y se pueden reconstruir las dos transiciones FTP/SMB a partir de evidencias físicas. No autoriza paquetes de red, pruebas de protocolo, ni recalibración A6/A7, persistencia A9, P8, muestra experimental o conclusión de tesis. R113 introducirá permisos temporales y mínimos por interfaz, destino y puerto, con capturas reales de protocolos; R114 integrará A1–A10 y TUI.

Las pruebas unitarias sintéticas se identifican explícitamente como regresión, jamás como evidencia operacional.

## English engineering summary

F10 adds two independently authorized, one-shot libvirt boots (FTP first, SMB second), each with isolated root F11 lease, durable attempt marker, replayable physical receipt and strict before/after 29-probe host audit. Pinned F9 evidence and successful FTP receipt are chained as prerequisites. The four guests remain strictly deny-isolated; no network traffic, A5/A6/A7/A9 or P8 authorization is conferred. No automatic retry, shutdown, firewall change or lease cleanup.
