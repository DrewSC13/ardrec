# R112-F9 — Arranque físico único del runner con denegación R34

## Estado y procedencia

- Rama de trabajo: `feat/p14-r111-r114-real-lab`.
- Antecesor obligatorio: `2ec2dbdac50ce259364b4c79f772aebd5db01e46` (R112-F8S).
- Fuente privada inmutable: `r112-f8s-reconciliation-v1/reconcile-x8d4l0tu/receipt.json` con SHA-256 `c03816343ced7bd471a7f7c62a0295176d8d23c67e67d8b52668c19dff5bee36`.
- El recibo F8S acredita solo el arranque QEMU SSH. No acredita protocolo SSH, ni tráfico de red, ni P8.

## Contrato F9

El incremento permite **exactamente un** `virsh start ardrec-r33-dev-runner`, únicamente desde la terminal Prometheus, previa autorización explícita del operador y con F11 y R34 conservados. Antes del inicio, SSH debe permanecer ejecutándose y runner/FTP/SMB deben estar apagados. Al terminar, SSH y runner deben permanecer ejecutándose y FTP/SMB apagados. Las tres redes permanecen activas pero sin forwarding, IP, DHCP ni DNS. El nwfilter por interfaz y la estructura nftables R34 de cuatro reglas DROP se mantienen. Esta etapa no autoriza tráfico entre máquinas.

La ejecución valida las 29 lecturas auditadas de `f6.capture()`, el inventario de dominios/bridges, el hook F11, tres etapas `prepare/start/started`, un lease root vinculado al runner y el XML live del runner con exactamente tres NIC. Los atributos de libvirt `connections` se normalizan **solo** para los XML de redes; no se omiten otros cambios.

## Dos fases sin instalaciones adicionales

1. Autenticar ZIP y aplicar sus cuatro archivos nuevos; ejecutar la suite R112, generar un plan físico privado y realizar commit local firmado. Esta fase no ejecuta un arranque.
2. Revisar el plan producido y ejecutar `--boot-runner <ruta-plan> --i-authorize-one-real-runner-boot-under-r34-deny`, con sudo precargado por `sudo -v`. Un archivo `boot.once` duradero se crea **antes** de cualquier instalación del lease y del único start. No hay reintento, rollback automático, shutdown, destroy, modificación de red ni limpieza del lease en caso de fallo.

El plan y el recibo de ejecución permanecen bajo `/home/cicada/ardrec-lab/r112-f9-real-runner-boot-v1/` con permisos privados. Se guardan `intent`, ticket, lectura de grant, resultado de `virsh start`, capturas antes/después, XML live y reclamaciones del hook. El `receipt.json` solo se crea si pasa la clasificación exacta. Si el inicio ocurre pero falla una comprobación posterior, el evento se conserva como incidente `NO-GO`, sin repetirlo.

## Criterio de aceptación

**F9=PASS_BOOT_ONLY** exige un recibo privado verificable y replay positivo, sin tráfico autorizado, con la VM runner observada ejecutándose junto a SSH. No acredita SSH/FTP/SMB de aplicación, la tesis, A5/A6/A7/A9 ni habilita P8. El cierre R112 requiere fases posteriores de autorización de red estrictamente delimitada, adquisición real de protocolos e integración R113/R114.

## English engineering summary

One-shot, explicitly authorized physical libvirt runner boot. SSH remains running; FTP/SMB remain shut off; R33 nwfilters and R34 four-drop-rule structure stay denied. 29 physical probes are revalidated before and after. The root lease is one-use and its three hook lifecycle markers are checked. No network traffic is authorized. No automatic retry, shutdown, lease cleanup or P8 promotion. Synthetic unit tests never count as physical observations.
