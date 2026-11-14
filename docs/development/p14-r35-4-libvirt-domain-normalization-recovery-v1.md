# P14-R35.4 — Recuperación del tercer parcial y validación integral del XML libvirt

## Base y evidencia

- Base exacta `a8546f09d4e54c8b1699456fde5a55da03f1469c` (PR #104, R35.3). Ejecutar en rama propia, con firma Git y CI protegida.
- Recibo R35 inicial: `recibos-instalacion-20261114T144532Z-41790`, nft creado, verificador textual incompatible.
- Recibo R35.2: `recibos-recuperacion-r352-20261114T152149Z-51703`, filtro y SSH definidos, normalización XML de red rechazada.
- Recibo R35.3: `recibos-completacion-r353-20261114T181135Z-65714`, `failure_code=defined_domain_identity_mismatch_ssh`, informe digest interno `d162b844c014a3db4b4692d5761596bbb86a9405b868eca8e9bca68ecfbd112f`.
- Diagnóstico R35.4: `diagnostico-r354-BJfUdTza` (solo lectura): nft verificado, filtro verificado, las tres redes definidas e inactivas y dominio SSH definido/apagado; sin puentes ni TAP de reserva presentes.
- Fuente archivada R32–R34, SHA-256 `58e7cf2f59dd97cab948c190d637b6ff8ee8f67b45400769fe0d97a9e8f2ea36`.

## Normalización XML permitida

El XML esperado R33 declara memoria MiB (por ejemplo 768 MiB) y libvirt devuelve KiB (786432 KiB). Se evalúa equivalencia exacta, positiva y entera. El dominio conserva nombre, UUID, tipo KVM, vCPU, OS/machine, arranque, features, clock, políticas de ciclo de vida, flags PM, QEMU emulator y especificaciones exactas de disco, controladores requeridos, serial, canal, vídeo y balloon.

Se permite `cpu mode=host-model` con el único atributo libvirt `check=partial`, además de direcciones PCI generadas con formato validado, serial ISA normalizado y elementos libvirt adicionales, solo cuando son exactamente: controladores `usb/piix3-uhci` y `pci/pci-root`, consola `pty` vinculada a serial, dos inputs PS/2 mouse/keyboard, audio `none` y direcciones `virtio-serial` del canal. Se prohíben hostdev, filesystem, graphics, redirdev, vsock, TPM, RNG, shmem, smartcard y watchdog, así como discos, NICs o canales extra, cambios de MAC, red, filterref, backing o lifecycle. Los PCI address se comprueban sin duplicidad.

Los estados de dominio aceptados son solo `shut off` o `apagado`. Autoinicio deshabilitado se admite solo con `Autostart: disable/no` o `Autoinicio: inhibe/no`, sin inventar estados. El ejecutor ya usa entorno `LC_ALL=C` al invocar comandos, pero el comprobador reconoce las salidas localizadas efectivamente observadas.

## Recuperación cerrada

Se autentican los tres recibos físicos en orden, sus listas SHA-256 y digests internos. El tercer estado debe registrar exactamente tres escrituras previas de libvirt, en este orden: `net-define FTP`, `net-define SMB`, `define --validate SSH`. El informe debe tener digest fijado, tres redes inactivas, solo dominio SSH definido, nft/filter vigentes, bridge MACs fijadas y P8 NO-GO. Se rechaza cualquier otro acto de escritura en el historial, drift o un cuarto recurso existente.

El modo de preflight R35.4, `--preflight-existing-3networks-ssh-domain`, es de **solo lectura**. Además de los controles previos revalida: nft JSON, filtro deny-all, tres redes, tres MAC de bridge, cuatro roles/12 QCOW2 y el dominio SSH por XML normalizado, apagado y sin autoinicio, y ausencia de otros dominios ARDREC.

La opción distinta `--resume-existing-3networks-ssh-domain`, con `--i-authorize-r35-installation`, es una **operación física separada**. Reutiliza la tabla nft, filtro, tres redes y dominio SSH existente; define solo los tres dominios restantes en orden FTP, SMB, runner, sin arrancarlos. Rehash de 12 QCOW2 inmediatamente antes de las definiciones, doble lectura de dominios, comprobación final de TAP/bridges ausentes. Si hay cualquier fallo después de escribir, el estado queda parcial y se debe revisar sin reintentos ni rollback automático.

## CLI

Para el preflight, invocar `scripts/ardrec_p14_r35_inactive_deployment.py` con las opciones:

```text
--source-archive /RUTA/source-r32-r33-r34.tar.gz
--receipt-dir /RUTA/RECIBOS_NUEVOS
--prior-partial-receipts /RUTA/recibos-instalacion-20261114T144532Z-41790
--second-partial-receipts /RUTA/recibos-recuperacion-r352-20261114T152149Z-51703
--third-partial-receipts /RUTA/recibos-completacion-r353-20261114T181135Z-65714
--preflight-existing-3networks-ssh-domain
```

No combinar con autorización. La recuperación física posterior exige reemplazar la última opción por `--resume-existing-3networks-ssh-domain --i-authorize-r35-installation`, con otra ruta nueva de recibos y aprobación específica.

## Verificación y limitaciones

- Pruebas unitarias positivas y negativas, regression P14 con `umask 022`, trazabilidad actual, build de empaquetado, CI Python/Rust y commit firmado antes de preflight físico.
- Los recursos existentes no se redefinen ni se eliminan. Nunca se invoca `net-start`, `start`, `autostart`, `nft flush`, ni se escribe QCOW2.
- P8 permanece NO-GO aun si el despliegue inactivo concluye. El aislamiento de una topología arrancada y los controles de reinicio no están acreditados; no hay pentesting ni validación experimental.
- AL-06 y AL-07 permanecen abiertos. `system_functional_acceptance=PENDING`, `experimental_validation=NOT_RUN`.
