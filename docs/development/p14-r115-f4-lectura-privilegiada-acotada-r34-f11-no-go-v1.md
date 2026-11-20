# R115-F4 — Verificación de DENY de seis vinculaciones con fuentes del anfitrión

**Rama:** `feat/p14-r115-a3-p7-a6-real`. **Base:** `a652195a544a549dbad6a44120e3d447cf4d4994`. F1, F2 y F3 permanecen sin commit. Este incremento no modifica los contratos R111–R114 ni ejecuta tráfico, VM, servicio FTP, catálogo P7 o P8.

## Motivo

F3 acreditó coincidencia de **definiciones** de seis NIC, tres redes y `nwfilter`, pero dejó `R115_F3_CHECK_F11_HOOK=ND`, `R115_F3_CHECK_R34_NFT=ND` y seis vinculaciones efectivas no acreditadas. La razón más probable es acceso insuficiente a las fuentes root; **no se infiere** un fallo de política por esa ausencia. Se reutiliza el validador desplegado en R113-F6, cuya operación `--attest-deny` solo ejecuta lecturas y comprueba el paquete root protegido, la tabla nftables y seis filterbindings. Su operación `--restore-deny`, que sí muta, está explícitamente excluida.

## Comportamiento del componente

El nuevo módulo `src/ardrec/coordination/r115_f4_effective_deny_readback.py` tiene dos modos:

- `--capture`: inspección F3 no privilegiada; **no invoca sudo**.
- `--capture --with-privileged-readback`: además ejecuta exclusivamente (mediante `/usr/bin/sudo -n --`, sin prompt de contraseña ni cambio de sudoers) `sha256sum` sobre `/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py`, `sha256sum` sobre `/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny` y el propio root helper `--attest-deny`. Antes de ejecutar el helper exige SHA-256 `3a9c2d0e70d7b6b808ee2eaf7382b11715c2e2d8e0f777ff627a1ed084a8bb05`, correspondiente al código R113-F6 revisado en el repositorio. Si no coincide, **el helper no se invoca**. Tampoco lo invoca si el hook F11 difiere de su huella fijada.

No se hace `sudo -v` ni se abre un diálogo desde el ejecutor. El usuario debe invocar explícitamente el segundo modo y disponer de política de autorización local preexistente; una denegación de `sudo -n` queda como `ND`, jamás como aprobación. No se escriben recibos como root. Los resultados completos, incluidos errores y hashes, se guardan bajo `/home/cicada/ardrec-lab/r115-f4-readonly-deny-v1/capture-*` con permisos privados.

## Interpretación estricta

- `CHECK_HELPER=MATCH`: bytes del helper root coinciden con el pin R113; no prueba que se haya ejecutado aún.
- `CHECK_HOOK=MATCH`: bytes actuales del hook F11 coinciden con el SHA vigente R113; no equivale a comprobar el efecto del hook durante un arranque.
- `CHECK_SIX_DENY_BINDINGS_AND_NFT=MATCH`: el helper ejecutado declaró `SIX_BINDING_DENY_ATTESTED`, seis vinculaciones, **cero escrituras** y P8 NO-GO después de validar sus fuentes. Solo es evidencia de lectura efectiva **en ese instante**.
- `ND`: falta de permiso, timeout, error de comando, ausencia o fracaso de una fuente; el reporte privado guarda el error. `DRIFT`: datos leídos que contradicen un pin o resultado requerido. DRIFT fuerza `LAB_ISOLATION_CONFIRMED=FALSO`; un MATCH no fuerza VERDADERO.
- Las VM siguen apagadas según la última lectura F3, así que `SERVICE_READY=FALSO` hasta nuevas comprobaciones. Que existan filterbindings sin VM activa no acredita una ventana operacional ni autoriza una prueba.

Ni siquiera tres MATCH anclan legitimidad institucional de firmantes/autoridad, atestación del cliente, configuración efectiva FTP, permiso de destino, admisión A6 ni publicación A9. Todos permanecen en NO-GO o ND. El root helper es un validador de DENY: su éxito **no concede el permiso de levantar filtros**.

## Pruebas e integración

20 nuevas pruebas adversariales cubren pin exacto, hash falso, denegación de sudo, salida de atestación falsa o malformada, datos con claves duplicadas, timeouts, truncamiento, ventanas, tipos JSON, conjuntos de comandos limitados, rechazo de lecturas no solicitadas y conservación de `NO-GO`. El instalador verifica huellas exactas de F1/F2/F3, rama, HEAD, catálogo, integridad ZIP y que solo se crean tres archivos nuevos antes de pruebas. No hace commits ni altera reglas, servicios o máquinas virtuales.

**Continuidad:** con la salida real, resolver permisos o divergencias de solo lectura mediante el mecanismo administrativo vigente; después establecer una raíz de confianza de autoridad externa por caso, sin autogenerar permisos. Solo tras A3 + catálogo/profiles validados se conectará A5/A6 reales y publicación A9.
