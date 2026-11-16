# ARDREC R58-A / F11-P — auditoría del guardia de arranque sin cambios físicos

## Estado de origen

- `main` integrado mediante PR #132; SHA base `c238f44a7f8cb9f8c251424fa7b5d9c9e9c7e94d`.
- CI de `main`: Python y Rust en éxito, según la lectura del operador.
- Bundle raíz instalado: `boot-guard.py` (`d2b25156…f0bb6`), `r34-deny.nft` (`8e971f03…b1f94`), `manifest.json` (`7b944380…f132`). Los hashes completos están fijados en el verificador.
- La unidad se observó `enabled / inactive / dead`, sin marca temporal ni InvocationID de inicio.
- La tabla `bridge ardrec_r34_guard` contenía las cuatro reglas DROP sobre las seis TAP. El filtro libvirt `ardrec-r33-block-until-containment` era DROP ALL.
- Cuatro máquinas DEV apagadas; red FTP inactiva.

## Análisis de `boot-guard.py` recibido del operador

`safe_staged()` verifica propietario, modo, inventario y SHA del bundle. `apply_if_missing()` lee y verifica R34 dos veces si está presente; si falta, comprueba ausencia inequívoca y sintaxis del contenido fijado antes de crearlo, seguido de dos lecturas. Este contrato es un **bootstrap puntual y delimitado**. **No es un watchdog** ni bloquea la API de libvirt, ni certifica el arranque manual de invitados.

`After=ardrec-r34-boot-deny.service` en libvirtd constituye una dependencia de **orden**. Sin `Requires=`, `Requisite=` o `BindsTo=`, no es una dependencia fuerte por sí misma. Incluso con una dependencia fuerte, la autorización de arranque manual de cada VM seguiría requiriendo una barrera independiente.

Por ello no hay base para declarar F11 completo ni activar FTP. El estado `Result=success` cuando el servicio está inactivo y sin `ExecMainStartTimestamp` no demuestra una ejecución satisfactoria de su `ExecStart`.

## Qué hace el verificador

1. Restringe su ejecución al repositorio principal, sobre un `HEAD` descendiente del merge base.
2. Ejecuta únicamente `git` de lectura, `systemctl show/cat`, `sudo -n sha256sum/stat`, `sudo -n nft -j -a list ...`, y `virsh --readonly` con verbos y nombres fijados.
3. Comprueba huellas y permisos de los tres archivos raíz; no lee ni imprime su contenido privado.
4. Verifica unidad systemd sin drop-ins, enlace de habilitación, dependencias efectivas de libvirtd y ausencia de primera ejecución acreditada.
5. Verifica sintáctica y semánticamente NFT DENY dos veces, el filtro libvirt DENY, las cuatro VM apagadas y la red FTP inactiva.
6. Devuelve JSON acotado sin archivos de evidencia ni cambios físicos.

## Códigos de salida

- **21**: guardia sin arranque registrado; estado bloqueado, lectura válida.
- **22**: arranque registrado pero no autenticado como primer arranque seguro; estado bloqueado, lectura válida.
- **23**: lectura fallida, permisos insuficientes, drift o contrato no acreditado; detener y revisar.

Ningún código concede autorización de aplicación física. `P8=NO-GO`, `manual_vm_boot_block_attested=false`, `first_boot_attested=false` y `independent_runtime_watchdog_attested=false` por diseño.

## Procedimiento seguro posterior

Antes de habilitar tráfico, redes o modificar XML de la VM runner: diseñar un mecanismo que haga fallar de forma cerrada los arranques de las VM DEV si R34 no está autenticado; demostrar su eficacia sin alterar servicios libvirt ajenos; documentar autenticación del primer arranque de F11 y recuperación física independiente (watchdog) con recibos privados. Los cambios de host y sus pruebas deberán tener una autorización separada.

El verificador **no realiza** `systemctl start/enable/daemon-reload`, `virsh define/start/net-start`, `nft -f`, reinicios ni lectura/escritura de archivos de invitado.

### F11-P F1 — Corrección de st_nlink del directorio

El campo `stat %h` del **directorio** de stage puede ser `1`, `2` o superior
según el sistema de archivos y sus subdirectorios; exigir exactamente 1 daba
`ROOT_STAT_PERMISSION_DRIFT` falso con entornos ext4. La corrección mantiene
propietario y grupo root (UID/GID 0), directorio modo 700, todos los archivos
regulares modo 600 y **exactamente un enlace físico por archivo**. Solo el
directorio admite un recuento positivo distinto de 1. No modifica el stage
real, R34, libvirt ni systemd y no acredita arranque ni autorización P8.

Se agregaron 16 casos de prueba, positivos y adversariales, incluido un
directorio temporal real.
