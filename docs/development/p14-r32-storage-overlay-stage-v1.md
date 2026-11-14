# P14-R32 — Materialización de cuatro overlays nuevos (laboratorio de desarrollo)

**Base exacta:** `fd23463b9d6893aa1ac1a06680bbdf95be47b47d`, PR #97. No sustituye ni reescribe los recibos R29–R31 ni la evidencia física de laboratorio del punto 5.

## Objetivo y entrada

R31 acreditó 4 bases y 4 overlays v6 mediante lectura privada con `sudo -n`. R32 consume **el archivo R31 auténtico** fijado por SHA-256 externo y el hash interno verificable, y exige 8/8 `READONLY_VERIFIED`, con custodia histórica por rol y `NO-GO` preservado. Los overlays v6 —y no directamente las bases v4— serán los *backing files* de cuatro overlays **nuevos**, para preservar la corrección FTP incorporada al overlay v6.

La ruta de destino, fija e imposible de alterar por entradas del usuario, es `/var/lib/libvirt/images/ardrec-dev-point4-r32`. Los cuatro nuevos archivos se llamarán `ssh-runtime.qcow2`, `ftp-runtime.qcow2`, `smb-runtime.qcow2` y `runner-runtime.qcow2`.

## Comportamiento

- `--plan`: valida el recibo R31 y serializa un plan de 4 COW; no invoca `virsh`, `sudo`, `qemu-img` ni otras acciones externas.
- `--stage-new-overlays --i-authorize-four-new-overlays`: **acción nueva y real**, solo después de autorización expresa del operador. Requiere Python no privilegiado, ticket `sudo -n` vigente, `libvirt` sin recursos ARDREC con esos nombres, raíces de almacenamiento de confianza y 40 GiB libres; valida hashes actuales y backing v6→v4 antes y después.
- Crea **un directorio nuevo** (sin reutilización ni recreación), define su grupo de acceso libvirt/QEMU y produce cuatro overlays QCOW2 nuevos con `qemu-img create -f qcow2 -F qcow2 -b`. Cada nuevo archivo se adjudica al UID/GID QEMU 64055 con modo 0600 y se verifica en modo lectura: formato, tamaño, backing, huella SHA-256 y metadatos de custodia.
- Solo se admiten invocaciones explícitas y exactas de los binarios del sistema: `sudo -n mkdir/chgrp/chown/chmod/qemu-img/stat/sha256sum` y `virsh --readonly` para inventario. Python y el programa de Git **no se ejecutan como root**. No se evalúa shell ni se aceptan rutas o roles arbitrarios.
- Si se produce una diferencia, indisponibilidad o fallo intermedio: NO reintentar sobre el mismo directorio. Se conserva el directorio y todos los hijos creados para análisis; el recibo externo queda marcado `INCOMPLETE_REVIEW_REQUIRED`. No hay limpieza automática y no se borra evidencia.

## Límites de aceptación

`FOUR_NEW_COW_OVERLAYS_VERIFIED_NOT_STARTED` indica **almacenamiento COW preparado**, no restauración de invitado, inicio de VM, identidad actual, conexión de red, ejecución SSH/FTPS/SMB, transición A8, generación A9 ni acreditación de A6/A7. En todos los casos `can_restore=false`, `operational_dispatch=false`, `p8_operational=NO-GO` y `final_risk=null`.

El nuevo directorio se crea una sola vez. Los nombres R32 no sustituyen v4/v6. Las huellas de las imágenes fuente se comprueban antes y después; sin embargo, la lectura de metadatos no reemplaza controles de montaje/custodia externos ni constituye validación operacional.

## Criterios de prueba y trazabilidad

- Pruebas unitarias de formato de recibo R31, rutas estáticas y hashes.
- Pruebas negativas de `sudo` genérico, destinos redirigidos, operación de red/VM, planes falsificados, fallos de almacenamiento y preservación de ejecución parcial.
- Prueba vertical solo con simulación de subprocess para R32; la creación física es un paso manual independiente.
- Regresión P14 y verificador de trazabilidad sin modificar el inventario histórico.
- Recibos de ejecución **fuera de Git**, con hash de contenido y nombre único. No incorporar rutas privadas, credenciales ni datos de terceros al repositorio público.

Próximo alcance **R33**: nueva topología privada sin NAT, inventario de redes/identidades, apagado y contención verificables, y solo después puesta en marcha autorizada del runner y de los tres invitados. R32 no inicia ese trabajo.
