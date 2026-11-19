# R113-F4B — Preparación de servicios FTP/SMB con evidencia real

**Naturaleza:** dos consultas QGA locales `systemctl show`, sin cambios operativos, sin conexiones entre invitados.

**Base física:** R113-F4A (commit `277da5f6d7187567512e19092bf07b24febca4b9`) acreditó unidades deshabilitadas `vsftpd.service` y `smbd.service`, pero no demostró su estado de ejecución. El inventario F4A, su recibo y la clasificación F3T siguen siendo fuentes independientes e inmutables.

## Alcance exacto

- En FTP: `/usr/bin/systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,ExecStart,Result vsftpd.service`.
- En SMB: mismo comando para `smbd.service`.
- Ninguna consulta en SSH o runner; no ejecutar `systemctl start`, `enable`, `restart` ni `stop`.
- `nmbd.service` y `samba-ad-dc.service` permanecen enmascaradas y fuera de alcance.
- Se comprueban F11/R34, estados físicos, identidad QGA y recibo F4A antes de iniciar una consulta.

## Clasificación

`CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION` requiere `LoadState=loaded`, `ActiveState=inactive`, `SubState=dead/exited`, `UnitFileState=disabled/enabled`, `FragmentPath` absoluto y `ExecStart` presente. Esto no prueba que el archivo de configuración de FTP o Samba sea seguro ni que el servicio arranque correctamente. Estados activos, fallidos o ambiguos detienen cualquier decisión de arranque posterior.

## Control de evidencia

Sesiones exclusivas con permisos 0700 y archivos 0600 en `/home/cicada/ardrec-lab/r113-f4b-unit-readiness-v1/readiness-*`. Se persisten marcadores antes del `guest-exec`, respuestas originales antes de clasificarlas y manifiesto SHA-256 con replay determinista. No se reciclan marcadores ni se reintentan consultas inconclusas. El código no toca Git remoto ni modifica reglas de red.

**Etapa siguiente:** si ambos diagnósticos reportan preparación válida, verificar la configuración mínima de cada demonio y autorizar por separado el arranque de `vsftpd` y `smbd`, manteniendo R34 en DENY. Inspeccionar nuevamente TCP 21 y 445 después del arranque; luego, y solo entonces, evaluar admisión temporal y reversible de tráfico entre runner y cada destino.

**P8:** NO-GO. No hay observaciones de protocolo ni autorización de tráfico en F4B.
