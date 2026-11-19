# R113-F3 — Lectura local de sockets TCP mediante QEMU Guest Agent

**Objetivo:** consultar exclusivamente `ss -H -ltn4` dentro de las máquinas `ardrec-r33-dev-ssh`, `ardrec-r33-dev-ftp` y `ardrec-r33-dev-smb`. La inspección ejecuta un proceso breve en cada invitado mediante el canal QGA. No se ejecutan conexiones TCP, scans, autenticaciones, cambios de firewall ni modificaciones persistentes deliberadas.

**Base:** R113-F2 (IP/MAC/CIDR reales, proof SHA-256 fijo) y controles F11/R34 del R112-F10R. Solo se admiten las máquinas propias del laboratorio de ARDREC. El operador debe autorizar expresamente una ejecución por invitado.

**Procedimiento:** (1) validar Git, recibo F2, 4 VM y 3 redes en aislamiento DENY, IP exacta QGA; (2) comprobar que `guest-exec` y `guest-exec-status` estén habilitados en cada invitado; (3) crear un directorio privado y marcadores de un solo uso antes de cada ejecución; (4) enviar únicamente `/usr/bin/ss -H -ltn4` sin shell; (5) consultar estado y decodificar respuestas QGA con límites de tamaño; (6) volver a auditar F11/R34; (7) escribir evidencia, hashes, clasificación y replay determinista.

**Interpretación:** `LISTENING_ON_LAB_IPV4` solo prueba que el SO invitado informa un socket en el puerto y dirección esperados. No acredita nombre, versión o seguridad de servicio, conectividad, ni vulnerabilidad. `LISTENING_ONLY_ON_OTHER_IPV4` y `NO_LISTENER_AT_EXPECTED_PORT` no activan remediación automática. Se verifican TCP 22 (SSH), TCP 21 (FTP) y TCP 445 (SMB). FTPS, FTP pasivo y otros transportes requieren admisión independiente.

**Conservación:** en caso de respuesta indeterminada, falta de `/usr/bin/ss`, QGA deshabilitado o cambio de R34, detenerse. No reejecutar el comando sin reconciliar la evidencia de intentos. Registro `0700`, archivos `0600`, huellas SHA-256, historial Git firmado. Se preservan el aislamiento y `P8=NO-GO`; A5/A6/A7/A9 siguen sin acreditarse. El siguiente incremento R113-F4 define la admisión temporal de tráfico interno y su revocación antes de probar comunicaciones.

**English summary:** local, bounded TCP listener inventory inside three lab guests. It is not network reachability, exploitation, or a P8 authorization. Retain deny-by-default and signed, reproducible evidence.
