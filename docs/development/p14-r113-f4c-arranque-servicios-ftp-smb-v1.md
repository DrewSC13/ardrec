# R113-F4C — Arranque controlado de vsftpd y smbd con revisión local

**Antecedente inmutable:** F4B, commit firmado `7d4b4f58189e3868afb9441cbfaa1c173d9310a2`; recibo privado `readiness-h1asomyk`, SHA-256 de manifiesto `dd8377392b03c1f15f1a907483b65c5d63145837310e69a4f328bf62431b2924`.

## Alcance y separación de autorizaciones

La instalación añade un clasificador, ejecutor, pruebas y este documento. El instalador **no ejecuta QGA ni modifica servicios**. Requiere 452 regresiones (431 anteriores y 21 específicas), árbol limpio y commit firmado.

Cada rol exige autorización textual independiente. Para cada uno se comprueban de nuevo los estados de las 4 VM, F11/R34 en DENY, tres redes, identidad IP/MAC de QGA y recibo F4B. Se permite exclusivamente:

- FTP: `/usr/bin/systemctl start vsftpd.service`.
- SMB: `/usr/bin/systemctl start smbd.service`.

Antes del arranque se vuelve a consultar `systemctl show` y se exige `inactive`, `loaded`, unidad definida y ejecución declarada. Después se captura `systemctl show` y `/usr/bin/ss -H -ltn4` dentro **del mismo invitado**. No hay conexiones inter-VM ni cambios de firewall, DHCP, redes, XML, usuario, cuentas o credenciales. No se modifican las configuraciones de vsftpd ni Samba. No se invocan `enable`, `restart`, `stop`, `nmbd` o `samba-ad-dc`.

## Evidencia e incidentes

Sesión privada nueva por servicio bajo `r113-f4c-service-activation-v1/{ftp,smb}-*` (0700). Capturas QGA originales y marcadores de un solo uso (0600). `started-start.once` se persiste **antes** del `systemctl start`. Error/timeout/resultado incierto: se conserva sesión incompleta, sin reintentar, reiniciar, detener ni restaurar servicios automáticamente.

Una sesión completa incluye recibo, manifiesto SHA-256 y replay determinista sin QGA. Dos resultados posibles para un arranque acreditado:

- `ACTIVE_WITH_LAB_IPV4_LISTENER`: servicio systemd activo y puerto esperado enlazado a IPv4 del laboratorio o `0.0.0.0`.
- `ACTIVE_WITHOUT_VERIFIED_LAB_IPV4_LISTENER`: unidad activa, pero el puerto esperado no se acreditó en IPv4; por ejemplo, escucha solo en IPv6 o requiere configuración. **No implica conectividad.**

No se validan aquí el contenido completo de `vsftpd.conf` y `smb.conf`, ni los permisos de recursos compartidos, ni los protocolos de aplicación. Esos controles deben comprobarse antes de habilitar tráfico. Los procesos de los servicios podrían intentar comunicaciones propias, pero el aislamiento R34/F11 permanece en denegación por defecto; `NETWORK_CONNECTION_PROBES=0` describe exclusivamente el operador.

**Regla de seguridad:** P8 permanece NO-GO. No publicar ni fusionar la rama hasta terminar R111–R114 y su auditoría. Los servicios iniciados no se habilitan automáticamente al reinicio. La próxima fase F4D debe revisar configuración e implementar una admisión de red temporal y revocable, con pruebas negativas y procedencia.
