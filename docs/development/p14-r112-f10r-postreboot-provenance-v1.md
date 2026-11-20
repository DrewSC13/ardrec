# R112-F10R — Cadena de procedencia posterior al reinicio

**Objetivo:** continuar FTP y SMB usando el motor R112-F10 ya implementado, sin reutilizar el recibo operativo del runner R112-F9 (anterior al reinicio).

Se modifica solo el controlador de planificación/replay F10. El motor puro F10, los clasificadores F8/F9/F12, libvirt, el hook F11, los filtros y R34 quedan sin modificar.

El plan FTP exige los dos recibos originales F12, autenticados por SHA-256 y repetidos mediante el clasificador F12. La cadena trazable es F11N (redes) → F12 SSH → F12 runner → F10R FTP → F10R SMB. El plan SMB exige además el replay del recibo FTP; `PosixPath` se admite mediante `isinstance` sin flexibilizar rutas ni el formato del recibo.

La referencia `parent_commit` del modelo F10 sigue identificando la base histórica del módulo. La autoridad operativa posterior al reinicio se incorpora en `plan.previous` (`F12_RUNNER`), que se valida al planificar, arrancar y repetir cada recibo. No se reescriben recibos previos.

Los arranques FTP y SMB se autorizan individualmente, cada uno una única vez, conservando `R34=DENY`, `traffic_authorized=false`, `P8=NO-GO`. Un fallo no provoca reinicio, limpieza de leases, reversión ni segundo intento. No se ha probado ningún protocolo SSH/FTP/SMB.

**EN:** Rebind F10 operational predecessor from stale pre-reboot F9 runner to independently replayed post-reboot F12 SSH and runner receipts. Keep original F10 classifier and host safeguards unchanged. SMB requires the actual FTP receipt; no automatic starts or traffic authorization.
