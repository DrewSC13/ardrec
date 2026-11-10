# ARDREC — P8-R25: medición real de las fuentes de configuración SSH

**Base de código:** `acf2f68b7687095a50691b93d3c538456b8b9cef`, PR #57 integrado, CI posterior #42739549842 aprobada. Material de entrada: imagen R9 con SHA-256 `fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103` en modo solo lectura, y recibo privado R24 SHA-256 `68747c677b41dea3f5c5329075ddc1a97b1bf8f47d34bc7c07a54be67a5194aa`.

R25 abandona la repetición de matrices de negación para **obtener evidencia material nueva**. El colector local del operador medirá los bytes exactos de `/etc/ssh/ssh_config` y de los fragmentos `*.conf` directos de `/etc/ssh/ssh_config.d` dentro de la QCOW2 original congelada. Se obtendrán hashes verificables y el conjunto acotado de entradas documentales; las directivas `Include`, `Host` y `Match` se cuentan solo léxicamente. No se ejecutan binarios del invitado ni se consulta el servidor SSH. El recibo original permanece privado, con permisos 0600/0700, y solo podrá publicarse su SHA y contadores agregados.

**Criterio de aceptación de este incremento:** fuente de configuración SSH materialmente observada, SHA de imagen pre/post idéntico, integridad del recibo antecedente R24, permisos privados, cobertura acotada y pruebas sintéticas adversariales. Si la QCOW2, la estructura de archivos o los permisos no coinciden, la colección se bloquea sin crear un recibo de éxito. El verificador de CI no accede a datos privados ni genera observaciones reales ficticias.

**Límite epistemológico:** la huella del archivo no demuestra su aplicación durante una sesión futura. La lista directa de fragmentos no resuelve inclusiones anidadas, patrones ajenos, `Host`/`Match`, configuración por usuario, políticas de entorno, precedencia efectiva, opciones CLI ni valores secretos. Ninguno de los 8 perfiles SSH queda materialmente vinculado o autorizado, y los 21 FTP/SMB no se alteran. Las obligaciones P8 permanecen 348 campos y 261 barreras probatorias abiertas; cinco variantes de escritura siguen pendientes de limpieza independiente.

La tesis (§§ 3.7.5 y 3.9.2) exige alcance, autenticidad de materiales, parámetros congelados, autorización vigente, presupuestos finitos, trazabilidad y limpieza independiente. Su verificación operacional corresponde a etapas controladas posteriores, no a una lectura offline.

**No ejecutar** `ssh`, `sftp`, `curl`, `smbclient`, `rpcclient` ni `ld.so` del invitado; no acceder a VM activa, no P9, no A1–A10, no autorización real ni despacho. P8/AL-06/AL-07 siguen abiertos.

**EN:** This increment adds measured SSH configuration source bytes in a pinned offline image, not proof of effective configuration or permission to run a client.

## R25-FIX1 — excepción exacta sin elevación de privilegios

El primer intento material fue bloqueado al encontrar un enlace simbólico en el fragmento `20-systemd-ssh-proxy.conf`. La comprobación posterior del operador, sin leer contenido, confirmó destino literal `/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf` y restauración de ACL temporal. FIX1 documenta y admite **solamente esa correspondencia exacta** al inspeccionar la imagen de hash fijo: el destino y todos sus ancestros deben carecer de enlaces y el destino debe ser un archivo regular. La lectura utiliza directamente la ruta absoluta del destino; el recibo registra el alias observado y los hashes de los bytes, nunca el contenido. Cualquier discrepancia bloquea. No se afirma resolución efectiva de `Include`, configuración, capacidad ni autorización. No se reescriben los datos históricos de R24 o la tesis.

## Resultado material R25 autenticado

El operador autenticó la imagen QCOW2 congelada y el recibo privado R24. La captura R25 midió **2 archivos** de configuración del cliente SSH (**2.426 bytes**): un archivo principal y un fragmento `.conf`. Un único enlace simbólico de destino literal verificado fue resuelto sin ejecutar binarios invitados. Se observó **una directiva `Include`** sin resolver. Los contenidos, hashes individuales y recibos privados permanecen fuera de Git.

SHA-256 del recibo privado R25: `eee28ad26a1d775b2d1f6215410ce072d64b1ea3a209567f8493848f4483fe5c`. SHA-256 de la imagen congelada: `fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103`. SHA-256 del recibo antecedente R24: `68747c677b41dea3f5c5329075ddc1a97b1bf8f47d34bc7c07a54be67a5194aa`.

**No hay configuración efectiva acreditada, ni cambio de las 261 barreras, 348 campos materiales, 29 perfiles bloqueados o cinco limpiezas pendientes.** Cero perfiles/casos autorizados y cero despachos. P8, AL-06 y AL-07 siguen abiertos; P9 y A1–A10 no iniciados.
