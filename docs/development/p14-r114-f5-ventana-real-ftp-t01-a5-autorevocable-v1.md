# R114-F5 — FTP-T01: primera tentativa física A5 específica, con cierre F6

## Alcance y autoridad

Una sola tentativa nueva y separadamente autorizada desde `ardrec-r33-dev-runner` (`10.203.31.1`, MAC `52:54:00:ad:31:01`) hacia `ardrec-r33-dev-ftp` (`10.203.31.2:21`, MAC `52:54:00:ad:31:02`), ligada a `FTP-T01-S01-01`, intento `ATT_R114_F5_FTP_T01_01`. Se recibe como máximo un saludo de 256 bytes del canal de control. No se envían credenciales, no se autentica ni se transfiere o enumera información.

El saludo FTP `220` recibido en F10R permanece evidencia *anterior* sin vínculo A5 retroactivo. El archivo `/etc/vsftpd.conf` leído en F4 es una **fuente local auténtica**, no prueba de parámetros efectivos; su recibo SHA-256 `a3261fcefb15ef67c5436d74eadc546f3874cef9185d9f89ca22cf6976a31e62` se exige como antecesor autenticado. El resultado F5, si se acredita, confirma únicamente la tentativa física de conexión de control y su respuesta. No confirma vulnerabilidad, A6, riesgo final ni ninguna transición o publicación.

## Red y revocación

En lugar de admitir los tres pares de F10R, F5 reutiliza **solo dos** filtros existentes (runner-ftp y ftp). R34 conserva cuatro `DROP` del mismo candidato de F8R, y admite **cuatro reglas FTP**: ARP y TCP de ida y vuelta en taps `a33d31r`/`a33d31t`. Todo SSH/SMB permanece sin permiso `ACCEPT`. R34 se abre únicamente después de armar y comprobar un temporizador root independiente de 120 s y de completar los dos bindings. Tras la tentativa, **siempre** se intenta `F6 --restore-deny` seguido de `F6 --attest-deny`, además del temporizador autónomo de respaldo.

El ejecutor guarda un marcador único **antes** de armar el temporizador; ninguna falla autoriza repetir la ventana. Si el cierre DENY no queda acreditado, el resultado es crítico y requiere intervención forense, con el timer como defensa adicional. No debe interpretarse `DENY` ni `A5` como acreditados solo por la salida del instalador.

## Persistencia y replay

El bundle root se prepara exclusivamente después de commit firmado y autorización independiente, en `/var/lib/ardrec/r114-f5-ftp-t01-root-v1`, con directorio `0700`, ficheros `0600`, manifiesto y SHA-256, sin sobrescribir F10R ni F6. La fase de staging **no hace cambios a libvirt, nftables ni systemd**. El controlador registra las salidas crudas de todas las órdenes relevantes, incluyendo QGA, nft y restauración, como archivos privados de solo creación. La comprobación y replay del recibo se ejecutan contra esas capturas, sin conexiones, invitados ni mutaciones de host.

## Límites epistemológicos

La identidad formal `FTP-T01-S01-01` se mantiene trazable al intento original F4. El resultado positivo solo acredita, bajo las guardas vigentes, que una tentativa física nueva de control FTP/21 produjo respuesta `220`. La familia FTP-T01 del catálogo exige también atestación del destino e integridad/procedencia; F5 conserva los soportes para valoración posterior pero no los introduce automáticamente en A6. El catálogo P7 sigue con estado `DRAFT_UNCALIBRATED_NOT_EXECUTABLE`, las condiciones A6 permanecen `ND`, `Rf` no está confirmado y `P8=NO-GO`.

## Pruebas, control y no reintento

La instalación exige regresión **819** (783 anteriores + 36 nuevas) y commit firmado sobre `636a6658b908fa1bdde1c095314382f9b9403000`. Tres decisiones independientes: instalar código, preparar bundle root, autorizar la ventana FTP. Las pruebas de fuente no constituyen una ejecución física; la inspección `nft --check` de la nueva política FTP debe realizarse en el host antes de abrir, según requisito de calidad, y cualquier fallo bloquea la ventana sin reintento. No push, no merge antes de R114 y P8 NO-GO.
