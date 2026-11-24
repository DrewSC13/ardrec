# R194 - Piloto local multiprotocolo

Reutiliza las primitivas TCP locales de R192.

## FTP

Selecciona BusyBox ftpd cuando el applet existe.
En su ausencia considera vsftpd con Bubblewrap,
configuracion privada y transferencia deshabilitada.

No envia comandos FTP, credenciales ni solicitudes
de transferencia. Solo registra una respuesta 220.

## SMB

Ejecuta Samba smbd mediante una conexion propia,
con aislamiento adicional solicitado a Bubblewrap.

Envia exclusivamente un mensaje SMB2 NEGOTIATE,
con dialectos SMB 2.0.2 y SMB 2.1.

No solicita autenticacion, conexion a recursos
compartidos ni operaciones sobre archivos.

## Limites

Una sola conexion por protocolo, lectura acotada,
terminacion del proceso y eliminacion del workspace.

Los servidores pueden rechazar la ejecucion sin root.
Las dependencias ausentes y resultados incompletos
se registran sin sustituciones sinteticas.

La observacion acredita transporte local solamente.
No acredita vulnerabilidad, control de acceso,
condicion A6, Rf confirmado ni publicacion A9.

No sustituye el laboratorio historico.
No admite observaciones experimentales.

P7=DRAFT_NOT_FROZEN.
P8=NO-GO.


## Correccion R194-C

R194-B identifico el fallo de montaje de /work sobre una
raiz del host de solo lectura.

Se sustituye el montaje completo del host por una raiz
temporal con /usr de solo lectura, identidad local minima,
espacios temporales y un directorio privado de trabajo.

Se conserva el aislamiento de red y la eliminacion de
capacidades. No existe fallback privilegiado.

Si no se encuentra un servidor FTP instalado, se permite
una distribucion fuente de pyftpdlib 2.2.0, fijada por SHA-256.
Solo se extraen modulos Python del paquete previamente
verificado. No se ejecutan instaladores ni scripts de build.

La descarga se realiza fuera del ejecutor, por consentimiento
del operador. El servidor no registra cuentas, no admite
comandos de aplicacion y utiliza una conexion local propia.

Uso opcional:

    uv run --no-sync python -B -m ardrec.coordination.local_protocol_pilot --confirm AUTORIZO_PILOTO_FTP_SMB_LOCAL --ftp-source ARCHIVE --json

El inicio del wrapper Bubblewrap no prueba que el daemon
haya completado su arranque. Solo una respuesta valida
permite acreditar la observacion de transporte.

La procedencia criptografica del paquete no equivale a
una auditoria independiente de seguridad.

Se mantienen las restricciones experimentales y los
contratos operacionales historicos.
