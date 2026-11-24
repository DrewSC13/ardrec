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
