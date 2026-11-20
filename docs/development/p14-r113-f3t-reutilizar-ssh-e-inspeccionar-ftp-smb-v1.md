# R113-F3T — Reutilización de SSH e inspección pendiente FTP/SMB

**Objetivo:** recuperar la observación local del puerto SSH 22 desde la captura QGA inmutable de R113-F3R; consultar una sola vez cada una de FTP y SMB, sin autorizar tráfico inter-VM.

## Evidencia de partida

- La inspección F3 (`inspect-gccubwyi`) se conserva como incidente incompleto. No se reproduce ni se sobrescribe.
- La inspección F3R (`inspect-9nl15krt`) conserva `capture-ssh.json`, SHA-256 `64cec801d60ab9fbcb4e675153e7157994d09f35bbebff2bbe64578e26b657cd`. La salida decodificada tiene SHA-256 `6a8b61d6c5fe645829d978a00d13bbdfa8550b3634fad211df11ee152de646fc`.
- `ss -H -ltn4` ejecutado en la VM SSH devolvió `exitcode=0`, incluida la dirección de resolución local `127.0.0.53%lo:53` y el socket `0.0.0.0:22`.
- La corrección del analizador acepta un sufijo de interfaz en una dirección IPv4 concreta, normaliza la parte IPv4 y mantiene los rechazos de IPv6, comodines con interfaz y entradas malformadas.

## Autoridad y ejecución

El comando `--verify-ssh-source` valida las huellas históricas y clasifica la captura SSH sin ejecutar QGA ni crear archivos. El comando `--inspect` requiere autorización explícita y solo puede iniciar `/usr/bin/ss -H -ltn4` mediante QGA en `ardrec-r33-dev-ftp` y `ardrec-r33-dev-smb`, una vez por VM. La marca `started-<rol>.once` se persiste antes de cada `guest-exec`; si el resultado es incierto, no hay reintento ni limpieza automática. Las capturas se persisten antes de clasificarse.

El replay no contacta las VM: relee por SHA-256 las evidencias de ambos incidentes, la captura SSH original, las nuevas capturas FTP y SMB, los marcadores, la clasificación y el manifiesto. La clasificación de `LISTENING_ON_LAB_IPV4` acredita un socket local; **no** acredita conexión desde runner, identidad del servicio, seguridad ni vulnerabilidad. La ausencia de listener tampoco se presenta como conexión negativa real.

No se instalan paquetes ni se cambia direccionamiento IP, reglas R34, filtros nwfilter, hook F11 o estado de las VM. P8 permanece en `NO-GO`. No hay push ni merge hasta el cierre acumulado R111–R114.

## Continuidad

R113-F4 deberá justificar puertos, direcciones, políticas deny-first y revocación de permisos temporales con base en resultados reales de F3T. Cualquier apertura de tráfico requerirá autorización nueva y un mecanismo probado de rollback o caducidad.
