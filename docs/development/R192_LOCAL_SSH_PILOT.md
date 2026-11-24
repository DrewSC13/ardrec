# R192 - Piloto local SSH monousuario

## Alcance

Observacion tecnica local de una identificacion SSH
emitida por el OpenSSH real instalado en el host.

No utiliza las VM historicas, B4/B9, red externa,
sudo, credenciales de usuario o comandos remotos.

Se crea una conexion TCP propia sobre 127.0.0.1 y
se cierra el socket de escucha antes de iniciar sshd
en modo inetd sobre la conexion ya establecida.

El cliente no envia datos del protocolo SSH.
No se intenta autenticacion.

La clave de host es efimera y se elimina junto con
el directorio privado de la sesion.

Se aplican limites de tiempo, volumen de lectura y
terminacion del grupo de procesos.

## Ejecucion

    uv run --no-sync python -B -m ardrec.coordination.local_ssh_pilot --confirm AUTORIZO_PILOTO_SSH_LOCAL --json

Requiere consentimiento del operador y OpenSSH Server
instalado. No instala dependencias automaticamente.

## Frontera de evidencia

El banner acredita una identificacion local observada.
No demuestra una vulnerabilidad, acceso indebido,
efectividad general de los controles ni un caso A5
historico completado.

No modifica los contratos historicos.

No se admite evidencia A6, no se confirma Rf y no
se publica una generacion A9 operacional.

El piloto no integra las 54 unidades experimentales.

P7=DRAFT_NOT_FROZEN.
P8=NO-GO.
