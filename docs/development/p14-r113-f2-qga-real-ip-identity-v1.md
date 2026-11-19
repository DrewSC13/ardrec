# R113-F2 — Identidad IP real mediante QEMU Guest Agent

**Rama:** `feat/p14-r111-r114-real-lab`.
**Commit padre:** `b559d85f45008ec6664eafeb2f99baca7add8cba`.

## Alcance

R113-F1 usaba `virsh --readonly -c qemu:///system domifaddr ... --source agent`.
El host confirmó el rechazo por el atributo de conexión de solo lectura: no por falta del agente. Se cambia exclusivamente la conexión para esa consulta a `virsh -c qemu:///system`; el comando `domifaddr` sigue siendo una consulta. Las otras capturas conservan `--readonly`.

Se acepta identidad, no servicio ni conectividad, únicamente al comprobar las seis parejas exactas de MAC/CIDR. El modelo compara interfaces anunciadas en el inventario libvirt y direcciones obtenidas del agente invitado, con cuatro máquinas `RUNNING`, tres redes `ACTIVE_DENY`, R34 y F11 preservados. Ausencia, cambios o direcciones privadas adicionales no se aceptan como identidad exacta.

| Red | Runner | Objetivo | Bridge |
|---|---|---|---|
| SSH | `10.203.30.1/28` | `10.203.30.2/28` | `br33d30` |
| FTP | `10.203.31.1/28` | `10.203.31.2/28` | `br33d31` |
| SMB | `10.203.32.1/28` | `10.203.32.2/28` | `br33d32` |

## Procedimiento

El aplicador valida huellas de entrada, modifica una única llamada en F1, ejecuta las regresiones R112, R113-F1 y R113-F2, revisa el diff, crea un commit firmado y produce una auditoría nueva F1 en el host actual. R113-F2 enlaza su prueba `identity.json` a la nueva captura F1 por SHA-256 y ejecuta replay determinista.

No arranca VM, ni instala paquetes, ni reconfigura redes, ni habilita tráfico, ni realiza sondeo TCP o aplicación. `P8=NO-GO` y A5/A6/A7/A9 siguen sin acreditarse. El siguiente incremento verificará listeners reales y propondrá una política de autorización limitada a los tres pares runner-objetivo con revocación explícita.
