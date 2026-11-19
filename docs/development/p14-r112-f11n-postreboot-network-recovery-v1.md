# R112-F11N — Recuperación posreinicio de redes libvirt R33

## Motivo y fuente de verdad

El reinicio físico de Prometheus apagó las cuatro VM y dejó inactivas las tres redes R33. R112-F10 incorporó el código y creó el commit local firmado `351d1912edaecac7208601de5666a08a0aec709f`, pero su preflight FTP se detuvo porque SSH no estaba ejecutándose. No hubo arranques FTP/SMB de ese intento. Los recibos anteriores F8S/F9 **son históricos, no una autorización para reutilizar sesiones, tickets ni estados**. El laboratorio permanece `P8=NO-GO`.

## Diseño: fail closed, una transición explícita

- `--plan` realiza 29 consultas host existentes, verifica el estado SHUTOFF de las cuatro VM, tres redes INACTIVE, identidad de NIC, puente, UUID, nwfilter drop, R34 `nftables` (cuatro reglas exactas), F11 hook SHA y el temporizador. Comprueba además ausencia de root leases de sesión y procedencia F9. Guarda plan y snapshot privados en `/home/cicada/ardrec-lab/r112-f11n-postreboot-networks-v1`.
- `--activate PLAN --i-authorize-three-isolated-net-starts` exige autorización explícita, reconcilia un snapshot fresco con el plan, escribe `apply.once` antes de la primera operación y ejecuta **tres y únicamente tres** operaciones `sudo -n virsh -c qemu:///system net-start`: SSH, FTP, SMB. Tras cada operación captura nuevamente los 29 resultados originales, valida el estado incremental de las redes y verifica no haber cambiado ninguna VM, identidad, XML estático, hook, nwfilter ni estructura de R34.
- Cada `command`, `after` y `step` se conserva por separado; el resultado solo recibe `receipt.json` cuando pasan las tres guardas. `--replay` vuelve a comprobar coherencia, SHA basados en representación canónica y la marca de intento, sin acciones físicas.
- Un error posterior a cualquiera de los `net-start` deja la evidencia de la transición parcial. **Prohibido** reiniciar la misma aplicación, borrar archivos `apply.once`, crear leases, apagar VMs/redes automáticamente o relajar reglas. Se exige reconciliación independiente antes de una acción nueva.

## Límites y responsabilidad experimental

Esta etapa **no** emite leases F11 ni realiza `virsh start` de VM. No abre puertos, no ejecuta pentesting, no consulta protocolos, no convierte mocks en pruebas físicas y no acredita algoritmos A5, A6, A7, A9 ni hipótesis. R34 permanece en DENY y P8 permanece NO-GO. El siguiente incremento debe reautorizar específicamente un nuevo inicio SSH, luego runner, antes de reutilizar el ejecutor F10 para FTP y SMB.

## English audit summary

R112-F11N strictly reactivates the three R33 no-forward libvirt networks after a host reboot. It requires a fresh 29-probe preflight, pinned F11 and R34 state, explicit operator consent, at most one `net-start` for each network, durable attempts, per-transition snapshots, and deterministic receipt replay. No VM boot, traffic grant, stale lease reuse, or P8 admission is permitted.
