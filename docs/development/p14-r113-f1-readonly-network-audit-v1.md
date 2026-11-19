# R113-F1 — Inventario de red y procedencia física real, sin tráfico

**Propósito.** Vincular el estado físico posterior a R112-F10R con el punto de partida de R113 sin introducir observaciones de aplicación ficticias. Comprueba los recibos originales FTP y SMB, sus predecesores F12, las 29 sondas físicas F11/R34 y los XML actuales de las cuatro máquinas.

**Operación.** `--audit` realiza exclusivamente lecturas de libvirt, systemd, nftables, Linux ip y los archivos privados. Las consultas `virsh domifaddr --source agent` son lecturas de metadatos del agente invitado, no una conexión SSH/FTP/SMB ni una prueba de servicio. Los datos permanecen en `/home/cicada/ardrec-lab/r113-f1-network-readonly-v1/audit-*` con permisos restringidos y SHA-256. `--replay` verifica las pruebas históricas desde el registro; no ejecuta el inventario de host de nuevo.

**Limitaciones.** Las direcciones encontradas son candidatas informativas, no evidencias de accesibilidad. La ausencia del agente invitado, el error de `domifaddr` o la falta de IP producen `INCOMPLETE` y nunca se rellenan valores estimados. No hay DHCP ni direcciones host en las redes libvirt aisladas; cualquier direccionamiento estático del invitado debe cotejarse antes de autorizar rutas. Los bloqueos de `nwfilter` y nftables R34 siguen activos; ningún permiso de tráfico ha sido instalado.

**Siguiente decisión.** R113-F2 deberá definir exactamente origen, destino, MAC/IP de invitado, interfaz/bridge, puertos y protocolos, duración, cierre automático verificable y política deny-first. Para FTP/FTPS también se necesita determinar el rango pasivo; para SMB el recurso autorizado y permisos; para SSH la cuenta y operación permitidas. No introducir permisos hasta que exista evidencia física suficiente de identidad y un mecanismo de restauración probado.

**EN.** Read-only inspection of four running lab guests and isolated networks, with independently replayed post-reboot physical receipts. Guest IPs are untrusted candidate metadata; there is no network authorization, service probing, or operational P8 accreditation.
