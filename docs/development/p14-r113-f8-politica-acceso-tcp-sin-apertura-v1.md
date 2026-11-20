# ARDREC — R113-F8: política de admisión candidata, sin apertura

## Objetivo

Convertir las capturas físicas R113-F5 y la acreditación forense R113-F7E en una política fija y reproducible para tres pares de VM, conservando el contrato de recuperación root F6. R113-F8 prepara la política y realiza replay **sin ningún cambio en libvirt, nftables, systemd, QGA, VM o redes**. No autoriza conexiones ni prueba protocolos.

## Procedencia vinculada

- F5: `a29b0c0e91ca139f1e2969d81dec10677c64460f6c6aead397cc1a68d8bc43ba` (manifiesto), la validación F6 autentica además cada archivo físico.
- F7E: `e7bd6fd12d3188ec821d16751cda18d21f88d2da6043acb1db8a3dafe369729c` (manifiesto de cierre con replay satisfactorio); el replay F7 original sigue incompleto.
- F6: nombres y XML de las seis vinculaciones candidatas bajo el recuperador root ya instalado; este incremento no altera ese código.

## Matriz cerrada

| Pareja | Origen runner | Destino | TCP |
| --- | --- | --- | --- |
| SSH | `10.203.30.1` | `10.203.30.2` | `22` |
| FTP | `10.203.31.1` | `10.203.31.2` | `21` |
| SMB | `10.203.32.1` | `10.203.32.2` | `445` |

Las reglas candidatas de libvirt por interfaz permiten ARP estrictamente entre las dos direcciones del par, TCP hacia el puerto objetivo y respuestas con estado `ESTABLISHED`; todo lo demás termina en un `drop all`. R34 sólo prepara reglas `accept` en la cadena `forward` para esas parejas y termina preservando los cuatro `DROP` originales. Las cadenas `input` y `output` mantienen las denegaciones originales. No hay permisos de IPv6, ICMP, UDP, DNS, tráfico externo, puertos FTP de datos ni enumeración.

## Separación de fases

La preparación estática **no demuestra** que las reglas sean aceptadas por el backend iptables/libvirt ni por el kernel nftables de Prometheus, ni que el watchdog sobreviva a un fallo. Antes de desplegarlas será imprescindible un ensayo de aceptación de política en el host, un guardián root que verifique reloj/deadline y el temporizador independiente armado **antes de la primera apertura**, una autorización expresa y prueba física de revocación.

La siguiente fase deberá controlar las dos capas de denegación de manera coherente: definir filtros previamente, revalidar política DENY y seis bindings, armar restauración, comprobar el temporizador, modificar bindings sólo si coinciden con el XML original autenticado y finalmente aplicar la política nft de la tabla aislada. Cualquier fallo debe reconducir a DENY por F6 sin reintentos ciegos.

## Condiciones de cierre

Replayed policy bytes and source SHA-256 unchanged; signed commit; `P8=NO-GO`, no physical network observation and no push/merge until closing R111–R114.
