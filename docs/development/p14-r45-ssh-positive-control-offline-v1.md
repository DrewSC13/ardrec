# ARDREC P14-R45 — Candidatos positivos SSH (solo offline; P8 NO-GO)

## Alcance y hechos de R44

* SHA base exacto: `1a8483910b030a49454a924bbddbd1668289d623`.
* `ardrec-r33-dev-ssh`: encendido, `a33d30t`, `52:54:00:ad:30:02`, `10.203.30.2/28`.
* `ardrec-r33-dev-runner`: apagado, tres NIC (SSH/FTP/SMB), con redes FTP/SMB inactivas. No arrancarlo sin decisión independiente sobre esas interfaces.
* `br33d30` sin IPv4. El filtro `ardrec-r33-block-until-containment` real tiene **DROP INOUT ALL**; `bridge ardrec_r34_guard` también sigue en deny-all.
* R42.2: observación TAP y bridge 0 tramas. R42.3: ruta directa ens3, ARP ABSENT, TX=0, RX=15. Esto no prueba contención.

## Qué genera R45

* Dos filtros **nuevos y distintos** para SSH y runner (no actualiza el filtro compartido existente). Permiten únicamente ARP de las identidades exactas y ICMP Echo Request/Reply entre `10.203.30.2` y `10.203.30.1`, con DROP terminal. No permiten TCP, UDP, IPv6, FTP, SMB o tráfico hacia Internet.
* Dos XML de dominio candidatos generados a partir del modelador R33: SSH conserva su NIC; runner propone **solo su NIC SSH**, conservando UUID, nombre y disco originales. Esto **no redefine ni arranca** el dominio actual. No aplicar el XML sin comparación estricta con `virsh dumpxml --inactive` y plan de restauración.
* Un nftables **solo para validar sintaxis** en una tabla deliberadamente distinta (`ardrec_r45_syntax_only`); **no lo instales**. No reemplaza `ardrec_r34_guard`; un `accept` en una tabla distinta no anula un `drop` en la tabla R34, y no produce conectividad positiva. El reemplazo coordinado de la tabla R34 requiere un incremento posterior y autorización separada.
* Un reporte JSON canónico con SHA256 y puertas de aceptación; archivos 0600 bajo un nuevo subdirectorio privado 0700. No hay auto-reintentos ni limpieza destructiva.

## Límites operacionales

- Esta fase **NO** ejecuta `sudo`, `virsh`, `nft`, `ip`, QGA, `tcpdump` o comandos de red. Tampoco inicia VM.
- No existe comando de aplicación de firewall en el paquete. Es deliberado: los filtros actuales son compartidos y una modificación del filtro instalado puede tener efectos inmediatos en VM en funcionamiento.
- No se crean permisos excepcionales, no se reinician servicios, no se altera estado del host, ni se acreditan A5/A6 de VM.
- `P8=NO-GO`; `isolation_proven=false`.

## Uso del desarrollo

1. Pruebas R45 y P14, trazabilidad.
2. `--plan`: imprime informe canónico sin efectos.
3. `--prepare-offline --receipt-dir <directorio nuevo> --i-authorize-private-local-files-only`: escribe candidatos privados sin aplicar ni validar sintaxis con herramientas del host.
4. `--verify-offline --receipt-dir <directorio>`: reconstituye contenido determinista y verifica SHA-256, permisos y conjunto completo de archivos.
5. Antes de aplicar cualquier cosa, solicitar nuevo trabajo separado: revisión independiente de reglas, validación `virt-xml-validate` y `nft -c`, igualdad contra libvirt vivo, confirmación de componentes existentes, diseño de rollback probado y autorización humana específica. Aún entonces la sustitución de filtros requiere ejecución controlada; no se permite ampliar redes FTP/SMB de modo implícito.

## Fuente conceptual externa

Documentación oficial libvirt Network Filters: `https://libvirt.org/formatnwfilter.html` y wiki nftables Bridge filtering: `https://wiki.nftables.org/wiki-nftables/index.php?title=Bridge_filtering`.


## R45-F1 — Corrección de validación Relax NG de nwfilter

La primera materialización offline R45 quedó verificada por SHA-256, pero **los dos XML
`nwfilter` fallaron** al ejecutarse `virt-xml-validate ... nwfilter` en
Prometheus. Ese resultado se conserva como evidencia de incompatibilidad.

Causa: el generador había añadido `dstmacaddr` al elemento `<icmp/>`.
El esquema `nwfilter.rng` de libvirt solo permite `srcmacaddr` para ese
protocolo. R45-F1 elimina **exclusivamente ese atributo de los dos
reglamentos ICMP**; conserva MAC de origen, IP origen/destino, tipo y código.
La condición Ethernet de MAC destino sigue declarada en el candidato nftables.
No usar esta corrección como autorización de despliegue ni como prueba de
contención; el candidato nftables continúa siendo **solo de sintaxis**.

Se refuerza la verificación estricta del resto de los atributos y se añade
una prueba con `virt-xml-validate` real cuando esté instalado. El generador
continúa sin ejecutarlo por sí mismo y no requiere herramientas del host para
producir los candidatos deterministas.

El recibo `r45-ssh-candidate-20261115T022340Z-5663` debe permanecer
**inmutable**. Los bytes corregidos no concuerdan con ese manifiesto;
crear un **nuevo** subdirectorio `r45-ssh-candidate-*`, verificar sus SHA-256
y ejecutar las cuatro validaciones XML y `nft -c` de nuevo. No modificar
`ardrec-r33-block-until-containment`, `ardrec_r34_guard`, la NIC del runner,
ni iniciar VM. `P8=NO-GO`.

Referencia del contrato: documentación oficial de libvirt Network Filters
y esquema `src/conf/schemas/nwfilter.rng`.
