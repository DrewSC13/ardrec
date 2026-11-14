# ARDREC P14–R35.3 — Recuperación segura de XML normalizado y estado parcial

## Evidencia de origen

- Base exacta: `c7bb54ab7d596c515b214008f4eef01be454683a` (PR #103).
- Primer recibo del host: `r35-private-Z9vpswND/recibos-instalacion-20261114T144532Z-41790`, error `installed_nft_table_semantics_mismatch`, digest interno `8a082fc006c9a588c3d2063972221c953f4b264a4c6a277f14e750660e3123f1`.
- Segundo recibo: `r35-private-Z9vpswND/recibos-recuperacion-r352-20261114T152149Z-51703`, error `defined_network_xml_mismatch_ssh`, digest interno `d582027739b71ccf7e8e280bb33217b1d4eb9eaf0596454a84e6489c831240e0`.
- Diagnóstico autenticado `diagnostico-r353-hDRUjenj`: tabla nft JSON `VERIFIED`, filtro deny-all `DEFINED`, red SSH inactiva y sin autoinicio; XML `net-dumpxml --inactive` idéntico al registrado durante el fallo. No existe red FTP/SMB ni dominio ARDREC.
- SHA-256 fuente R32–R34: `58e7cf2f59dd97cab948c190d637b6ff8ee8f67b45400769fe0d97a9e8f2ea36`.

## Corrección

1. El XML del bridge libvirt puede omitir `ipv6="no"` y añadir un único elemento `<mac address="..."/>`. Solo se admiten raíz de red, nombre, UUID, bridge, DNS y los valores ya autenticados, sin IP/forward/DHCP/rutas/elements extra. La MAC debe ser local, unicast, única entre bridges ARDREC y diferente de las MAC guest previstas.
2. Para SSH existente, la MAC queda adicionalmente anclada a `52:54:00:59:04:5a` (leída, autenticada y revalidada). No se aceptan MAC cambiadas en esta ruta de recuperación.
3. Verificar los dos recibos exactos con sus SHA256SUMS, digest interno, cadena fuente, secuencia y alcance único de mutaciones históricas. Rechazar segundos `nft -f -` y definiciones adicionales.
4. Preflight *read-only* dedicado verifica el estado actual de nftables, nwfilter y SSH; ausencia de FTP/SMB y cuatro dominios, ausencia de TAP/bridge reservados, doce QCOW2 y ocho XML.
5. La recuperación autorizada omite totalmente `nft -f -`, `nwfilter-define` y `net-define network-ssh.xml`; solo puede definir las redes FTP/SMB y los cuatro dominios apagados. Se reconfirma nftables y se verifican MAC, recursos y estado final.
6. Todos los pasos generan recibos nuevos e inmutables con SHA-256. Los recibos antiguos se conservan; un error tras escribir no inicia rollback ni segundo intento.

## Interfaz CLI

Preflight, **sin autorización de instalación**:

```text
--source-archive /RUTA/source-r32-r33-r34.tar.gz
--receipt-dir /RUTA/NUEVO-PREFLIGHT
--prior-partial-receipts /RUTA/recibos-instalacion-20261114T144532Z-41790
--second-partial-receipts /RUTA/recibos-recuperacion-r352-20261114T152149Z-51703
--preflight-existing-nft-filter-ssh
```

La instalación **no forma parte de este parche**, requiere PR + CI y preflight real satisfactorios, además de autorización explícita. Su opción distinta es `--resume-existing-nft-filter-ssh --i-authorize-r35-installation` con los mismos dos recibos.

## Invariantes

- `P8=NO-GO`, sin VM/redes iniciadas, sin despacho operacional, sin pentesting.
- `nft`: solo lectura estructural JSON sobre tabla preexistente, jamás recreación, flush o persistencia.
- `libvirt`: ningún `net-start`, `start`, `destroy`, `undefine` o `autostart`.
- `QCOW2`: solo estat, hashes y `qemu-img info`; nunca modificación.
- No sustituir recibo parcial con afirmaciones ni aceptar colisiones preexistentes fuera del único conjunto autorizado.
- Regresión Python P14, tests específicos, Python empaquetado, Rust CI y firma de commit exigidos antes del preflight real.

## Riesgos remanentes

Libvirt podría normalizar campos de dominios de forma distinta a la esperada. El ejecutor seguirá fail-closed ante ese supuesto; no se relajará la comparación ni se declarará éxito a partir de un estado parcial. La validación de redes y servicios invitados, algoritmos, aislamiento en ejecución, seguridad de reinicios, AL-06 y AL-07 siguen pendientes.
