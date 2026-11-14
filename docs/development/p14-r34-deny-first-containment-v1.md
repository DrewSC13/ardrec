# P14-R34 — Políticas de contención *deny-first* en formato offline

R34 consume el recibo físico de topología R33, fijado por SHA-256 de archivo e interno, y compara los siete XML con los bytes esperados por su generador. R33 sigue siendo un artefacto offline y no tiene autorización para arrancar máquinas.

## Diseño

Se generan dos políticas nuevas, sin modificar los siete XML anteriores:

1. **`bridge-deny.nft`:** tabla `bridge ardrec_r34_guard`, con tres cadenas `input`, `output`, `forward` y reglas de descarte limitadas a `a33d30r/t`, `a33d31r/t` y `a33d32r/t`. No utiliza `flush ruleset`, no elimina tablas, no instala reglas y no abre puertos. Las reglas se referencian por nombre de interfaz y no conceden tráfico a terceros. El resto del firewall mantiene su comportamiento previo.
2. **`nwfilter-deny.xml`:** filtro `ardrec-r33-block-until-containment`, idéntico al nombre que ya figura en las seis NIC del XML R33. Una única regla `<all/>` con `drop` `inout` bloquea todos los protocolos. El UUID se deriva de la huella R33, sin emplear un identificador de otro laboratorio.

Los dos controles están deliberadamente configurados para **denegar todo**. No son todavía un allowlist SSH, FTPS o SMB, ni una afirmación de aislamiento físico aplicado. La aceptación de un archivo XML por el esquema de libvirt no certifica el comportamiento efectivo del filtrado en una VM.

## Ejecuciones y autoridad

- `--plan`: valida fuente y describe las dos políticas en JSON canónico. No invoca binarios externos.
- `--prepare-offline`: escribe exclusivamente los dos archivos y el recibo JSON en un directorio privado vacío; requiere autorización explícita para escritura local, sin `sudo`.
- `--host-preflight`: requiere autorización explícita para consultas **de solo lectura**, valida los archivos contra libvirt/nft con `virt-xml-validate` y `nft -c -f -`, y comprueba que la tabla, interfaces, puentes, nombres de dominios, redes y filtro no estén ocupados. No define, arranca, detiene ni elimina recursos. Puede requerir `sudo -n` para las consultas nftables.

Los informes siempre mantienen `operational_dispatch=false`, `p8_operational=NO-GO`, sin riesgo final ni generación publicada.

## Límites y siguiente etapa

R34 no instala las políticas ni define libvirt: la **instalación física e inactiva**, con recibos de operaciones paso a paso y bloqueo de colisiones, será R35 bajo aprobación separada. No ejecutar el procedimiento histórico R8. No reinterpretar R33/R34 como servicio real ni como aceptación experimental.

Para un ciclo posterior con tráfico permitido será imprescindible desarrollar una política restringida, comprobar que no existen rutas de salida/host/IP forwarding, realizar controles positivos y negativos de red y preservar el estado de los recursos ajenos. Antes de ese punto el filtro completo de denegación no debe eliminarse o reemplazarse.
