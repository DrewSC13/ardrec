# P14-R33 — Topología libvirt **solo en archivos XML** / Offline topology

## Dependencias y objetivo

Base: `f97ee69f94946c3dc07f8945f567e0b3ecb869c8` (PR #98). Se consume el recibo físico R32 original `r32_staging.json`, anclado por SHA-256 del **archivo** `b032c35c5f9760b9b057b6bbc3e681fca82ff37532c897b37463a147b1cdaadf`, validando además el digest interno, los cuatro overlays nuevos, identidades, backing, estados y `NO-GO`. No se reutiliza el ejecutor histórico R8, no se modifican v4, v6 o R32, ni se crea otro QCOW2.

## Entregables reales, alcance y puertas

- Tres archivos XML de red libvirt aislada, sin `<forward>`, `<ip>`, DHCP o DNS, con `ipv6=no`; puentes reservados `br33d30`, `br33d31`, `br33d32`.
- Cuatro XML de dominio KVM con nombres y UUID *nuevos*, discos R32 exclusivos, vCPU/RAM del laboratorio, MAC originales (conservar configuración estática del invitado), controladora virtio, canal QEMU guest agent, serial PTY y VGA sin listener gráfico.
- En **todas las NIC** se exige `filterref='ardrec-r33-block-until-containment'`, cuya definición deliberadamente **no se instala** en R33. No debe poder iniciarse un dominio por accidente antes de definir y validar una política de contención separada. Esta referencia no sustituye pruebas físicas del cortafuegos.
- `--plan`: genera un manifiesto reproducible con los SHA-256 de los siete XML, sin operaciones externas. `--prepare-xml`: escritura explícita de siete XML **nuevos** y un recibo SHA-256 en directorio privado 0700 propiedad del operador; creación exclusiva 0600. No hay sobrescritura ni limpieza automática de intentos parciales.
- R33 **NO ejecuta `virsh define`, `net-define`, `net-start`, `create`, `start`, nftables, sudo ni comandos remotos**. No instala filtros ni marca los XML como desplegados. Los nuevos dominios y redes son propuestas ejecutables de configuración, pendientes de validación de host y aceptación.
- Si se genera XML parcial, conservarlo. No repetir en ese mismo directorio ni eliminar evidencia sin revisión. Los XML son deterministas vinculados al digest R32.

## Semántica de aceptación

`XML_PREPARED_ONLY` significa únicamente que los siete XML están escritos y ligados al recibo; no acredita que sean compatibles con el libvirt del anfitrión o que existan como dominios definidos. `PLAN_ONLY` no escribe archivos. En ambos modos: `libvirt_definitions_created=false`, `network_started=false`, `vm_started=false`, `host_firewall_modified=false`, `operational_dispatch=false`, `can_restore=false`, `p8_operational=NO-GO`, sin Rf ni A9 operacional.

## Próximo incremento R34

Validar con utilidades propias del host la sintaxis libvirt de los siete XML; configurar y verificar **antes del arranque** reglas específicas de contención en el bridge y un filtro por interfaz que no permita salida indebida, con pruebas negativas y positivas y preservación de nftables ajeno. Solo entonces, bajo autorización separada, registrar definiciones inactivas y preparar el arranque. R33 no constituye una autorización para acciones de red o pentesting. Los resultados de R33 son desarrollo, no observaciones de la muestra experimental.

## English

R33 deterministically emits three isolated-network XMLs and four KVM domain XMLs, bound to the authenticated R32 physical storage receipt. All guest NICs refer to a deliberately unresolved deny-until-containment nwfilter, so premature VM startup must fail closed. No libvirt objects are defined or started, and no network or host firewall changes occur. XMLs are immutable, hashed, and preserved privately with a canonical receipt. Operational authorization remains NO-GO.
