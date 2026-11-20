# R115-F3 — Seis vinculaciones F11, controles R34 y revisión criptográfica de autoridad

**Base:** `a652195a544a549dbad6a44120e3d447cf4d4994`. **Rama:** `feat/p14-r115-a3-p7-a6-real`. Incremento sucesor de F1 y F2, sin modificar archivos históricos ni producir admisión operacional.

## Objetivo real de esta entrega

Comprobar en Prometheus, **en solo lectura**, las cuatro definiciones de dominios (SSH/FTP/SMB/runner), las seis interfaces virtuales previstas, las tres definiciones de redes sin reenvío, los tres estados de red, el `nwfilter` de denegación, la huella de código del hook F11, el servicio de denegación en arranque, la política nftables R34 (desde la lectura F2) y el watchdog. Incorporar además una ruta de **revisión documental criptográfica** para una autorización FTP-T01 y una declaración independiente de revocación. Ninguna de estas comprobaciones convierte el catálogo P7 ni P8 en ejecutable.

Este incremento **no** acredita TAPs efectivamente conectados mientras las VM están apagadas, que el hook o watchdog hayan producido su efecto tras un reinicio, la capacidad de un cliente concreto ni la disponibilidad del servicio FTP. `MATCH` es coincidencia de la fuente leída contra el contrato; no un lease vivo. La diferencia `DRIFT` en un control esencial provoca `LAB_ISOLATION_CONFIRMED=FALSO`; la lectura incompleta provoca `ND`. Las VM apagadas siguen ocasionando `SERVICE_READY=FALSO`.

## Fuentes e interfaces

Se reutiliza F2 para leer FTP/runner, definición y estado de red FTP, R34 nftables y timer. F3 agrega nueve comandos inmutables (`shell=False`, sin `sudo`, sin QGA ni sockets):

- `virsh --readonly` para XML SSH/SMB, red SSH/SMB y estado de ambas redes;
- `virsh --readonly nwfilter-dumpxml ardrec-r33-block-until-containment`;
- `sha256sum /etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny`;
- `systemctl show ardrec-r34-boot-deny.service` (LoadState/ActiveState).

La comprobación de NIC se hace con `r112_runner_nic_definition.validate_domain`, la de redes con `_safe_net`, y la de identidad/estado con `r112_f4_isolated_networks.parse_net_info`. Se exige además la coincidencia de los controles F2 ya recopilados. No se inspeccionan ni modifican redes no pertenecientes a ARDREC.

**Importante sobre nftables:** la lectura R115-F2 en Prometheus fue `R115_F2_CHECK_R34_NFT=ND`. F3 no interpreta ese valor como aprobación. Si vuelve a ocurrir, registrar el motivo de permiso en el recibo privado y conservar NO-GO. No introducir privilegios permanentes ni modificar sudoers automáticamente para conseguir MATCH. La siguiente fase necesitará una atestación privilegiada *acotada, supervisada y verificable* para la política efectiva y las seis vinculaciones activas.

## Declaraciones de autoridad y revocación

El módulo acepta, **solo si se proporcionan los cuatro archivos privados juntos**, `--contract`, `--authorization`, `--revocation` y `--trust`. No genera llaves ni se autoriza a sí mismo. `--contract` satisface el esquema F1 original y vincula el hash del documento de autorización firmado. La autorización es específica de `case_id`, familia FTP-T01, ventana UTC, VM/IP/MAC/puerto/red, catálogo, cliente, perfil y presupuesto finito. Un firmante separado revisa el estado de revocación; ambas declaraciones tienen firmas Ed25519 comprobadas mediante el verificador OpenSSL ya existente en `r58f_signed_witness.py` con prefijos de dominio separados. Se rechazan claves reutilizadas, divergencias de alcance, alteraciones de bytes, firmas inválidas y declaraciones fuera de contrato. La revisión de revocación tiene vigencia y caducidad explícitas.

**Límite de autoridad:** que una persona proporcione un archivo de confianza y firmas no demuestra que tenga legitimación institucional ni que el anclaje esté aprobado en el anfitrión. F3 NO establece ese anclaje. Por tanto, una declaración criptográficamente válida pero no revocada sigue `SCOPE_APPROVED=ND`; una revocación firmada válida provoca `FALSO`. Los ejemplos con llaves efímeras de la suite son **fixtures**, no autorizaciones reales y no deben reutilizarse. No completar los cuatro archivos usando identidades inventadas.

La ruta normal `--capture` sin documentos es el uso previsto ahora; registra un nuevo recibo privado y conserva `NO-GO`.

## Evidencia, salidas y no-alcance

Ruta de recibos: `/home/cicada/ardrec-lab/r115-f3-f11-authority-v1/capture-*`, directorios `0700` y archivos `0600` (`capture.json`, `report.json`, `manifest.json`), creados de manera exclusiva. El manifiesto incluye las huellas SHA-256 de los documentos originales. El resumen imprime estados sin exponer configuraciones privadas; los errores completos de lectura se conservan en el documento de captura. Los recibos F2 se mantienen intactos.

La prueba incluye firma válida, firma alterada, doble uso de clave, revocación válida, revocación vencida, dominio desviado, DNS en red, filtro permisivo, hook alterado, timer/servicio de denegación, errores de lectura, DTD y falta de permiso nft. Los tests son **offline con fuentes simuladas**, nunca pruebas físicas ni evidencia de vulnerabilidad.

No se modifica P7 histórico (`execution_enabled=false`), P8 `NO-GO`, A5 sin despacho, A6 `ND`, A7 sin riesgo confirmado y A9 sin generación nueva. No se hace `git commit` ni merge hasta consolidar el alcance y verificar las pruebas en el anfitrión.

## Comprobación posterior sin mutación

Desde el repositorio, para una nueva adquisición de solo lectura (si el estado cambia o debe repetirse la verificación):

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 -m ardrec.coordination.r115_f3_f11_authority --capture`

**Próximo trabajo:** registrar con autorización explícita del operador y control administrativo la fuente anclada de la clave de autoridad y revocación; acreditar seguridad efectiva de nftables y las seis vinculaciones/aislamiento del anfitrión, y finalmente cliente/perfil/preparación FTP. Después enlazar la decisión de A3 al flujo ordinario A5→A6→A7→A8→A9→A10 y TUI. Ninguna de las fuentes antiguas autoriza una nueva ejecución retroactivamente.
