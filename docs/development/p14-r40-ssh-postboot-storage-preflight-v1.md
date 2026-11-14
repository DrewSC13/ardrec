# ARDREC P14–R40 — Preflight físico de almacenamiento SSH posterior al primer arranque

## Base y objetivo

Base exacta: `main=69d085d0596da341f36767bca205751952dcea6e` (PR #110 fusionado, R39).

R39 registró con fuentes R36.5 y lectura independiente de libvirt el estado `SSH_NETWORK_ACTIVE_DOMAIN_OFF_RECONCILED_NO_GO`: red SSH activa, dominio SSH apagado, otras redes y dominios ARDREC inactivos. El apagado anterior fue registrado por libvirt/QEMU, pero su solicitud originaria permanece `NOT_ATTESTED`. R39 no demostró aislamiento físico del tráfico ni verificó las imágenes QCOW2 posteriores al arranque.

R40 es **exclusivamente de lectura del anfitrión y del almacenamiento**, con un recibo local nuevo. No realiza reanudación, activación, SSH, `qemu-agent-command`, escaneo, paquetes, accesos a huéspedes ni modificaciones de `nft`, nwfilter, libvirt o QCOW2. No implica autorización para reanudar: **P8 NO-GO**.

## Contrato técnico

1. Revalida el directorio de recibo R39 (`r39_reconciliation.json` + `SHA256SUMS`) con permisos privados, manifiesto exacto, SHA y semántica; revalida **independientemente** los dos recibos R36.5 y comprueba su vínculo con R39.
2. Verifica el archivo R32–R34 previamente fijado: el TAR debe coincidir con `r35.ARCHIVE_SHA256` y con los invariantes de extracción exacta y cadena de autoridad del validador R35. No acepta un archivo alternativo aunque tenga una estructura similar.
3. Relee el estado físico mediante `r39.capture_current` (= `r365.current(..., NETWORK_ONLY)`): nftables, nwfilter, XML, inventarios, MAC y presencia de exactamente el puente SSH. No permite una VM activa ni segmentos adicionales.
4. Reutiliza los validadores de almacenamiento R35 para los **12 archivos QCOW2 de las cuatro funciones**: bases y overlays padre se comparan con los hashes R32; los overlays runtime FTP/SMB/runner deben conservar sus hashes originales; el runtime SSH, **potencialmente modificado después del arranque**, se verifica por propiedad, permisos, enlace QCOW2, backing, tamaño virtual, estabilidad de metadatos y dos lecturas consecutivas SHA-256. Registra su hash actual en el recibo y **NO impone** el hash de runtime previo al arranque.
5. Relee el host después de examinar el almacenamiento. Si hay cambio, rechazo sin nuevo recibo. La comparación secuencial **no es snapshot atómico** y no demuestra ausencia de modificaciones por terceros fuera de la ventana observada.
6. Sólo si todos los controles pasan, crea una carpeta nueva `0700`, con `r40_preflight.json` y `SHA256SUMS` en `0600`, sin incluir bytes originales, contenidos de discos o logs sensibles.

## Salida y límite epistémico

El único estado de aprobación documental permitido es `POSTBOOT_STORAGE_CONTAINMENT_CONSISTENT_NO_GO`. Se conservan `permission_to_resume=false`, `resumption_performed=false`, `guest_isolation_tested=false`, `network_traffic_tested=false`, `guest_os_identity_verified=false`, `technical_truth_accredited=false`, `final_risk=null`, `P8=NO-GO` y `experimental_validation=NOT_RUN`. Un informe nuevo **no reautoriza** el primer arranque, ni es apto para elevar A6 de ND.

Para una reanudación real posterior se necesitará **un contrato independiente con permiso explícito** para un intento nuevo, comprobación de consistencia antes del único `virsh start` permitido, y después una etapa separada de verificación negativa de tráfico. Las pruebas de penetración quedan todavía excluidas.

## Operación sobre Prometheus

El repositorio oficial es `/home/cicada/Development/GitHub/ardrec`; los ZIP y recibos privados se almacenan exclusivamente en `/home/cicada/Development/GitHub/ardrec-patches`. Nunca subir recibos, credenciales ni imágenes a GitHub.

Identificar el archivo original R32–R34 `tar.gz` cuyo SHA-256 es exactamente:

`58e7cf2f59dd97cab948c190d637b6ff8ee8f67b45400769fe0d97a9e8f2ea36`

La aplicación no confía en el nombre del archivo. Requiere que exista y pase `r35.verify_source_bundle` antes de leer imágenes.

```bash
cd /home/cicada/Development/GitHub/ardrec
sudo -v
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
ARCHIVE=/RUTA/A/ARCHIVO_R32_R34_ORIGINAL.tar.gz
python3 -B scripts/ardrec_p14_r40_ssh_resume_preflight.py \
  --source-archive "$ARCHIVE" \
  --r365-preflight "$BASE/recibos-preflight-r365-20261114T200434Z-94940" \
  --r365-first-boot "$BASE/recibos-first-boot-r365-20261114T200824Z-98270" \
  --r39-reconciliation "$BASE/r39-ssh-reconciliation-20261114T215708Z-5663" \
  --receipt-dir "$BASE/r40-ssh-preflight-$(date -u +%Y%m%dT%H%M%SZ)-$$"
```

**El marcador `ARCHIVE=/RUTA/...` es deliberado**: no inferir un path de archivo físico que no se haya mostrado. Antes de usar el CLI debe localizarse en Prometheus el archivo con hash idéntico.

Tests: `PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r40*.py' -v`; suite `test_p14*.py`, trazabilidad, `git diff --check`, commit firmado, PR protegido y CI.
