# R115-F7 — Adaptador R115 de un arranque SSH bajo DENY (v1)

## Base, alcance y estado

**Base comprobada en Prometheus:** `6ce42a1143d50f7adf69ea3159b56c0e993c45cb`, rama `feat/p14-r115-a3-p7-a6-real`, commit local firmado y limpio; F1–F6: 1.018 pruebas aprobadas. Este incremento **no reescribe ni invoca** los ejecutores históricos R112-F12/R112-F10: el motor físico nuevo reutiliza los clasificadores *puros* R112-F8/F12, el ticket F11 existente y la atestación F5. No se cambiará de rama para evitar sus controles de procedencia.

**Instalación F7:** añade cuatro archivos exclusivamente, no inicia VM, no habilita redes, no ejecuta A5, no clasifica A6 ni publica A9. La captura por defecto es `--inspect --role ssh` y requiere `sudo -v` introducido interactivamente en la misma terminal para usar las lecturas privilegiadas de F5. El comprobador no crea autorizaciones ni modifica `/etc/ardrec`.

**Ejecución física** — implementada en la ruta `--boot` exclusivamente para **SSH** — queda *NO-GO* mientras falten autorizaciones independientes, autorización firmada del caso FTP-T01, material de confianza y revocación, commit firmado de F7, plan vigente, consentimiento específico en CLI y precondiciones en tiempo real. Runner y FTP tienen validación de etapas parciales, pero **no existe ruta de arranque F7 para ellos todavía**. SMB tampoco.

## Contratos y orden

1. `--inspect --role ssh|runner|ftp`: colecta datos reales solo de lectura, recalcula la semántica de estados, cuatro controles R34/F11 y las seis vinculaciones según el estado de cada VM. Si las cuatro están apagadas, únicamente SSH puede estar `DENY_STAGE_READY_NO_BOOT_AUTHORITY` (no es aprobación A3 ni autorización de arranque).
2. `--plan --role ssh --contract <privado> --authorization <privado>`: requiere código **commiteado y firmado** con árbol limpio, contrato/ autorización FTP-T01 firmada, raíz root de confianza independiente, revocación fresca, revisión de R112-F8 de 29 lecturas, F5 y ausencia de ticket o marcador previo. Genera un plan de 24 h, no un ticket, en carpeta `0700` con archivos `0600` y hashes. Si no hay autoridad, STOP sin plan.
3. **Firma externa del permiso de arranque SSH:** otro firmante root-administrado, diferente de la firma de alcance, emite una declaración Ed25519 específica del rol SSH, el HEAD, el hash canónico del plan, los hashes del contrato y autorización, y un intervalo máximo de 120 segundos. Un segundo firmante diferente emite revocación reciente (máximo 90 segundos). Las raíces root son **fijas** (`/etc/ardrec/r115-boot-trust-v1.json`, `/etc/ardrec/r115-boot-revocation-v1.json`). El proceso ARDREC **no crea ni firma** este material.
4. `--boot --role ssh --plan-dir <dir> --contract <privado> --authorization <privado> --permit <privado> --i-authorize-one-physical-ssh-boot-deny-only`: vuelve a verificar firma Git, árbol, instante, preflight F5, 29 observaciones R112-F8, DENY F11/R34, contrato y permiso, y ausencia de marcadores. **Antes** de cualquier operación privilegiada, persiste la intención y un marcador `boot.once` con creación exclusiva; después puede instalar exactamente un ticket root F11 y ejecutar **un solo** `virsh start` de SSH. No se realiza `net-start`, `--restore-deny`, A5 ni tráfico autorizado.
5. Postarranque: lectura F5 (SSH RUNNING con un solo vínculo activo DENY, restantes VM OFF), observación R112 y clasificación F8 del start, XML vivo y tres marcadores F11. Si cualquier dato falla, queda incidente durable de no-reintento y P8 `NO-GO`; no se ejecuta shutdown, cleanup ni segundo start.
6. `--replay --role ssh --plan-dir <dir> --boot-dir <dir>`: verifica la correspondencia del plan/recibo y rehace la clasificación histórica a partir de los archivos. La firma independiente debe conservar sus declaraciones y raíces históricas por separado: **el replay de este primer adaptador no equivale a una nueva acreditación de autorización**. No se publican riesgos finales.

### Esquemas de autoridad de arranque

`boot-trust` exige `schema=ARDREC-R115-F7-EXTERNAL-BOOT-TRUST-v1`, `boot_signer` y `revocation_signer`, cada uno con `key_id` y `public_key_pem` Ed25519 distintos. Las declaraciones usan la envoltura `{statement, signer_key_id, signature_b64}` existente de F3. El permiso lleva `schema=ARDREC-R115-F7-ONE-BOOT-PERMIT-v1`, `permit_id`, `role=ssh`, `guest`, `head`, `plan_sha256`, `contract_sha256`, `authorization_sha256`, `valid_from`, `valid_until`, `action=SINGLE_DENY_BOOT_ONLY`, `network_traffic_authorized=false`; firma sobre `b'ARDREC-R115-F7-BOOT-ONE-START-v1\x00' + canonical(statement)`. La revocación lleva `schema=ARDREC-R115-F7-BOOT-REVOCATION-v1`, `permit_sha256`, `permit_id`, `issued_at`, `valid_until`, `revoked`, `reason_code`; firma sobre `b'ARDREC-R115-F7-BOOT-REVOCATION-v1\x00' + canonical(statement)`. El JSON es canónico, Ed25519, y las comprobaciones fallan cerradas. No se distribuyen claves privadas.

**Autoridad distinta:** la autorización de alcance FTP-T01 F3/F6 y la autorización específica de arranque F7 son entidades separadas, ambas obligatorias. Ninguna sustituye aprobación institucional. Los documentos deben ser emitidos por la autoridad designada fuera de ARDREC; nunca autoconcedidos en un script de instalación.

## Limitaciones importantes y continuidad

- R115-F7 no habilita ejecución general del catálogo P7. `execution_enabled=false`, `pilot_completed=false` y `catalog_frozen=false` permanecen sin cambios.
- No debe usarse `--boot` inmediatamente después de la instalación: **primero un commit F7 firmado**, autoridad independiente y ventana activa. La entrega no ejecuta `--plan` ni `--boot`.
- En caso de start incierto, `boot.once` impide el segundo intento. No se borran tickets/ marcadores, no se intenta reparar automáticamente y se mantiene el incidente. Se necesita decisión humana documentada y nuevo alcance para cualquier recuperación.
- El paso siguiente será extender el transporte reutilizando R112-F9 y R112-F10 para **runner y FTP**, revalidar las NIC y `nwfilter-binding` después de cada arranque, e integrar la primera ventana P8 formal; después A5→A6→A7→A8→A9→A10 y TUI.
- Ninguna cifra de pruebas unitarias sustituye la ejecución real de las VM en Prometheus.
