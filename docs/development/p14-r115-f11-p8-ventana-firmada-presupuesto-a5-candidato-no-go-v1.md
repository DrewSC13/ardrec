# ARDREC R115-F11 — Ventana P8 firmada, presupuesto finito y candidato FTP-T01

## Propósito y alcance

R115-F11 integra el lector acotado R115-F10 con una **revisión documental P8 firmada y revocable**, y valida un candidato FTP-T01 por sus bytes, origen declarado y límites. Esta entrega **no es un despachador de tráfico**, no abre conexiones, no inicia VM, no modifica nftables y no clasifica evidencia A6. El procedimiento de instalación ejecuta pruebas y genera un expediente privado de **NO-GO**. No se debe confundir una firma válida con la aplicación efectiva de una ventana en el anfitrión.

## Base auditada

- Rama `feat/p14-r115-a3-p7-a6-real`, HEAD anterior: `e0bb0bb3dabfb14ff64292bb3b2aa9a76fa3ad2b`.
- F1–F9: 30 archivos firmados. F10: 4 archivos nuevos en el árbol sin seguimiento, verificables contra el ZIP original.
- El catálogo `lab/operational-catalog-v1/catalog.json` sigue en `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`, `execution_enabled=false`, `pilot_completed=false`, `catalog_frozen=false`. Ninguna firma P8 cambia ese estado.
- FTP-T01: control TCP IPv4 `10.203.31.2:21`, sin comandos de autenticación, transferencia de datos ni mutación; ver un código 220 no demuestra autenticación ni acceso a archivos.

## Contrato criptográfico P8

Se requieren archivos **provisionados por autoridad externa**, nunca creados por ARDREC:

- `/etc/ardrec/r115-p8-trust-v1.json`: esquema `ARDREC-R115-F11-P8-EXTERNAL-TRUST-v1`, `window_signer` y `revocation_signer` Ed25519 con claves públicas distintas. Propietario root y permisos no escribibles por grupo/otros.
- `/etc/ardrec/r115-p8-revocation-v1.json`: declaración separada Ed25519, vinculada por SHA-256 al permiso concreto. Antigüedad máxima de revocación: 90 segundos.
- Permiso externo `ARDREC-R115-F11-FTP-T01-TRAFFIC-WINDOW-v1`, firmado sobre `ARDREC-R115-F11-TRAFFIC-WINDOW-v1\0 + JSON canónico`, con caso, familia, fase, HEAD, catálogo, hashes exactos de contrato y autorización de alcance, destino, periodo y presupuesto.
- También deben estar acreditados la confianza independiente y revocación de alcance de F6; una firma P8 aislada **no basta**.

La ventana documental dura como máximo 120 segundos. Los máximos técnicos: 1 conexión, 1 intento ordinario, 0 reintentos, 10 segundos, 4.096 bytes recibidos, 16 lecturas de hasta 512 bytes, 16 líneas, 8.192 bytes de salida y 512 MiB de memoria. Cada valor debe ser un entero real (no `bool`), con límites congruentes y no superior al contrato A3.

## Puente F10 → candidato A5

`validate_transport_candidate()` toma un resultado F10 y comprueba destinatario, límites, Base64 canónico, longitud, SHA-256, interpretación de la respuesta FTP, ausencia de envíos y que no se atribuya aprobación P8 o A6. Emite un **candidato no admitido**: `a5=PENDING_INDEPENDENT_PHYSICAL_ATTESTATION`, `a6=ND`, `p8=NO-GO`. Los bytes recibidos no bastan para acreditar cuándo, cómo, desde qué VM o bajo qué reglas de red se originó la observación.

## Bloqueos permanentes de esta entrega

1. Catálogo P7 en borrador no ejecutable.
2. Autoridad externa de alcance y arranque ausente en el último recibo F9.
3. Cinco guardas A3 sin acreditación actual completa; VM apagadas en la última captura.
4. Sin ejecución root de apertura/cierre limitado de P8, ni prueba efectiva previa/posterior de F11/R34.
5. Sin procedencia física A5 que habilite clasificación A6.

No hay ruta en este módulo que devuelva `p8=GO`; esto es intencional. La **siguiente fase física** deberá implementar el controlador root de ventana restringida, preflight atómico con condiciones actuales, marcador de intento único, revocación en cada lectura, restauración DENY verificable y recibo comprobable antes de cualquier admisión A6. Los permisos externos no deben generarse por el propio ejecutor.

## Ejecución y pruebas

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 scripts/ardrec_p14_r115_f11_p8_signed_window.py --review`

Para suministrar documentos ya emitidos por la autoridad independiente: `--contract`, `--authorization`, `--signed-window` juntos, sin introducir contraseñas ni claves privadas. Los documentos se leen de forma privada, no se modifican.

Los recibos se guardan bajo `/home/cicada/ardrec-lab/r115-f11-p8-review-v1/` con `report.json` y `manifest.json` que fija su SHA-256. El CLI no necesita `sudo`. Los ensayos locales deben ejecutarse sin privilegios y comprobar las suites R112–R115 y el árbol Git limpio firmado.

## Trazabilidad y límites

No se abre socket de salida, no se arranca VM, no se cambia la política nftables, no se hace push ni merge. No se da por admitida evidencia ni confirmado riesgo, estado o generación. Este incremento prepara una revisión independiente, reproducible y revocable, no la ejecución física.
