# R117-F5B — Instalación root transaccional autenticada

## Alcance

El instalador F5B parte de la construcción determinista de F5A:
33 fuentes históricas fijadas, 3 fuentes del despacho F4,
catálogo, lock y manifiesto. Son 39 archivos en total.

F5B incorpora inspección de fuentes, comprobación del ZIP exacto,
validación de autoridad externa, instalación root y lectura de
integridad de la instalación.

## Autoridad independiente

La aprobación debe ser emitida fuera del repositorio por una
autoridad Ed25519 independiente, con clave pública de confianza
provisionada separadamente en:

- /etc/ardrec/r117-f5b-release-trust-v1.pem
- /etc/ardrec/r117-f5b-release-approval-v1.json
- /etc/ardrec/r117-f5b-release-approval-v1.sig

Los tres archivos son root:root, modo 0600 y sin enlaces
simbólicos. El documento JSON debe ser canónico y contener
exactamente schema, head, candidate_sha256, valid_from,
valid_until, purpose, authority y p8.

La firma Ed25519 cubre los bytes:
"ARDREC-R117-F5B-ROOT-RELEASE-APPROVAL-v1" + NUL +
JSON canónico UTF-8 terminado en salto de línea.

No se incluye ninguna clave privada, firma, autorización
ficticia ni aprovisionamiento automático de autoridad.

## Instalación

El agente debe instalarse por un procedimiento privilegiado
independiente y previamente autorizado en:

/var/lib/ardrec/r117-f5b-root-agent-v1/installer.py
/var/lib/ardrec/r117-f5b-root-agent-v1/candidate.py

Ambos archivos deben ser root:root 0600. El directorio debe
ser root:root 0700. La ejecución con --apply rechaza fuentes
no coincidentes con el commit Git firmado y cualquier ausencia
de autoridad externa.

La publicación transaccional conserva evidencias y rechaza
estados parciales. No se permite relanzar automáticamente
una instalación interrumpida ni borrar evidencias.

## Seguridad

La instalación no arranca VM, no abre puertos, no modifica
nftables y no crea permisos de ejecución. El recibo F4 declara
authorized_to_boot=false. El arranque requiere separadamente
la autoridad Ed25519 de F4, revocación reciente y estados
físicos DENY.

El modo --offline es el único que se ejecuta en CI.
No ejecutar --apply durante pruebas ni al instalar código.
F5B no concede A6 ni P8.

P7=DRAFT, A6=ND y P8=NO-GO.

## F5B-H1 — Bloqueo de aplicación privilegiada

La auditoría del PR #193 detectó que el recibo de release puede publicarse antes del cierre transaccional y que el verificador F4 no confirma todos los ejecutables instalados.

Por ello, `--apply` se bloquea explícitamente antes de cualquier acceso root o modificación física. La novena prueba demuestra el rechazo anticipado.

El código de instalación permanece como implementación en revisión; no está liberado para su ejecución.
F5C deberá resolver publicación durable, aceptación del commit completo, inspección de todos los archivos, bootstrap de confianza y puente de atestación root.

Estado: SOURCE_ONLY; P8=NO-GO; A6=ND.
