# R139 — Liberación independiente B9: cadena firmada completa (fuente)

## Identidad y alcance

Rama `feat/ardrec-cierre-operacional-experimental`, base **R138** firmada
`9ad7fcb7672bdd016beb0cf6c8d6139957ffdc4d` y árbol
`d1a0f39aa64d07459e2d7f1767a68b4ae7c0717f`.
Se conserva `main=95a6d57b8241101c7a8fa3aedc07fb779b088d9f`.

## Función

`r139_independent_release_review.review` conecta la validación operativa
R136 (ocho firmantes B4 y dos de tráfico B9; firmas y revocaciones actuales)
con el validador **B9 V2** `signed_release`. Este último comprueba dos
firmantes adicionales independientes, su firma Ed25519, el hash del manifiesto,
las identidades B4/F3/R116, HEAD, `boot_id`, el hash de la referencia F8,
ventana de validez y revocación actual firmada. Reutiliza los bytes originales
B4/B9 V2 mediante verificación de sus SHA-256.

El campo `source_commit_signature_verified=true` del documento firmado es una
**declaración de la autoridad emisora**; este módulo NO verifica de forma
independiente la firma criptográfica del commit Git en el repositorio. Del mismo
modo, la referencia F8 es documental: no se reproducen ni atestiguan los
recibos físicos de SSH→runner→FTP y su procedencia root no está establecida.

Las doce claves se generan temporalmente **solo en las pruebas**. El paquete
no incluye claves privadas ni autoriza crear autoridades operacionales.

## Resultado admisible

`operational_signed_semantics=PASS` + `release_signed_semantics=PASS` significa
que los documentos suministrados son coherentes y están firmados respecto a
las claves suministradas. No significa que esas claves hayan sido instaladas
por una autoridad root independiente, ni que los documentos procedan de una
ruta inmutable, ni que exista autorización real de instalar, armar DENY o abrir
tráfico. Por contrato siempre se devuelve:

- `root_trust_provenance_verified=false`;
- `source_commit_signature_independently_verified=false`;
- `f8_physical_boot_chain_attested=false`;
- `installation_permission=false`;
- `root_installed=false`, `traffic_enabled=false`, `a6=ND`, `a9=null`, `p8=NO-GO`.

## Evidencia

30 pruebas nuevas incluyendo firma real, claves duplicadas por id y por bytes,
revocación alterada, liberación caducada, SHA de manifiesto y F8 cambiados,
`boot_id` o HEAD incorrectos, source B4/B9 corrupto y material sin canonical JSON.
Regresión requerida en Prometheus: R130–R136 (221), F7/F8 (60), R138 (19),
R139 (30) = **330** pruebas. CI de rama local pendiente de ejecución remota.

## Falta para A / B

- Instalar el agente fuera del checkout, autenticado como root, con
  `openat`/`O_NOFOLLOW`, control de ancestros, permisos, hashes y procedencia;
- verificar externamente confianza, firmas Git reales y recibos F8;
- insertar una revalidación de revocación fresca **antes de cada mutación**
  de la transacción R135 sin aceptar callbacks arbitrarios como autoridad;
- publicar/reconciliar los destinos reales B4/B9, no `published-b4` de ensayo;
- probar recuperación, interrupción, caída de proceso y operación con root;
- recibir autorizaciones externas actuales; atestar físicamente 5/1 DENY;
- FTP-T01 real y A1–A10, 54 unidades, sin inferir A6 ni A9 desde mocks.

No `sudo`, `virsh start`, `nft -f`, tráfico, PR, merge o push en R139.
