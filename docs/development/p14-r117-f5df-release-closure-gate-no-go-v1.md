# ARDREC R117-F5D-F — Cierre transaccional y Ed25519 en la puerta F4

Este incremento actualiza el punto de aceptación real de F4 sin realizar
ninguna instalación root ni publicar el release. El staging histórico
F5D-E bajo `/var/lib/ardrec/r117-f5de-candidate-46b1f004e405-v1`
permanece sin modificaciones.

F4 verifica antes de aceptar el recibo de release:

1. Un solo diario F5B, con nombre restringido, dueño root, directorio 0700,
   conjunto exacto de cinco archivos y marcadores exactos.
2. Intent, complete, receipt y manifest ligados al HEAD mediante SHA-256,
   campos exactos y JSON estricto.
3. Complete declara ausencia de arranques, tráfico y permisos de boot.
4. Aprobación `INSTALL_SOURCE_ONLY` limitada a 600 s y firma Ed25519 real
   comprobada por OpenSSL contra el ancla root fija en `/etc/ardrec`.
5. Uso de descriptores de memoria anónimos para evitar archivos temporales
   persistentes durante la comprobación criptográfica.

**Límites:** la nueva puerta F4 no es un instalador y no concede P8, acceso
SSH/FTP/SMB, inicio de VM ni autorización de alcance. La validez de una firma
no sustituye el aprovisionamiento independiente del ancla ni la revocación
externa. Queda pendiente la publicación transaccional única del instalador,
la validación de durabilidad poscorte y el establecimiento de claves reales.

Se actualiza exclusivamente el hash F4 en el manifiesto de despacho; las
33 fuentes R116 permanecen congeladas. El nuevo candidato se reconstruirá
solo a partir del commit protegido posterior al merge.

Pruebas: regresiones de fuente, 40 contratos históricos F4 y CI Python/Rust.
Las pruebas de unidad no constituyen atestación del host: la prueba positiva
operativa requerirá una instalación real autorizada y evidencias root.

P7=DRAFT; A6=ND; P8=NO-GO; F5B --apply=BLOCKED.
