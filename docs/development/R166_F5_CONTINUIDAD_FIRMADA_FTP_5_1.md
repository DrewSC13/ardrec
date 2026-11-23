# ARDREC R166-F5 — Continuidad firmada y topología FTP 5/1

## Alcance

Corrige dos incompatibilidades reales de la ruta física reutilizada R115, sin
implementar otra vía de arranque ni modificar los contratos de red.

1. El guardián Git R115-F7 conserva íntegra la rama histórica
   `feat/p14-r115-a3-p7-a6-real` y su ancestro `6ce42a1...`, pero admite
   también exclusivamente la rama de continuidad
   `feat/ardrec-a1-a10-cierre-integral-v1` cuando el HEAD firmado y el árbol
   limpio descienden **de los dos ancestros**: el histórico y el commit
   R165/PR215 `5c7770c1548585f8eac7f50d5f68b8fb77a10614`.
   Una rama arbitraria o un único ancestro no pasan el control. La firma
   `%G?=G`, el seguimiento Git, el rechazo de cambios locales y los
   contratos de autorización y revocación permanecen obligatorios.
2. La inspección R115-F16 comunicaba `MATCH_4_ACTIVE_2_OFFLINE` aunque
   su contrato físico exigía **cinco vinculaciones DENY activas y una ausente
   con SMB apagada**. La etiqueta y el rechazo se alinean con el contrato
   original 5/1; se añade comprobación exacta de salida de CLI.
3. El CI incorpora las veinte pruebas de procedencia R138 y conserva
   las regresiones de R115 y R166.

## Evidencia inicial

R166-F4 en Prometheus: `OFFLINE_DENY_BASELINE_MATCH`; cuatro definiciones
`MATCH`, cuatro máquinas `OFF`, nft/helper/hook `MATCH`, doce consultas exitosas,
seis consultas de bindings inexistentes por VM apagada, originales reabiertos
SHA-256 `f0fc5d8281a9786031bbe82685e3a3e54fded9938da6e6fad85ce8598cd9b6c5`.
Ese estado offline es correcto y **no equivale** al estado físico FTP 5/1.

## Seguridad y aceptación

Antes de arranques, el operador debe verificar staging R163, autorización
independiente y revocación firmadas, el commit limpio y firmado, la integridad
de los filtros y el permiso específico de cada arranque. La CLI `--inspect-current`
solo observa. No genera permisos, no abre P8, no enciende máquinas ni publica A9.
La ventana root de 60 segundos y su restauración independiente continúan
pendientes, según el contrato R115-F16. Su ausencia bloquea el piloto con tráfico.

El procedimiento de consolidación usa el operador descargable
`ARDREC_CIERRE_24_operador.py`: primero comprueba y ejecuta regresiones, luego
**solo si se elige `--firmar`**, agrega la lista cerrada de archivos y solicita
commit firmado Git. No realiza `push`, PR ni merge. Un inventario root separado
usa únicamente `stat` y `sha256sum` sobre las rutas declaradas; no lee claves
ni instala B4/B9.

La entrega experimental requiere 54 unidades reales y valoración independiente;
no se sustituye con tests unitarios ni con la captura del piloto.
