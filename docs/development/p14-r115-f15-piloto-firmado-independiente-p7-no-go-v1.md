# R115-F15: vía documental independiente para el piloto P7 FTP-T01

## Propósito y límite exacto

El catálogo P7 mantiene el estado `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`, con `pilot_completed=false`, `catalog_frozen=false` y `execution_enabled=false`. Las reglas de P8 para actividad ordinaria exigen una calibración previa; una calibración auténtica precisa de un ensayo controlado. F15 distingue una **solicitud excepcional de piloto** del despacho P8 ordinario, sin declarar resuelto el requisito físico.

F15 **no** habilita el catálogo ni cambia los valores de P7. **No** inicia VM, modifica nftables, crea sockets, emite claves, firma permisos, obtiene una autorización o promueve A6/A7/A8/A9/A10. El instalador solo ejecuta pruebas y emite un commit local firmado; la CLI `--prepare` solo genera una solicitud privada no ejecutable.

## Reutilización de contratos

- F1: contrato DEV de la familia FTP-T01 y catálogo de 25 familias.
- F3/F6: verificación criptográfica Ed25519 de autorización de alcance y revocación de una autoridad independiente; una referencia local o hash no constituye autoridad.
- F7/F8: pasos físicos separados SSH → runner → FTP con atestación DENY y recibos de intento único. **F15 no los ejecuta.**
- F10/F11/F12: transporte de control FTP, ventana documental P8 y perfil finito. La autorización de piloto no reemplaza la ventana ordinaria P8.
- F13/F14: reserva durable y replay de candidato A5. No admitir evidencia A6 por un documento de piloto.

## Contrato firmado exclusivo del piloto

El operador solicita al responsable independiente un permiso Ed25519 `ARDREC-R115-F15-FTP-T01-PILOT-PERMIT-v1`. Su `statement` debe incluir exactamente: `schema`, `pilot_id`, `case_id`, `stage`, `family_id`, `head`, `contract_sha256`, `scope_authorization_sha256`, `catalog_sha256`, `target`, `budget`, `valid_from`, `valid_until`, `action`, `pilot_only_no_production_p8`.

- Acción exacta: `ONE_ISOLATED_FTP_T01_CONTROL_GREETING`.
- Familia única: `FTP-T01`, destino único vinculado al contrato DEV, puerto TCP 21.
- Tiempo firmado máximo: **60 segundos**, con fechas UTC explícitas; la autorización y su revocación deben estar vigentes simultáneamente.
- Perfil no más amplio que F12, y siempre dentro del contrato F1.
- Máximo: una conexión, un intento ordinario, cero reintentos, diez segundos de recepción, 4.096 bytes de entrada, 16 llamadas `recv`, lectura de 512 bytes, 8.192 bytes de salida.
- La firma usa dominio `ARDREC-R115-F15-P7-PILOT-PERMIT-v1\x00` sobre JSON canónico del `statement`; se reutiliza el verificador Ed25519/OpenSSL existente.
- El documento de revocación `ARDREC-R115-F15-P7-PILOT-REVOCATION-v1` vincula `pilot_sha256` y `pilot_id`; dominio de firma distinto y antigüedad máxima de 30 segundos. Una revocación válida es bloqueo, no excepción.
- La raíz de confianza `ARDREC-R115-F15-P7-EXTERNAL-TRUST-v1` requiere dos claves públicas de roles distintos: `pilot_signer` y `revocation_signer`. La separación de claves **no acredita por sí sola independencia institucional**: esta debe verificarse en el procedimiento externo.

La política de confianza y la revocación deben ser instaladas de forma independiente por un administrador autorizado en `/etc/ardrec/r115-p7-pilot-trust-v1.json` y `/etc/ardrec/r115-p7-pilot-revocation-v1.json`, con archivos regulares propiedad de root y directorios no escribibles por grupos u otros. No introducir claves privadas ni gestionar sudoers desde ARDREC.

## Por qué firma válida no es GO

El estado `DOCUMENT_SIGNED` demuestra exclusivamente que un documento vigente fue firmado bajo la clave pública aceptada. La admisión **física** requiere además la cadena SSH → runner → FTP realmente atestada, los seis vínculos DENY en ejecución, la política nftables y F11/R34 efectivas, verificación A3 de destino/cliente/servicio, controlador raíz de piloto que abra y cierre una excepción de tráfico de alcance mínimo, revocación verificada en el momento de la acción, captura y restauración documentadas. Estos mecanismos no están implementados completamente en F15.

**Resultado invariante de F15:** `physical_pilot_authorized=false`, `pilot_completed=false`, `p7_execution_enabled=false`, `p8=NO-GO`, `a5=NO-GO`, `a6=ND`, A7–A10 sin resultado. Un recibo F15 no es una autorización de arranque ni de conexión; su JSON no puede reutilizarse como lease.

## CLI y continuidad

Desde la raíz del repositorio firmado con Python y PYTHONPATH configurados:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 scripts/ardrec_p14_r115_f15_p7_independent_pilot.py --capabilities
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 scripts/ardrec_p14_r115_f15_p7_independent_pilot.py --prepare
```

Sin contrato ni firma externa el informe registra `ND` y blockers explícitos. Los recibos se guardan en `/home/cicada/ardrec-lab/r115-f15-p7-pilot-v1` con manifiesto SHA-256. No se imprime material criptográfico ni se crea un permiso de manera automática.

**Próximo incremento concreto:** controlador físico de piloto **separado** del P8 ordinario; instrumentación del experimento para medir tiempos, bytes y fallos reales y evaluación documentada antes de congelar cualquier perfil P7. Este próximo incremento no debe interpretar F15 como un GO autónomo.
