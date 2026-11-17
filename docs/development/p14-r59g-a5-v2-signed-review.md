# ARDREC P14 / R59-G — A5 v2: firma doble y registro de confianza fijado

## Alcance funcional

R59-G implementa el **consumidor de declaraciones A5 v2 firmadas**, reutilizando sin modificarlos los módulos existentes R59-D/E/F, R58-F (Ed25519) y R58-G (registro de confianza de observador/revisor).

- Reabre y verifica el informe A5 v2, su intento, variante, candidato R59-D, puente P7 R59-E y soporte físico **declarado** con SHA-256.
- Rechaza `NO_START`, resultados benignos locales, soportes ausentes, diferencias de caso/variante/intento/método, rutas inseguras y cambios de bytes.
- Construye una declaración firmable con separación de dominio `ARDREC-R59G-A5-V2-DECLARED-RESULT-V1\0`, identidad completa, huellas de la cadena y tiempos declarados.
- Exige dos firmas Ed25519 auténticas (`observer` y `reviewer`), claves diferentes, IDs diferentes, y un registro R58-G de confianza **fijado por SHA-256 suministrado externamente**. La huella NO se acepta desde el propio recibo firmado.
- Rechaza claves revocadas, periodo inválido, caso fuera de campaña, revisión anterior al fin declarado y revisión a más de 24 h del fin declarado.
- Guarda el resultado privado, inmutable e idempotente, una declaración firmada por ID de intento, recuperable tras verificar nuevamente fuentes, firmas y registro externo.

### Lo que el resultado **no demuestra**

Los testigos de las pruebas locales son identidades efímeras creadas por el test, no testigos físicamente independientes. Incluso dos firmas legítimas solo autentican la atribución de una **declaración**. No acreditan ejecución A5 ni aislamiento F11, no convierten una observación en condición técnica válida y no habilitan A6, A7, A8, A9 o P8.

Estado impuesto y verificado en todos los informes: `a5_physical_start_accredited=false`, `a6_classification=ND`, `confirmed_final_risk=null`, `published_generation=null`, `operational_dispatch=false`, `p8_operational=NO-GO`.

## Interfaces

- `r59g_signed_a5_review.statement_for(doc)`: firma el objeto A5 v2 por bytes canónicos y prefijo de dominio.
- `build_review(v2_root, a5_root, a6_root, attempt_id, signatures, registry_document, registry_pin_sha256, review_at_utc)`: comprobación completa sin escritura.
- `persist(output_root, v2_root, a5_root, a6_root, attempt_id, signatures, registry_path, registry_pin_sha256, review_at_utc)`: escritura privada create-once, fsync y readback.
- `verify_stored(...)`: prueba de reapertura con registro fijado externo; rechaza cambios de origen.

La CLI `scripts/ardrec_p14_r59g_signed_review.py` tiene `--inspect-v2` (sin atestación), `--submit-signed` y `--verify-signed`. Nunca usa claves privadas; acepta un JSON de dos firmas por ruta privada, distinto del registro R58-G que se fija por huella externa.

## Pruebas y continuidad

`PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r59g_*.py' -v`

La suite es autocontenida para generar testigos efímeros mediante `/usr/bin/openssl` y probar la firma real, sin red ni ejecución de invitados. El runner comprueba además el registro FTP-T02/DATA `NO_START` de R59-F y sus límites de acreditación.

El código está listo como incremento **source-only** sobre la rama `feat/p14-r58z-verified-workspace`. No modifica archivos previos salvo insertar un paso de CI. El host, nftables, libvirt, systemd, VM, F11 y TUI R38 permanecen intactos. No crear commits ni PR sin una decisión separada.

## Riesgo residual

La autenticidad del **registro** requiere un anclaje externo confiable de su SHA-256; si el mismo remitente controla el registro y el pin, las firmas no proporcionan confianza independiente. La credencial y la revisión no establecen procedencia física ni validez experimental. F11 continúa `NO-GO` hasta instalación autorizada y pruebas negativas/recuperación independientes.
