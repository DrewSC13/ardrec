# ARDREC R166-F1 — Una entrada de expediente documental con relectura real

**Estado:** integración de CLI y archivo documental local verificada en pruebas de regresión; **NO** acreditación de laboratorio ni publicación operacional A9.

## Propósito y alcance

`python -m ardrec caso` amplía la entrada existente sin alterar `python -m ardrec live --texto` ni el modo DEV. Admite una exportación B9/F13 ya disponible, verifica identidad y originales con los contratos R129-B10 y R165-F2, y conserva una proyección privada inmutable que puede reabrirse en otro proceso.

Este incremento **no** emite tráfico SSH, FTP ni SMB, no activa invitadas, no solicita privilegios root, no cambia nftables y no puede confirmar A6, Rf ni A9. No crea una segunda ejecución ni restaura automáticamente un intento consumido. El almacén `record.json` es **documental y derivado**: no se cuenta como `DurableStore` ni como generación del algoritmo 9.

## Entrada normal y comandos exactos

Preparar, como usuario no root, un directorio privado `0700` con originales exportados y ficheros `0600`. Su contenido tiene estos nombres **obligatorios**: `handoff.json`, `intent.json`, `receipt.json`. Si hay respuesta de la invitada, añadir **ambos** `guest.json` y `qga.json`. Cuando existan cinco documentos B11, colocarlos en `signed/` (directorio `0700`) como `source.json`, `technical.json`, `revocation.json`, `witness.json` y `trust.json` (ficheros `0600`). El diario F13 original permanece **en su ruta privada absoluta**, no se mueve ni se regeneran intentos.

Ejemplo de la secuencia, sustituyendo las rutas por las del expediente que exista:

```zsh
python -m ardrec caso sellar --origen "$ORIGEN" --journal "$JOURNAL_F13" --manifiesto "$MANIFIESTO" --texto
python -m ardrec caso revisar --manifiesto "$MANIFIESTO" --texto
python -m ardrec caso incorporar --manifiesto "$MANIFIESTO" --archivo "$ARCHIVO" --texto
python -m ardrec caso incorporar --manifiesto "$MANIFIESTO" --archivo "$ARCHIVO" --texto
python -m ardrec caso reabrir --manifiesto "$MANIFIESTO" --archivo "$ARCHIVO" --texto
```

Se admite `--json` en lugar de `--texto`. Para documentos firmados **históricos**, `sellar` exige `--evaluacion-utc 2026-11-21T22:00:00Z` con el instante real correspondiente, verificable en los soportes; esa comprobación es **histórica**, jamás una autorización actual. No utilizar una fecha inventada o extraída de fixtures para un expediente real. No se da por vigente una revocación desde una firma histórica.

El manifiesto ancla rutas absolutas y SHA-256 de cada documento. El controlador vuelve a validar el diario F13 y vuelve a calcular toda la cadena B9/B11. `reabrir` vuelve a leer las fuentes y compara el registro derivado íntegro. Si algún soporte cambia, se devuelve un código concreto y no se altera el registro anterior.

## Condiciones y archivo de un solo caso

- El registro de identidad incluye `head`, `session`, `case_id`, `case_key`, `attempt_id`, hash del manifiesto, hashes de los documentos, cadena A5–A10 y la primera condición bloqueante.
- Las lecturas exigen archivos privados, regulares, sin enlace simbólico, con propietario efectivo, enlace único y permisos `0600`; los directorios privados exigen `0700`. Los formatos JSON deben ser canónicos y no contener claves repetidas.
- El archivo de un caso usa bloqueo `flock`, temporal durable, `fsync`, `rename` atómico y verificación SHA-256. Dos incorporaciones idénticas emiten `DOCUMENTARY_RECORD_WRITTEN` y `ALREADY_INCORPORATED`. Dos documentos incompatibles para el mismo archivo devuelven `ARCHIVE_CAS_CONFLICT`.
- Si el proceso se interrumpe antes de la publicación del registro, puede permanecer `.pending-*`. No es resultado confirmado y se preserva para auditoría. La repetición del comando completa de forma segura el expediente si los originales continúan intactos. Una interrupción tras la publicación se confirma con `reabrir`.
- Esta atomicidad es del **archivo derivado**. No acredita ni sustituye CAS ni recuperación de la generación **operacional A9**, que sigue bajo las guardas del modelo nativo.

## Correspondencia A1–A10 y nivel alcanzado

| Bloque | Requisito y módulo existente | Entrada observada por R166-F1 | Decisión, salida y prueba | Alcance |
|---|---|---|---|---|
| A1 | `ardrec.rules.kernel`; evaluación determinista | Contratos heredados del núcleo | Pruebas del núcleo previas; R166 no vuelve a ejecutar A1 global | Integración pendiente |
| A2 | Validación del escenario/configuración inicial | Manifiesto R166, identidad y SHA de exportaciones | Rechaza origen, formato e identidad inválidos; pruebas R166 3, 9, 12 | Validación **documental**, no inicialización de estado global |
| A3 | `r119_live_inspection`, R115-F5/F11; controles de laboratorio | No recibe capacidad operacional de habilitación | `P8=NO-GO`, bloqueo explícito; pruebas R166 1, 13 | Sin ejecución física |
| A4 | Selección y prioridad del catálogo P7, módulos preexistentes R58 | No ordena nuevos candidatos desde documentos B9 | Ningún consentimiento físico generado | Pendiente de integración en la CLI operacional |
| A5 | `r129_b9_receipt_gate.review` y F13; R165-F2 | Journal original + handoff + intención + recibo + respuesta QGA | Revisión B10 y traza A5; pruebas R166 1–5 | Reproducción documental, no nuevo intento |
| A6 | `r129_b11_independent_a6.signed_review`, R165-F2 | Soportes B11 opcionales con tiempo histórico | Verifica firma documental, conserva A6=ND; pruebas R166 10, 13 | No certifica relectura root física |
| A7 | R165-F3 y B12 / cálculo exacto existente | La CLI R166 recibe revisión documental, no condiciones de cálculo confirmado | `RF_CONFIRMADO=ND`; pruebas R166 1, 10 | Sin riesgo confirmado |
| A8 | Estado nativo `transition_service`, R165-F3 | No se registra nueva transición operacional | `A8=OPERATIONAL_TRANSITION_NOT_APPLIED`; pruebas R165-F3 | Solo ensayos nativos anteriores en memoria |
| A9 | `DurableStore`, R165-F3 y B13; preflight nativo | Archiva reporte separado | `A9_GENERACION_OPERACIONAL=NO_PUBLICADA`; R166 2, 5, 6, 13 | Archivo R166 != A9 |
| A10 | R165-F2 + vista texto del caso | Documento y cadena A5–A10 | Impresión de seis eventos, causas y huellas; R166 1, 7 | Lectura del expediente desde CLI |

La cadena documental R165-F2 expone seis hitos A5–A10. Los nombres impresos corresponden a esos hitos y **no** significan que se hayan satisfecho los diez algoritmos completos ni que exista publicación operacional.

## Verificación física siguiente en Prometheus (NO-GO hasta recibo)

1. Revisar el HEAD, árbol Git y `git status` actuales, y comparar con el recibo R163-F10 firmado, el journal y las huellas de fuentes B4/B9 V2. No usar un archivo del checkout como prueba de instalación root.
2. Consultar las capacidades del código existente **sin ejecutar `--stage` ni `--apply`**:

```zsh
python3 -B scripts/ardrec_p14_r163_v3_bootstrap.py --capabilities
python3 -B scripts/ardrec_p14_r163_v3_root_stage_agent.py --capabilities
```

3. Cuando el agente esté **realmente** instalado en `/opt/ardrec/r163-installer-v1/installer.py`, bajo el perfil root aprobado y con política vigente, efectuar la comprobación `--preflight` mediante el procedimiento privilegiado autorizado; comparar inventario, journal, recibo, propietario/permisos y bytes instalados. No se invoca automáticamente desde el aplicador del parche.
4. Verificar la captura real de los estados de VM y red desde `python -m ardrec live --capturar --texto`. El comando R119 existente solo inspecciona y registra, nunca habilita tráfico. Confrontar estados de SSH/Runner/FTP/SMB y cinco vinculaciones DENY efectivamente activas más una sexta ausente mediante capturas independientes, no por el mero número de reglas definidas.
5. Solo cuando el control de instalación, topología, política, restauración autónoma y recepción original FTP-T01 sean observables con originales de Prometheus, preparar el piloto autorizado. La respuesta `220` acredita como máximo el canal de control observado, nunca autenticación ni vulnerabilidad.

**Recibo saneado que debe regresar:** fecha UTC y arranque, commit, identificador de paquete R163, huellas SHA-256 de B4/B9 y de sus lecturas instaladas, cadena de journal/recibo F10, número/estado de vinculaciones DENY, presencia/ausencia de invitadas por alias, límite de recuperación observado, identificador F13/B9/FTP-T01 y estatus `P8`, `A6`, `Rf`, `A9`. No incluir secretos, direcciones de interfaces privadas, claves, firmas originales ni logs crudos en GitHub.

## Ensayos R166-F1

Las pruebas de regresión reutilizan los fixtures B10/B11 ya existentes (señalados explícitamente como sintéticos) para demostrar el mecanismo sin producir tráfico. Ejecutar como usuario **no root**, con Python `3.14.7` en Prometheus/CI. No asignar las 13 pruebas a las 54 unidades de la investigación.

El `CI` de Entrega A incluye ahora la rama `feat/ardrec-a1-a10-cierre-integral-v1` y el patrón `test_p14_r166_f1_case_archive_cli.py`; cualquier salto de pruebas por privilegios debe fallar en CI. Las pruebas locales del entorno auxiliar deben etiquetarse con su versión exacta de Python.
