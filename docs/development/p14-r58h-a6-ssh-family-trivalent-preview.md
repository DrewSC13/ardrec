# ARDREC P14 · R58-H — Evaluación trivalente A6 para las ocho familias SSH

**Base:** `main` firmado `dcde0774540c33fb47c46c0a9862ac2cfc37e7ec` (PR #139).
**Fuente académica exacta:** `Tesis ARDREC(20261116-013627).pdf`, SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, §3.3.2, §3.3.4, tabla 3.3 y §3.7.2 tabla 3.9.
**Catálogo base:** `lab/operational-catalog-v1/catalog.json`, SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e` (P7, todavía no congelado).

## Funcionalidad implementada

El núcleo `ardrec.evidence.r58h_ssh_family_logic` lee el catálogo P7 por su SHA-256 completo, valida la versión y obtiene las familias **SSH-T01...SSH-T08**. Aplica exclusivamente las precondiciones, los soportes obligatorios, los soportes de aceptación, la precedencia y la limpieza declarados para cada familia. No crea una novena familia ni ejecuta comandos SSH.

Para cada unidad **sintética** `(session_id, derived_case_id, assessment_index)`:

- Valida identidad y vínculo con la familia; rechaza casos y ventanas duplicados, campos extraños y estados fuera de dominio.
- Calcula conjunción trivalente fuerte de precondiciones: `FALSO` prevalece; `ND` permanece indeterminado; solo todas `VERDADERO` satisfacen la guarda simulada.
- Distingue falta de soporte (`ND`) de soporte contradicho (`FALSO`), y exige procedencia e integridad como entradas hipotéticas; **esas entradas no certifican su propia realidad**.
- Presenta las seis clases del catálogo: `POSITIVO_VALIDO`, `NEGATIVO_VALIDO`, `INCONCLUSO`, `INCIDENCIA`, `INVALIDO`, `NO_ADMITIDO`. Son **resultados hipotéticos de reglas**, no clases admitidas de un intento real.
- Un negativo válido *hipotético* exige `OBSERVADO_NEGATIVO` explícito y soportes completos; la falta de observación jamás se convierte en resultado negativo.
- La familia `SSH-T07` exige limpieza independiente del marcador. Si se declara fallo, se produce `INCIDENCIA` en la simulación; una contradicción entre limpieza y soporte se trata como `INVALIDO`.
- Recalcula el informe completo, además del SHA-256, para bloquear informes alterados incluso si se actualizó su digest.

## Límite de autoridad

`hypothetical_result_class=POSITIVO_VALIDO` o `NEGATIVO_VALIDO` **no significa que A6 haya admitido evidencia técnica**. Se ejecuta un evaluador de condiciones supuestas, no una comprobación externa de firmas, testigos, parámetros efectivos, inicio, terminación ni limpieza real. Estas comprobaciones permanecen pendientes de acreditación independiente, trazabilidad por intento y autorización física. La propia entrada `integrity=VERDADERO` o `provenance=VERDADERO` se interpreta como hipótesis y no como verificación realizada por este código.

Todas las salidas mantienen `a6_classification=ND`, `technical_truth_accredited=false`, `confirmed_final_risk=null`, `published_generation=null`, `applied_state_transition=null`, `operational_dispatch=false` y `p8_operational=NO-GO`. No se escriben recibos, no se cambia libvirt/nftables/systemd, no hay tráfico ni se arrancan VM. Las 54 unidades son un límite de la interfaz; **no representan 54 casos validados**.

## Comandos

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58h_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58h_ssh_family_demo.py --synthetic-offline
```

El CLI usa el catálogo **real fijado por SHA**; los tests de reglas emplean adicionalmente una copia mínima explícitamente identificada `TEST_FIXTURE_NOT_PINNED` para escenarios adversariales. Los campos de resultados de pruebas sintéticas no se transportan ni son admisibles en el estado operacional.

## Continuidad

Extender, en PR separados, la misma clasificación trivalente a FTP-T01...T08 y SMB-T01...T09, prestando especial atención a variantes control/datos, firma/cifrado y lectura/escritura. Después conectar resultados **técnicamente acreditados** con el puente A6–A7 y A9, respetando el punto de autorización física F11 y manteniendo `R34 DENY` / `P8=NO-GO`.
