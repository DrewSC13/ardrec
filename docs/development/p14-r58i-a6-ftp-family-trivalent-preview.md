# ARDREC R58-I — Evaluador trivalente FTP/FTPS en modo sintético

**Base:** `main` firmado `35744a9e58e8421aef5fdb24a04dcd434ad3ca69` (PR #140).

**Fuente normativa:** catálogo operacional P7, `lab/operational-catalog-v1/catalog.json`, SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`, cuya fuente es la tesis ARDREC SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, sección 3.7 y tabla 3.10. No se ha recalibrado ni congelado el catálogo P7.

El nuevo evaluador `ardrec.evidence.r58i_ftp_family_logic` cubre FTP-T01…FTP-T08 y las cuatro opciones condicionadas: FTP-T02/CONTROL, FTP-T02/DATA, FTP-T08/READ y FTP-T08/WRITE. Cada opción es una identidad de evaluación explícita, con identificador de caso distinto, y nunca se deduce del estado de otra. `DATA` exige precondiciones adicionales `CONTROL_CHANNEL_VERIFIED` y `SESSION_AUTHENTICATED`, y soporte `CONTROL_DATA_CORRELATION`. `CONTROL` no necesita ni acredita por sí solo correlación con el canal de datos. La variante `WRITE` de FTP-T08 agrega preparación de marcador, limpieza verificable y los soportes `MARKER_CREATED`, `MARKER_VERIFIED`, `CLEANUP_CONFIRMED` sin alterar la definición del catálogo fuente. FTP-T07 también exige limpieza separada. La precedencia se obtiene del catálogo: FTP-T02 CONTROL=1/DATA=3; FTP-T08 READ=3/WRITE=4.

La lógica trivalente exige que todas las precondiciones sean `VERDADERO`; `FALSO` o `ND` bloquean elegibilidad. La presencia de un soporte no equivale a una condición positiva: el signo proviene únicamente de `outcome` explícito, todavía sintético. La ausencia de soporte produce `INCONCLUSO`, nunca `NEGATIVO_VALIDO`. Contradicciones e incidencias de limpieza se clasifican por separado. Se preservan las seis clases de tesis: `POSITIVO_VALIDO`, `NEGATIVO_VALIDO`, `INCONCLUSO`, `INCIDENCIA`, `INVALIDO`, `NO_ADMITIDO`.

Se valida el fichero completo del catálogo por SHA-256 antes de cualquier evaluación normal. El informe se ordena por sesión, caso, índice y variante, evita duplicados, se reconstruye para comprobar integridad e indica siempre `mode=SYNTHETIC_RULE_EVALUATION_ONLY` y `a6_classification=ND`. Una inyección `_test_families` se marca como `TEST_FIXTURE_NOT_PINNED` y no adquiere autoridad.

La demostración recorre ocho familias y diez opciones evaluadas con entradas sintéticas. Este número no equivale a diez casos de laboratorio reales. No existe acreditación técnica independiente, contribución de riesgo, `Rf` final, cambio de estado, generación A9, despacho P8, operación de red ni modificación de VM. Se conservan `R34 DENY` y `P8=NO-GO`. Los límites de ejecución física siguen pendientes de piloto.

Comprobar en checkout:

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58i_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58i_ftp_family_demo.py --synthetic-offline
```

El siguiente incremento R58-J ampliará la cobertura lógica a SMB-T01…T09 sin ejecutar los servicios. Las 25 familias seguirán sin aceptación experimental hasta las pruebas físicas autorizadas.
