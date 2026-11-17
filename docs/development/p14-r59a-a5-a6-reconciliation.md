# ARDREC P14-R59-A — Conciliación verificable de fuentes A5→A6 (solo lectura)

**Base:** commit SSH local `5a477100a8c754d6c307357c9091b751725d448d`, sobre la rama de desarrollo `feat/p14-r58z-verified-workspace` tras aplicar R58-Z y R58-Z-R2. **No modifica la TUI R38/R42.5.**

## Objetivo y capacidad real

R59-A une en un informe *sin colisión semántica* dos fuentes disponibles:

1. La instantánea **física histórica SSH** R42.2/R42.3, autenticada por R58-Y y proyectada en R58-Z. Se revalida al leer desde SQLite. Su fuente carece de `a5_attempt_id`, identidad de condición comprobada y cualquier inicio vinculado de A5.
2. Opcionalmente, el diario **real de intentos benignos locales P9/P12**, validado por `r58m_durable_a5_audit.audit_benign_journal`. Este diario puede contener un `START_INTENT` local y soportes cuyos bytes fueron examinados, pero no contiene identidad del caso SSH/FTP/SMB, no tiene origen físico independiente acreditado y no constituye una prueba de pentesting.

El informe identifica los registros, huellas de los archivos y cadenas de eventos, estado de auditoría, número de observaciones y motivos exactos que impiden la asociación causal A5→A6. No inventa un campo de unión que las fuentes históricas no poseen. Rechaza promociones de inicio operacional A5, evidencia A6 positiva, `Rf` confirmado, publicación A9 o `P8=GO`, incluso si se recalcula el SHA-256 del informe.

La salida se puede guardar como JSON inmutable y privado, reabrir e **inspeccionar de nuevo ambas fuentes** para detectar deriva o manipulación. Esta instantánea documental no es una generación A9. Un SHA-256 sin firma o ancla externa independiente no prueba integridad frente a un administrador que pueda reescribir simultáneamente informe y fuente.

## Entradas y uso desde la raíz Git

```sh
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59a_reconcile.py --texto
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59a_reconcile.py --snapshot
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59a_reconcile.py --verify
```

**Para auditar también un diario P9/P12 preexistente**, repetir `--texto`, `--snapshot` y `--verify` con el **mismo** par de argumentos explícitos:

```sh
--journal-root /ruta/privada/p9 --request-id ID_VERIFICADO_DEL_DIARIO
```

El lector R58-M verifica el diario y los artefactos locales. No crear una prueba, intento ni diario P9 por este comando. El `request-id` se toma de la fuente real y **no debe adivinarse**.

## Pruebas y trazabilidad

Archivo nuevo `lab/tests/test_p14_r59a_provenance.py`, patrón `test_p14_r59a_*.py`; incluye 27 casos: lectura y replay; persistencia; drift SSH y P9; rechazo de symlink, permisos, doble clave JSON, manipulación de clases y falsa vinculación; invariantes `P8 NO-GO`; distinción de casos. El workflow Python suma ese patrón sin quitar pruebas R58-Z previas.

**Alcance de pruebas locales:** R59-A 27/27 con implementaciones reales R58-Y/R58-Z y un *stub exclusivamente de pruebas* de la interfaz de auditoría R58-M, más mock de sus respuestas. La comprobación contra la implementación auténtica R58-M, los recibos físicos de Prometheus y los diarios privados se ejecutará en el anfitrión. El stub **no forma parte del ZIP**.

## Alcance y límites de aceptación

- R58-Y SSH observado: puede haber evidencia de red histórica real, pero **no evidencia A6**.
- P9 benigno: si hay un recibo preexistente, puede probar la ejecución de un fixture local, **no la identidad de un caso SSH/FTPS/SMB**.
- A5 real operacional: **0**; A6 acreditada: **0**, clasificación `ND`; A7 `Rf`: **no confirmado**; A9: **no publicada**; F11: no activado; P8: **NO-GO**.
- El algoritmo completo A5→A6 con entrada física operativa permanece pendiente de contratos de identidad, autorización, inicio, resultado y soportes independientes de la misma unidad/caso. El siguiente incremento debe implementar ese recibo operativo **únicamente después de cerrar las barreras F11**, sin convertir la conciliación documental actual en un oráculo positivo.
- No se modifica Rust, libvirt, VM, red, ejecutor ni el monitor TUI R38.
