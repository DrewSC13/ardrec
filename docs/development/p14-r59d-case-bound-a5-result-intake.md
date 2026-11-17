# ARDREC P14 / R59-D — Contrato tipado A5 → admisión documental A6

**Implementación funcional source-only, sin despacho físico.** R59-D introduce el punto de recepción de resultados de intentos A5, independientemente de la etapa de ejecución. El objetivo es impedir asociaciones falsas entre servicios, familias, casos derivados, ventanas de evaluación, intentos, configuración efectiva, método y soportes.

## Qué implementa

- Identidad de solicitud A5 (`r59d-a5-case-intent-v1`), con familia SSH/FTP/SMB conforme a la numeración de 25 familias, identificador de caso derivado, índice de evaluación, `ATT_*`, hash de configuración y método de observación por protocolo. El contrato presupone **fase modelo PENDIENTE**, sin transformarla en autoridad operacional.
- Recibo tipado del resultado **declarado**. Valida correlación exacta en ocho campos, orden temporal UTC, resultados `NO_START`, `OBSERVADO_POSITIVO`, `OBSERVADO_NEGATIVO`, `INCONCLUSO`, `INCIDENCIA`, fuente y digest/longitud del soporte. Si declara `NO_START`, debe carecer de fechas de ejecución y soporte.
- Persistencia privada `0700`/`0600`, SHA-256 reproducible, escritura con `O_EXCL`, idempotencia por bytes, rechazo de enlaces simbólicos, conflicto, permisos indebidos y manipulación posterior; reapertura con nueva validación del contrato y soporte original.
- CLI con tres modos: `--demo-no-start`, importación de archivos privados `--import-intent/--import-receipt/--import-support`, y `--verify-sha` para reapertura. Se limita a fuentes locales, sin procesos, sockets, comandos privilegiados ni VM. Importar un recibo positivo nunca lo acredita como positivo real.

## Qué NO implementa / comprobaciones físicas pendientes

R59-D no acredita el origen del recibo, identidad real del actor, vínculo independiente con F11, autorización A3/P8, inicio físico A5 ni contenido verdadero del soporte. `physical_authority_receipt_sha256` **solo admite null en este formato**; se requiere nueva versión y un verificador independiente de autoridad, identidad y prueba física antes de admitir ese dato. Todos los resultados se reciben con `a5_physical_start_accredited=false`, `a6_classification=ND`, `a7_confirmed_rf=null`, `a9_published_generation=null`, `P8=NO-GO`. No reemplaza R58-H/I/J ni sus criterios de clasificación técnica.

El catálogo P7 fija 8 familias SSH, 8 FTP y 9 SMB. **Este módulo valida su nomenclatura, no todos los metadatos de cada familia del catálogo**: la vinculación con la revisión técnica P7 y con las autorizaciones operacionales será una fase posterior.

## Probar y demostrar sin ejecución

```shell
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r59d_*.py' -v
mkdir -p -m 700 /home/cicada/ardrec-lab/r59d
chmod 700 /home/cicada/ardrec-lab/r59d
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59d_a5_intake.py --demo-no-start --store-root /home/cicada/ardrec-lab/r59d
```

**No modificar la TUI R38/R42.5.** La fuente está preparada para integrarse con un verificador futuro de recibos A5 reales. La instalación física de F11 se gestiona y autoriza por separado.
