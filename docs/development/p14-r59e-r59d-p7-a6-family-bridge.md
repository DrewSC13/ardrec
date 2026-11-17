# ARDREC P14 / R59-E — Puente funcional R59-D A5 → P7/R58-H/I/J A6

## Alcance

R59-E vuelve a verificar desde archivos privados `0700/0600` los recibos R59-D y sus soportes (si existen), verifica el catálogo completo P7 con SHA-256 fijado (8 SSH, 8 FTP, 9 SMB) y ejecuta **el clasificador existente R58-H, R58-I o R58-J** para evaluar, exclusivamente como simulación, un caso vinculado a servicio, familia, sesión, intento, índice y configuración.

Los resultados `NO_START` nunca ejecutan un motor de reglas ni pueden contener revisiones positivas. Para otros resultados, los precondicionantes, soportes, integridad, procedencia y cleanup tienen valor `ND` por defecto. Si se aporta una revisión declarativa `UNATTESTED_REVIEW_DECLARATION`, se verifican todas las claves contra el catálogo fijado, pero incluso una simulación de `POSITIVO_VALIDO`/`NEGATIVO_VALIDO` **no acredita verdad técnica**.

Se congelan en un recibo único por huella R59-D la variante (FTP-T02 CONTROL/DATA, FTP-T08 READ/WRITE, SMB-T03 SIGNING/ENCRYPTION, SMB-T09 READ/WRITE), la revisión y la huella del resultado de las reglas. Toda segunda escritura con distinta variante o revisión falla. **La variante no estaba en la identidad de intento R59-D**: el sidecar solo es una selección de revisión, no un vínculo físico probado. Una evolución futura del contrato de A5 deberá incluirla en la identidad antes de ejecución.

## Restricciones y seguridad

- No hay sockets, comandos privilegiados, VM, cambio del estado de host, F11, despacho ni A5 real.
- A6 permanece `ND`; riesgo `Rf` confirmado, transiciones A8 y generación A9 siguen sin valor.
- El conjunto original R58-H/I/J sigue siendo un clasificador de **simulación** para el catálogo P7, todavía borrador y no calibrado para ejecución.
- Cada reapertura recalcula el informe desde el recibo R59-D persistido, su soporte verificado y el catálogo de 25 familias fijado. Manipulaciones o alteraciones del origen invalidan el informe.
- Un SHA-256 por sí solo no demuestra autenticidad de origen, aislamiento, privilegio, condiciones de red ni verdad experimental.
- La TUI R38/R42.5 no se modifica; `P8=NO-GO`.

## Comando de prueba integrado (una vez aplicada la fuente)

```bash
mkdir -p -m 700 /home/cicada/ardrec-lab/r59e
chmod 700 /home/cicada/ardrec-lab/r59e
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59e_a5_a6_family_bridge.py \
  --source-root /home/cicada/ardrec-lab/r59d \
  --output-root /home/cicada/ardrec-lab/r59e \
  --from-r59d-demo-summary /home/cicada/ardrec-lab/r59d/r59d-demo-first.log
```

El demo `NO_START` solo revisa identidad y obligaciones del catálogo: no afirma inicio A5 ni clasificación técnica A6. Para reabrir con `--verify`, indicar `--candidate-sha HEX` del recibo R59-D y los mismos directorios.
