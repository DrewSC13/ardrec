# R122 — Conciliación operacional FTP-T01, recibos físicos y expediente A5–A10

**Alcance:** SOURCE_ONLY / replay, sin autorización operativa, sin arranque ni tráfico.

## Origen y reutilización

- R115-F5: captura física de host (libvirt/nft/F11) con recibo privado, verificado por R119.
- R115-F16: reglas de admisión del piloto FTP, topología y DENY vigentes, comprobadas desde la captura.
- R115-F13/F14: reserva, consumo irrevocable e interpretación conservadora del resultado A5 candidato.
- R121: expediente F13 y cálculo exacto A7, recomendación A8 y auditoría, sin promoción A6.
- A9: DurableStore ya existente; R122 **no lo abre ni publica generación**. El archivo privado A10 no equivale al HEAD autoritativo.

## Entradas, invariantes y salidas

`r122_operational_boundary.build(...)` exige un commit de 40 caracteres y un recibo R115-F5 verificable. Puede vincular opcionalmente un directorio F13 y una unidad matemática exacta (siempre ambos o ninguno). El `head` dentro de la reserva F13 debe coincidir exactamente con el HEAD evaluado; se rechazan casos cruzados, alteración de manifiestos, rutas no admitidas y valores matemáticos no canónicos.

La respuesta conserva los SHA-256 de captura, reporte físico F5, dictamen F16 y expediente R121, el estado observado de las VM y los bloqueos de autorización. La evaluación es reproducible para el instante UTC registrado y las mismas fuentes inmutables. El hash de la salida es auditado y puede archivarse en un directorio privado bajo un archivo de manifiesto. Una revisión del archivo vuelve a leer los recibos originales; si han cambiado, falla.

Los invariantes son: `P7=DRAFT_NOT_EXECUTABLE`, `P8=NO-GO`, `A6=ND`, `Rf confirmado=None`, `A8 aplicado=None`, `A9 generación=None`, acciones físicas desde R122=0. **Una captura F5 fresca, incluso con cinco enlaces DENY, no demuestra origen físico de los bytes F13 ni un permiso de tráfico**. El dictamen F16 es `SOURCE_ONLY` hasta que exista controlador raíz independiente con política vigente. Los documentos históricos de F5B/R118 son prueba de continuidad de fuente y no se reutilizan como permiso de arranque.

## Uso autorizado en Prometheus

Desde `/home/cicada/Development/GitHub/ardrec`, en `zsh`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r122_operational_boundary.py --capabilities | more
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r122_operational_boundary.py \
  --inspect --head "$(git rev-parse HEAD)" \
  --capture /home/cicada/ardrec-lab/r115-f5-lifecycle-deny-v1/capture-xgwi5e2_ | more
```

El `--capture` usa la captura real histórica, sin recapturar ni invocar `sudo`. El resultado incluirá `F5_CAPTURE_NOT_FRESH` y `HOST_OFFLINE_NO_FTP_T01_TRAFFIC` cuando corresponda. Para asociar una reserva F13 legítima añada **ambas** `--journal /ruta/absoluta/case-...` y `--unit-file /ruta/absoluta/unidad.json`. Se rechaza una reserva de otro HEAD; tampoco se puede reutilizar un intento consumido. `--persist` guarda un informe A10 en un directorio privado; no publica A9.

## Aceptación

- 50 pruebas R122: preflight, F5, F16, F13/R121, racionales, SHA, rutas privadas, symlink, audit-replay y denegación de acciones físicas.
- Regresiones R121, R120, R119, R118, R117, R115-F13, R115-F14, R58-E, TUI R38 y R69 ejecutadas por separado.
- CI obligatorio Python/Rust + SSH R36.5 previo a merge protegido. No se habilita P8 por el hecho de que CI termine en verde.

## Brechas funcionales no resueltas

1. La admisión independiente de la procedencia física F13 (sólo digest/220 no sirve).
2. El piloto P7 calibrado y congelado por autoridad competente (el catálogo vigente es DRAFT).
3. Una versión raíz operativa sucesora con autorización independiente, revocación y guardián de cierre autónomo para una ventana acotada.
4. El flujo A6 confirmado → A7/Rf → A8 autoridad → A9 DurableStore, con prueba de caída y recuperación real.

R122 identifica y conserva estas fronteras: no las declara implementadas.
