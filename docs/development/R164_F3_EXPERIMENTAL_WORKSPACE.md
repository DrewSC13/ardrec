# ARDREC R164-F3 — Integración experimental R148/R149

## Propósito

Vincular un nuevo espacio privado R148/R149 al commit firmado de R164,
manteniendo intactos los instrumentos, registros y lanzadores históricos.

El expediente contiene 54 posiciones inicialmente sin asignar, 18 SSH,
18 FTP y 18 SMB, y la propuesta de cobertura de 25 familias.
No contiene casos físicos acreditados, estimaciones definitivas ni
autorizaciones operacionales.

## Estructura

- `register/`: protocolo y registro R148, sellados.
- `selection/`: plan y lista de familias R149; CSV de trabajo editable.
- `manifest.json`: vinculación entre fuentes Git, catálogo y documentos.

El manifiesto NO funciona como firma de autoridad independiente.
Los hashes son referencias de integridad, no testimonios de observación.

## Límites

P7 permanece `DRAFT_NOT_FROZEN`, P8 `NO-GO`, A6 `ND`,
A9 `NOT_PUBLISHED`; 0 resultados físicos verificados.

`--prepare` requiere una carpeta nueva y no sobrescribe.
`--audit` relee el expediente y valida que el commit de creación
sea antecesor firmado del HEAD actual, y que sus objetos no deriven.

No actualizar registros antiguos para que coincidan artificialmente
con el HEAD de R164. Una selección CSV completa sigue siendo
`CANDIDATE_COMPLETE_UNVERIFIED`, no resultado de tesis.

## Pruebas

`PYTHONPATH=src:scripts python3 -B -m unittest discover -s lab/tests -p 'test_p14_r164_f3_workspace.py' -v`

Todas las operaciones son offline, no-root y sin activación B4/B9.
