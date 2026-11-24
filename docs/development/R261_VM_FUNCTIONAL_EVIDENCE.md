# R261 — Integración de evidencia funcional de VM

## Alcance

Se incorpora una entrada nativa de lectura de recibos funcionales
procedentes de máquinas virtuales privadas del laboratorio piloto.

El módulo autentica los identificadores de los documentos,
contrasta los artefactos recuperados con sus huellas, vincula
familias candidatas del catálogo y reproduce el dictamen A8 nativo.

La evidencia funcional no constituye una observación experimental.
No acredita una evaluación A6 completa, riesgo confirmado,
referencia independiente I4 ni publicación operacional A9.

## Reproducción / Reproduction

    python -m ardrec estudio --evidencia-vm DIRECTORIO --artefactos-vm DIRECTORIO --sha256 IDENTIFICADOR --texto

Los recibos y artefactos privados permanecen fuera de Git.

## Pruebas / Tests

Ocho casos sintéticos verifican reproducción, integridad,
duplicación, alcance y conservación de ND.

P7 permanece DRAFT_NOT_FROZEN y P8 permanece NO-GO.
