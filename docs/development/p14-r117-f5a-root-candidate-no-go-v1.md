# R117-F5A — Candidato root reproducible

## Objetivo

Preparar un candidato root R117 verificable sin instalarlo,
ejecutarlo ni otorgarle autoridad operacional.

## Fuentes

El bundle incorpora las 33 fuentes históricas fijadas de R116,
incluido el piloto raíz transformado mediante seis sustituciones
exactas. Incorpora también los tres módulos versionados R117-F4,
el catálogo, el lock y el manifiesto.

Se exige coincidencia de SHA-256 con los locks de origen y
reproducción byte a byte del candidato. El archivo resultante
contiene 39 entradas y es determinista para un mismo HEAD.

## Seguridad

F5A no instala archivos en /var/lib/ardrec, no crea recibos
privilegiados, no inicia máquinas virtuales y no altera redes,
nftables ni temporizadores.

El ZIP candidato no debe ejecutarse como root.

F5B requiere una implementación separada de instalación
transaccional, autoridad de release independiente, validación de
dependencias realmente instaladas, recibos durables, rollback y
reconciliación ante interrupciones.

P7=DRAFT. A5 físico=NOT_ATTESTED. A6=ND. P8=NO-GO.
