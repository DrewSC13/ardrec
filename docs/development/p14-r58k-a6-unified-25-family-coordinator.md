# ARDREC P14 · R58-K — Coordinación A6 de SSH/FTP/SMB con A7 y A8

**Base exacta:** `main` integrado desde PR #142: `e92c5e5fb896b3298e017a09bf34e547b66a9fef`.
**Fuente:** catálogo P7 `lab/operational-catalog-v1/catalog.json`, SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`; tesis SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

## Alcance de la implementación

Se introduce `build_unified_preview` y `verify_unified_preview`, un **coordinador offline sintético**, que integra los evaluadores de las **25 familias** definidos en R58-H (SSH 8), R58-I (FTP 8) y R58-J (SMB 9). El demo contiene 29 casos sintéticos: SSH 8, FTP 10, SMB 11 por las variantes independientes. Una muestra real de 54 unidades no se infiere de este fixture ni se da por ejecutada. El lote admite 1 a 54 identidades de evaluación distintas, incluso subconjuntos que no cubran todos los protocolos.

El contrato de cada elemento exige `service_id`, `unit` con el formato exacto del evaluador original, y `risk` con únicamente `initial_risk`, `normalized_criticality`, `replacement_risk`. No se admite un campo de evidencia del llamador. Los resultados trivalentes y las seis clases técnicas **son hipotéticos**, incluso cuando indiquen `POSITIVO_VALIDO` o `NEGATIVO_VALIDO`.

El identificador de caso derivado `SSH-T01-S01-01` (y sus equivalentes) contiene guiones que el núcleo matemático R58-D no acepta. El coordinador crea una identidad técnica para A7 de la forma `CASE_` + 48 dígitos hexadecimales de SHA-256 con separación de dominio y asociación a servicio, sesión, caso derivado e índice de evaluación. Se conservan ambas identidades, se rechazan duplicados y no se mezclan sesiones ni variantes. No se modifican los IDs académicos originales.

El coordinador vincula cada caso evaluado con R58-E, que delega en R58-D el cálculo matemático de las cotas de riesgo y en A8 la recomendación conservadora de pausa. **Todas** las contribuciones permanecen `UNRESOLVED [0,1]` porque la clasificación sintética no acredita el estado técnico del servicio. `A6=ND`, `technical_truth_accredited=false`, `confirmed_final_risk=null`, `published_generation=null`, ninguna transición ni despacho operativo. `P8=NO-GO`, `R34 DENY` y F11 sin activación física se preservan.

R58-K **no integra testigos R58-F/G como evidencia técnica**, no incorpora nuevas familias de explotación, no dispara operaciones SSH/FTP/SMB ni autoriza ensayos. El pin del catálogo acredita integridad relativa a bytes fijados, no independencia de observador, procedencia física ni verdad del resultado declarado. Tampoco completa los diez bloques A1–A10: es una integración **A6–A7–A8 sintética** con exclusión explícita de A9.

## Pruebas

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58k_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58k_unified_family_demo.py --synthetic-offline
```

Se incluyen pruebas adversariales de límites de lote, duplicidad global, identidad por protocolo/sesión/variante, sobrescritura de credenciales/riesgos, entradas con contribuciones inventadas, valores fuera del dominio, modificación de informes con nuevo hash, integridad del catálogo original, alcance de A7, preservación de A8 y ausencia de publicación. En un checkout con catálogo completo, el demo usa exclusivamente el catálogo real fijado.

## English summary

R58-K joins the three existing synthetic family evaluators into one deterministic, source-only A6 coordination layer, binds all case-windows via domain-separated collision-guarded identifiers to R58-E exact unresolved A7 intervals and conservative A8 stop recommendations. No trust, evidence, VM operation, risk confirmation, A9 publication or state transition is promoted. Full functional or experimental acceptance is **not claimed**.
