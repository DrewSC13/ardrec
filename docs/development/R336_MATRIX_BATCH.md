# R336 — Cálculo documental nativo por lotes / Native documentary batch

## Español

El módulo `ardrec.experiments.matrix_batch` consume directamente el CSV privado
R309 (54 posiciones, sin crear una segunda matriz). Reutiliza R149/R243 para
validar la selección y R228/R232 para calcular R0, CN y las cotas prospectivas
de Rf y la recomendación A8 de cada unidad con entrada completa. Verifica los
soportes introducidos incluso en unidades incompletas; una ausencia se conserva
como pendiente, una discrepancia de bytes rechaza el lote. No imputa datos ni
convierte ND en cero. La salida es un informe reproducible de solo lectura.

Se requiere el SHA-256 esperado del CSV, fuentes nativas del registro/selección
original y soportes privados por contenido. El registro debe permanecer sin
observaciones. Los objetos se leen por unidad; no se conserva todo el corpus en
memoria. El informe no acredita semántica, cronología previa, identidad física,
congelamiento, frescura externa ni atomicidad entre lectores. El mismo UID puede
modificar fuentes después de la comprobación. No hay admisión ni despacho.

## English

The native matrix batch consumes the existing R309 private CSV and reuses R149,
R243, R228 and R232 to compute documentary R0/CN and prospective risk bounds
for complete units. Partial inputs and absent supports remain pending; mismatched
bytes reject the batch. It checks entered supports even on partial rows. No
imputation, operational authority, A6 accreditation or A9 publication occurs.
The output is read-only and deterministic. Source integrity is not factual
truth or external freshness. AL-06/AL-07 remain open; P8 remains NO-GO.
