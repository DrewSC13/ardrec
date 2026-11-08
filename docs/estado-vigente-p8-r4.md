# ARDREC — Estado de trabajo de P8-R4 (propuesta no integrada)

**ES.** La última base integrada comprobada de `main` es
`5855ac8956b1672c698919e3c8c87b2cfa1c1823` (PR #35, P8-R3).
Este documento acompaña un **incremento fuente propuesto** y **no** constituye
resultado de CI ni prueba física hasta su comprobación y eventual integración.

- **P1–P7:** conservar los cierres parciales documentados y sus exclusiones.
- **P8-R1/R2/R3:** existen 29 posiciones bloqueadas, una compuerta Rust deny-only
  y una matriz de lectura; el PR #35 pasó CI de `main` y fue integrado.
- **P8-R4 propuesto:** contrato versionado por caso y pruebas sintéticas de
  identidad, enlace de etapa/familia/variante, captura, limpieza, presupuesto y
  ciclo de autorización. **No** crea perfiles ejecutables ni permisos.
- **Inventario real:** 0 escenarios P6, 0 casos derivados reales, 0 binarios
  fijados, 0 perfiles autorizados, 0 despachos y 0 unidades experimentales
  congeladas. La muestra prevista de 54 unidades **no** es un inventario real.
- **Dependencias abiertas:** AL-06, AL-07 y siete obligaciones. Para ligar
  perfiles reales: primero escenario de desarrollo y evidencia de alcance,
  después derivación P7, identidad de artefactos AL-07, autorización privada,
  presupuesto seguro y validación de aislamiento. No inferir cierres por este
  contrato de propósito limitado.
- **P9–P46:** continúan en el orden fijado. No atribuir a este incremento
  supervisión de procesos, piloto, congelamiento de muestras ni A1–A10.

**EN.** This is a proposed source-only, deny-only P8-R4 case-binding and
private-authorization grammar, based on merged P8-R3. All operational, physical,
experimental and mathematical verification dependencies remain outstanding.
