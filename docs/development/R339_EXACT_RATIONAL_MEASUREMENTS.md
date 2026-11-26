# R339 — Mediciones racionales exactas / Exact rational measurements

## Español

La línea base ordinal de la tesis utiliza racionales exactos. R148/R149
aceptaban únicamente decimales, por lo que un valor como 1/3 debía rechazarse
o aproximarse antes del contraste. Una aproximación podría modificar los
empates, los ceros o los rangos de las diferencias.

Se amplía la entrada de mediciones de R148, R149, I2 y el resumen R184/I8
para admitir fracciones no negativas reducidas `numerador/denominador`, en
[0,1], con componentes de hasta 24 dígitos. Se conservan las reglas anteriores
para decimales y los límites de la escala común. No se introduce redondeo en
el cálculo de errores, diferencias ni rangos. El modo mixto usa Fraction;
la media descriptiva textual de R148 conserva su presentación decimal de
28 cifras significativas, mientras R184/I8 conserva medias racionales.
Se mantienen los formatos y resultados de los registros exclusivamente
decimales; tres ejemplos se comprobaron por huella completa de informes.

Doce pruebas nuevas cubren las 125 ternas ordinales, empates, diferencias
cercanas, 54 pares sintéticos, formato inválido, contexto decimal ambiental,
I2, I8 y R336. Son regresiones de software, no observaciones. No se elige el
comparador principal, no se congela P7 ni se completa la matriz. No se
modifican los soportes, la evidencia ni la autoridad operacional. AL-06 y
AL-07 continúan abiertos; P8 permanece NO-GO.

## English

R148/R149 and I2/R184/I8 now accept bounded, reduced normalized rational
measurement strings in addition to legacy decimals. Mixed records preserve
exact errors, differences and tie-aware ranks. Only R148 descriptive mean
presentation is rounded; R184/I8 retains exact rational summaries. The
original decimal-only report format and legacy hashes are preserved. The
24-digit component bound is an implementation decision, not a thesis scale
change. Oversized fractions are rejected rather than silently rounded.
Synthetic regressions do not establish physical observations or experimental
admission. The comparator and freeze require methodological approval;
AL-06/AL-07 remain open and P8 remains NO-GO.
