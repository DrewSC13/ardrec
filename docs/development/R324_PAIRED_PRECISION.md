# R324 — Precisión del análisis pareado / Paired precision

## Español

R148 calculaba errores y rangos absolutos en el contexto decimal ambiental.
Dos magnitudes diferentes podían quedar empatadas y una resta de errores
previamente redondeados podía perder una diferencia real. Se conserva el
motor original, la dirección de contraste y el algoritmo de signos exacto.
El contexto de cálculo se fija en 80 dígitos, con 28 para la presentación
de medias descriptivas y 60 para la representación decimal de p. La
magnitud de cada diferencia usa copy_abs, sin redondear. Se rechazan
exponentes fuera de [-48, 12]; el límite inferior coincide con R184.
R184 usa un contexto propio de 128 dígitos. No cambian los registros
originales ni sus sellos. Una salida estadística regenerada puede cambiar
si antes dependía del contexto decimal o si p necesitaba más de 45 dígitos.
Los informes históricos se conservan, no se sobrescriben.

No se acreditan observaciones, referencia independiente, P7, P8, AL-06
ni AL-07. No se ejecutan operaciones de red. Las pruebas usan fixtures.

## English

R148 now isolates its arithmetic from ambient decimal settings, preserves
exact absolute differences for ranking, bounds decimal exponents and
represents the exact sign-flip probability for up to 54 pairs. R184 uses
an explicit context. Historical records are unchanged; regenerated reports
may differ. No experimental or operational authority is created.
