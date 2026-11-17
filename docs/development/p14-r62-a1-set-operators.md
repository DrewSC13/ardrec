# P14-R62 — A1 conjuntos tipados, salida R26 e invariantes de decisión

**Tesis:** ARDREC, 17-11-2026, SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.
§3.6.1, figuras 3.4–3.5; páginas impresas 105–106 (PDF 120–121).

## Requisito normativo y decisión de representación

La figura 3.5 incluye `PERTENECE` (∈) y `SUBCONJUNTO` (⊆). El núcleo vigente R61
solo implementaba seis relaciones y carecía de un dominio para conjuntos.
R62 incorpora **dos representaciones de ingeniería**, no formatos expresamente
prescritos por la figura:

- `CONJUNTO_TEXTO`: lista JSON de cadenas no vacías, ordenadas lexicográficamente,
  sin duplicados y con máximo 64 elementos; al evaluar se convierte a `frozenset[str]`.
- `CONJUNTO_RACIONAL`: lista JSON de racionales canónicos, ordenados
  lexicográficamente por representación, sin duplicados y con máximo 64 elementos;
  al evaluar se convierte a `frozenset[Fraction]`.
- Un campo de conjunto en el ambiente admite exclusivamente un `frozenset` del tipo
  declarado. Un campo no suministrado da `ND`; **el conjunto vacío conocido no es `ND`**.
- `PERTENECE` exige un elemento `TEXTO` o `RACIONAL` y un conjunto compatible.
  `SUBCONJUNTO` exige dos conjuntos con el mismo tipo de elemento.
- Se admite `IGUAL`/`DISTINTO` entre conjuntos del mismo dominio. Las relaciones
  de orden siguen restringidas a racionales escalares.
- Entrada incorrecta, coerción implícita, colección mutable, duplicados,
  tipo incompatible y tamaño excesivo se rechazan antes de decidir.

## Propagación hacia la sesión existente

La ruta R26 usa los módulos reales A1 → A2 → A3 en **modo sintético**. Las dos
filas A1 declaran ahora salidas `CASE_POLICY` y `CASE_REFERENCE`; la sesión
conserva el resultado en A1, A3 y en los eventos enlazados. La igualdad de
ambas proyecciones es una condición obligatoria del constructor y verificador.
Esto no elige una ejecución ni convierte la etiqueta declarativa en un permiso.

## Aceptación y límites

Oráculo nuevo: `lab/tests/test_p14_r62_a1_set_and_session.py`.
Regresiones: R16/R17/R18/R22/R26/R61 y las demostraciones vinculadas.
La prueba integrada R26 conserva `p8_operational=NO-GO`, `published_generation=None`
y `final_risk=None`.

Este incremento **no declara A1 al 100 %** hasta registrar la matriz de criterios,
verificar la suite completa sobre el nuevo SHA y comprobar integración en `main`.
No habilita los tres servicios físicos ni acredita las 54 unidades experimentales.

**EN.** Adds the two set operators explicitly shown in thesis Figure 3.5, with
bounded and typed immutable sets, ND propagation, negative type checks, and
an independent oracle. Propagates the declared winner output into the synthetic
R26 A1-A3 session and its event chain, without operational authorization.

## R62-R3 — Compatibilidad real de la fuente R26/R58-P

R58-P reconstruye las mismas reglas A1 que R26 al enlazar los 29 casos
sintéticos de las 25 familias. Las reglas `ALLOW` y `DENY` deben incluir
respectivamente `CASE_POLICY` y `CASE_REFERENCE`, con fuente canónica
idéntica en ambos módulos. No se omite la guarda
`R26_RULE_SOURCE_MISMATCH`; se refuerza además el cotejo de `table_output`.
Oráculo: `test_p14_r62_r3_r58p_binding.py` sobre el catálogo fijado.
P8 continúa en `NO-GO`.

**EN.** Restore exact shared R26/R58-P declarative rule-source identity,
verify output parity and reject drift, with no operational authority.
