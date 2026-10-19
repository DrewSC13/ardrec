# Contratos numéricos / Numeric contracts

## Español

### Fuente y alcance

Se implementan las magnitudes de la sección 3.9.4 de
TESIS ARDREC, páginas impresas 112–114.
SHA-256 del documento consultado:
`da959bd6ab8eb49df5c746f2bfc50df2633794a2c089a2a757ffc65ca39ae9ce`.

Este incremento proporciona validación y serialización en Python.
No implementa todavía A1–A10 ni el transporte entre Python y Rust.

### Decisión

- Los racionales recibidos contienen únicamente `numerator` y `denominator`.
- Ambos deben ser enteros exactos; los booleanos quedan excluidos.
- El denominador es positivo y la fracción está reducida.
- La única representación admitida del cero es `0/1`.
- Las entradas no canónicas se rechazan; no se corrigen silenciosamente.
- La aritmética utiliza `fractions.Fraction`.
- Una magnitud determinada usa `status: DETERMINADO` y `value`.
- Una magnitud no determinada usa `status: ND` y `reason_code`.
- `null` no representa ND y ND no se convierte en cero.
- El decodificador rechaza claves duplicadas, decimales, exponentes
  numéricos, NaN, Infinity y contenido adicional.
- La salida JSON tiene orden estable de claves y separadores compactos.
  No se declara conformidad con un estándar externo de JSON canónico.

### Límites iniciales de implementación

Se permiten hasta 256 bits de magnitud por entero y 4096 bytes por
documento JSON de una magnitud. Los códigos de motivo cumplen
`[A-Z][A-Z0-9_]{0,63}`; esto valida su sintaxis, no su admisibilidad
para una regla de dominio particular.

Estos límites son decisiones iniciales del software, no valores
prescritos por la tesis. Deben revisarse al implementar la contraparte
Rust y evaluar los tamaños reales. El límite de 4096 bytes no establece
el límite de las futuras tramas del protocolo completo.

Los cálculos internos pueden producir fracciones mayores; su exportación
falla explícitamente si excede el contrato, sin redondear ni truncar.

### Verificación

La suite contiene 12 pruebas y recorre 820 combinaciones de
numerador/denominador para comprobar ida y vuelta.
Incluye aritmética exacta, tipos inválidos, cero, signos, reducción,
límites, variantes ND y entradas JSON ambiguas o malformadas.

CI ejecuta la suite como un paso independiente del empaquetado.
Los registros históricos del empaquetado conservan su alcance original.
Estas pruebas no acreditan validación experimental de ARDREC.

## English

### Source and scope

This increment implements the magnitudes described in section 3.9.4 of
TESIS ARDREC, printed pages 112–114.
The consulted document's SHA-256 is:
`da959bd6ab8eb49df5c746f2bfc50df2633794a2c089a2a757ffc65ca39ae9ce`.

It provides Python validation and serialization.
A1–A10 and the Python–Rust transport remain unimplemented.

### Decision

- Incoming rationals contain only `numerator` and `denominator`.
- Both must be exact integers; booleans are excluded.
- The denominator is positive and the fraction is reduced.
- Zero has exactly one representation: `0/1`.
- Noncanonical input is rejected rather than silently corrected.
- Arithmetic uses `fractions.Fraction`.
- Determined magnitudes use `status: DETERMINADO` and `value`.
- Undetermined magnitudes use `status: ND` and `reason_code`.
- `null` does not represent ND, and ND is not converted to zero.
- The decoder rejects duplicate keys, decimal and exponent numbers,
  NaN, Infinity and trailing content.
- JSON output uses stable key ordering and compact separators.
  Compliance with an external canonical JSON standard is not claimed.

### Initial implementation limits

Integers allow up to 256 magnitude bits; one magnitude JSON document
allows up to 4096 bytes. Reason codes match `[A-Z][A-Z0-9_]{0,63}`.
This checks syntax, not admissibility under a particular domain rule.

These are initial software decisions, not thesis-prescribed values.
They require review when implementing the Rust counterpart and
evaluating actual sizes. The 4096-byte limit does not define the
future full-protocol frame limit.

Internal calculations may produce larger fractions; export fails
explicitly when the contract limit is exceeded, without rounding
or truncation.

### Verification

The suite contains 12 tests and exercises 820 numerator/denominator
combinations for round-trip verification.
It covers exact arithmetic, invalid types, zero, signs, reduction,
limits, ND variants and ambiguous or malformed JSON input.

CI runs this suite separately from packaging.
Historical packaging records retain their original scope.
These tests do not establish experimental validation of ARDREC.
