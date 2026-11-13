# ARDREC — R16 / A1: núcleo tipado, versión 1 (solo desarrollo)

**Base Git exigida:** `53d8c01f26bbaab6de3e3a23662bffc5322d8568` (merge firmado PR #81). **Ámbito:** primera implementación de componentes de A1; no certifica A1 integral, A2–A10, criterio de aceptación AC-06 ni P8 operacional.

## Correspondencia con la tesis

La sección 3.3.2 de la tesis ARDREC de noviembre de 2026 declara expresiones tipadas, constantes, campos autorizados, operadores lógicos y relaciones compatibles; distingue `VERDADERO`, `FALSO`, `ND` y habilita solo con `VERDADERO`. Las figuras 3.4 y 3.5 distinguen `DECIDIR` de `EVALUAR`. **Este incremento implementa un subconjunto controlado de esa frontera**, sin interpretar resultados como comprobaciones técnicas.

### Contrato implementado

- `EVALUAR`: `CONSTANTE`, `CAMPO`, `NO`, `Y`, `O` y `COMPARAR`; tipos `LOGICO`, `RACIONAL` y `TEXTO`. Las relaciones ordenadas solo admiten racionales exactos.
- `DECIDIR`: filas con identidad única y condición lógica, compilación y validación de TODAS las filas antes de decidir, resultados y observaciones deterministas. Varias filas verdaderas producen `reglas_ambiguas`; si una fila es ND, no se acredita elección única; todas falsas retornan `FALSO`.
- `ND` en campos declarados pero ausentes no se convierte en cero, texto vacío ni `FALSO`. No se acepta ninguna referencia de campo fuera del esquema explícito.
- Operadores desconocidos, aridades incorrectas, tipos incompatibles, fracciones no canónicas, ciclos y expresiones excesivas fallan cerradamente.
- `Y` y `O` aplican lógica trivalente fuerte: `FALSO Y ND = FALSO`, `VERDADERO O ND = VERDADERO`; ninguna salida distinta de `VERDADERO` habilita una guarda.
- Ninguna entrada permite `argv`, shell, red, perfiles P8, ejecución Rust, modificación de estados ni publicación de generaciones.

**Decisión por validar antes de dar A1 por cerrado:** las combinaciones `ND` en tablas de decisión, precedencia y cualquier `resultado` derivado de la tabla deberán contrastarse con el pseudocódigo final de la tesis. Esta versión usa rechazo conservador de ambigüedades, **no afirma identidad semántica integral**. El contrato operativo A1 deberá integrar los dominios/operadores exactos de cada regla de A2/A3/A4/A6/A8, referencias y errores de la especificación completa. Esta entrega no sustituye el diagrama ni el pseudocódigo del capítulo III.

## Reproducibilidad

```sh
python3 -B -m unittest discover -s lab/tests -p test_p14_r16_a1_kernel.py -v
python3 -B scripts/demo_p14_r16_a1.py
python3 -B scripts/verificar_trazabilidad_actual.py
```

**Criterio actual:** componente probado en CI y Prometheus, si sus pruebas pasan; `A1=PARTIAL_COMPONENT`, `AC-06=PENDING`, `P8_OPERATIONAL=NO-GO`, `AL-06/AL-07=OPEN`, `SYSTEM_ACCEPTANCE=PENDING`, `EXPERIMENTAL_VALIDATION=NOT_RUN`.

## English summary

R16 implements a pure, strictly typed three-valued A1 rule kernel and an unambiguous decision-table subset. It never dispatches a process, writes global state, or grants operational P8 authority. A1 remains partial pending full thesis-level semantic reconciliation and integrated acceptance.
