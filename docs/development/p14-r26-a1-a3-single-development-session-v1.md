# P14-R26 · Primer paquete · sesión única A1–A3

**Base exacta:** `f42083f42bf5c2bbff66a8163276ea69e6323c0b` (PR #91).
**Tesis:** versión `Tesis ARDREC(20261114-012812).pdf`, §3.6.1, figuras 3.4–3.12.
**Alcance declarado:** subconjunto sintético A1/A2/A3 en memoria, con un evento por etapa y unidad.

## Resultado esperado, congelado antes del cálculo

El archivo `lab/p14-r26-session-v1/oracle.json` es el oráculo independiente del adaptador. Tres unidades de **desarrollo**, no observaciones experimentales:

| Unidad | Hecho lógico del fixture | A1 | A2 | A3 | Autoridad |
|---|---|---|---|---|---|
| SSH_DEV | VERDADERO | ALLOW | PREPARADO, R0=1/4 | VERDADERO | DENEGADA |
| FTP_DEV | AUSENTE | ND | PREPARADO, R0=1/4 | ND | DENEGADA |
| SMB_DEV | FALSO | DENY | PREPARADO, R0=1/4 | VERDADERO, guarda ALLOW falsa | DENEGADA |

A1 usa la tabla `ALLOW := FACT` y `DENY := NO FACT`, sin prioridad oculta. A2 prepara dos casos independientes por servicio y dos controles referenciados. Las precedencias de controles son **declarativas**, no prioridades A4; no se usa un número de precedencia como autorización. A3 evalúa ambas guardas por los contratos reales de `guard_preview.py`. Incluso SSH conserva `AUTORIDAD_OPERACIONAL_NO_ACREDITADA`. Una ausencia en FTP sigue siendo ND, no falso ni verdadero.

## Contrato de sesión (consumible en A4 y TUI)

La función `build_development_session()` reutiliza módulos R17–R22. Devuelve un `DevelopmentSession` con JSON canónico, hash de escenario normalizado, hashes de los seis artefactos de base, nueve eventos con ID estable, orden determinista y vínculo con el evento anterior. `verify_session_document()` verifica su estructura de seguridad y su integridad de enlace, **no autentica el origen de un archivo ni demuestra una observación física**.

Todos los eventos llevan `source_kind=SYNTHETIC_FIXTURE`; una entrada no puede afirmar `LIVE_VM`. No hay argumentos de red, credenciales, `subprocess`, shell, autorización operacional ni acceso a máquinas. La salida permite recorrer A1/A2/A3 en un único proceso y leer los motivos de bloqueo. `--texto` es un acta de terminal, **no la TUI viva de P26**.

Los riesgos `1/4` y la criticidad `1/2` son únicamente magnitudes didácticas del fixture. No se calcula riesgo final A7, no se persisten generaciones A9, no se despacha A5, no se acredita evidencia A6 ni se ejecuta A10. El valor `recalibrated_risk_preview` igual a R0 es un inicializador A2, no un resultado experimental ni riesgo final.

## Pruebas y trazabilidad

`lab/tests/test_p14_r26_session_a1_a3.py` contrasta cada unidad contra el oráculo; valida los hashes y la cadena, igualdad byte a byte al repetir, estabilidad frente a permutaciones, referencias A2 inválidas, JSON duplicado, intento de hacerse pasar por VM, riesgo no canónico y adulteración del reporte. Los regresivos de R21 y R25 (54 unidades sintéticas) se ejecutan por separado en el bloque de terminal.

**Cierre acotado:** el primer incremento integra tres **subconjuntos** sin otorgar semántica integral A1_FULL/A2_FULL/A3_FULL. Siguiente dependencia: A4–A6 consumirán la sesión y sus eventos; después A7–A10 publicarán, coordinadamente y solo con autorización, una generación verificable. La TUI se conectará a los eventos confirmados, no a un JSON inventado.

## Divergencia identificada antes de modificar el núcleo A1

La **figura 3.4 de la tesis vigente (página impresa 105)** describe que `DECIDIR` retorna **ND** si no hay coincidencias o existe alguna evaluación indeterminada. El `rules/kernel.py` del SHA base devuelve **FALSO** si ninguna fila coincide y no hay ND. No se modifica ese contrato transversal en este parche sin medir las regresiones: el fixture de tres servicios usa una fila explícita `DENY := NO FACT`, evitando el caso divergente. A1_FULL conserva como obligación resolver ese contraste normativo con prueba de oráculo y actualización coordinada de consumidores. En SMB la tabla selecciona DENY pero la guarda de CONTROL_POLICY continúa FALSA y sin autoridad.
