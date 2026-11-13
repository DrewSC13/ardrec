# P14-R22 — Diagnóstico trivalente de guardas, enlace inicial hacia A3

**Base inmutable:** `8c3cf450de9523411d543149af3744074dc16db7` (PR #87).
**Alcance:** componente puro de análisis sintético, no planificación ejecutable ni control A3 completo.

## Propósito

R17–R21 proveen reglas A1, estado inicial A2, grafos locales, referencias de
controles y un contrato integrado de solo lectura. R22 calcula, por unidad,
la decisión A1 de su tabla (`VERDADERO`, `FALSO`, `ND`) bajo un ambiente
**sintético proporcionado por el llamador**. Reutiliza directamente `decide`
del núcleo A1, en lugar de implementar otra lógica booleana.

El diagnóstico conserva la identidad de los controles, la regla declarada,
el caso objetivo, los valores trivalentes y las razones de bloqueo. Una tabla
ambigua se rechaza. La incertidumbre ND nunca se traduce en permiso.

Los casos sin dependencias declaradas son **estructuralmente libres**, no
casos ejecutables. Las dependencias de casos no están confirmadas, y las de
controles no se han aplicado. Aunque una guarda resulte VERDADERO, todos
los controles incluyen el bloqueo `AUTORIDAD_OPERACIONAL_NO_ACREDITADA`.

## Semántica y límites

- Entradas exactas R17–R21 y un ambiente por cada servicio del contrato.
- Tipos de hechos heredados de A1: `Truth`, `Fraction` y `str`; se rechazan
  coerciones (incluidos `bool` en vez de `Truth` y números flotantes).
- Sin hechos presentes se obtiene ND cuando la regla necesita ese campo.
- Se rechazan varias reglas verdaderas y se conserva ND cuando no puede
  certificarse una elección única.
- Resultado JSON canónico y SHA-256 con dominio explícito para los campos.
- Hasta 64 servicios y 393.216 bytes en el documento de diagnóstico.
- Ninguna lectura de red, variables de entorno, archivos del host, ejecutores
  Rust, credenciales o comandos; ningún permiso A3/P8 es concedido.

## Reproducibilidad y pruebas

`lab/tests/test_p14_r22_a3_guard_preview.py` verifica casos verdaderos,
falsos, ND, tabla ambigua, dependencias no acreditadas, tipos, identidad de
fuentes, inmutabilidad, orden estable y adulteración del JSON. El ejemplo
`scripts/demo_p14_r22_a3_guard_preview.py` genera 54 unidades sintéticas,
108 casos y 108 controles: 18 tablas verdaderas, 18 falsas y 18 ND.

La CI ejecuta la prueba unitaria dirigida y la demostración sintética.
El laboratorio completo y el ejecutor Rust se comprobarán en Prometheus.

## Trabajo no cubierto

**A1_FULL=NOT_CLOSED, A2_FULL=NOT_CLOSED, A3_FULL=NOT_CLOSED.**
El diagnóstico no decide elegibilidad real, autoridad, prioridades, consumo,
criterios de control, disponibilidad técnica ni planificación efectiva de
A3. Tampoco publica generación A9, ejecuta las 54 unidades físicas,
valida AL-06/AL-07 ni convierte resultados simbólicos en evidencias.
**P8_OPERATIONAL=NO-GO.**
