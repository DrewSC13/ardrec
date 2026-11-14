# P14-R23 — Orden de candidatos A3 sin agenda ejecutable

**Base exacta:** `9422d418e4d7ddcb931ae3f1bac856daf3d4c5ae` (PR #88).
**Alcance:** simulación de orden de controles A3 sobre R17–R22, sin despacho P8.

## Función y semántica

R23 compone la instantánea de contrato A2-R21 y el diagnóstico A3-R22, y **revalida**
la cadena de seis fuentes al calcular el orden. Una condición verdadera no autoriza
una acción: solo da lugar a un candidato **condicional y no ejecutable** cuando la
tabla A1 acredita una única regla y todos sus controles predecesores también
pertenecen a la propuesta.

- El orden local procede de las dependencias y precedencias R20 (Kahn); el
  recorrido entre servicios utiliza orden ascendente de ID, **sin prioridad global**.
- Las guardas FALSO/ND y las tablas no acreditadas se excluyen. Si falta un control
  exigido por otro, el segundo se excluye, aunque su guarda sea verdadera.
- Los límites enteros exactos `max_per_service` (0–32) y `max_total` (0–2048)
  acotan la propuesta. Se rechazan booleanos, floats, negativos y desbordamientos.
- Para cada candidato se conservan `pending_controls`, `pending_cases` y
  `AUTORIDAD_OPERACIONAL_NO_ACREDITADA`. Una referencia en el orden **no prueba**
  aplicación de control, inicio ni terminación de caso, ni verificación de evidencia.
- La huella SHA-256 describe el registro JSON canónico, no firma de autoridad ni
  publicación A9. La recomputación y verificación exige las fuentes y ambientes
  originales; no basta con reemplazar una huella por otra.

## Demostración y regresión

`lab/tests/test_p14_r23_a3_candidate_order.py` incluye negativos y límites;
`scripts/demo_p14_r23_a3_candidate_order.py` ejecuta 54 servicios sintéticos:
18 SSH, 18 FTP, 18 SMB; dos casos y dos controles por servicio. Distribuye
18 tablas verdaderas, 18 falsas y 18 ND; produce 36 candidatos condicionales,
72 controles excluidos, 0 comandos ejecutables y 0 generaciones publicadas.

La CI agrega las pruebas R23 y la demostración; no abre conexiones a invitados,
no invoca SSH/FTP/SMB y no acredita capacidades P8.

## Límites no resueltos

**A1_FULL=NOT_CLOSED; A2_FULL=NOT_CLOSED; A3_FULL=NOT_CLOSED.**
`P8_OPERATIONAL=NO-GO`; casos autorizados=0. La salida de R23 **no es** agenda
operativa: faltan estado confirmado, evidencia y consumo de controles, autoridad
P8, ventanas, aceptación de dependencias interservicio, restricciones de tiempo,
criterios de elegibilidad A3 completos, planificación/selección A4 y escenarios
físicos del catálogo. Los 54 registros son ficticios, no el experimento de tesis.
