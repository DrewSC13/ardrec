# P14-R24 — Previsualización de elegibilidad hipotética A3

**Base exacta:** `32720edc1648e8b3e7262c2dfa374cfe90fe6676` (PR #89).
**Alcance:** desarrollo sintético de solo lectura; ningún efecto operacional.

## Objetivo

R16–R23 producen reglas tipadas A1, cuatro contratos A2, diagnóstico
trivalente A3 y un orden no ejecutable de controles candidatos. R24 añade
una función **what-if** para contrastar ese orden con *suposiciones declaradas*
de prerrequisitos, sin modificarlo ni crear candidatos nuevos.

Cada servicio declara exactamente una marca hipotética `ND`, `FALSO` o
`VERDADERO` para cada caso y cada control. Son **marcas ficticias**: no son
resultados de un ejecutor, evidencia, hechos acreditados, confirmación de
consumo, generación publicada ni autorización. El esquema rechaza campos
adicionales de comando, permiso o despacho.

Para cada candidato de R23, la evaluación R24 produce:

- `LISTO_CONDICIONAL`: bajo esas suposiciones, sus dependencias figuran como
  satisfechas; **no está habilitado para ejecutar**.
- `BLOQUEADO`: algún caso/control requerido tiene marca FALSO o ND.
- `OMITIDO_SUPUESTO`: la hipótesis dice que el propio control o su caso objetivo
  ya estaría satisfecho; **no acredita que realmente ocurrió**.

Las exclusiones de R23 se conservan sin resucitar candidatos. El orden de R23
permanece estable. Las suposiciones VERDADERO deben respetar las dependencias
locales transitivas declaradas; se rechazan declaraciones inconsistentes.

## Contrato e integridad

- Campos exactos, tamaños acotados, tipos estrictos y conjunto completo de IDs
  locales; no se permiten servicios/casos/controles ajenos, duplicados ni parciales.
- Serialización canónica ordenada con huella SHA-256 del escenario y del informe.
- La verificación vuelve a recorrer R17–R23 y reconstruye todo el resultado.
- Los objetos de salida son inmutables y no conservan referencias mutables del
  usuario; permutar servicios y marcas no cambia las huellas.
- No hay llamadas a red, subprocess, sockets, API del ejecutor, escritura
  operativa, agenda real, firma de autorización ni vinculación P8.

## Pruebas

- `lab/tests/test_p14_r24_a3_readiness_preview.py`: pruebas de casos positivos,
  negativos y adversariales, integridad, procedencia, contradicciones, ND,
  duplicados y prohibición de permisos.
- `scripts/demo_p14_r24_a3_readiness_preview.py`: 54 servicios sintéticos,
  18 SSH, 18 FTP y 18 SMB. De 36 candidatos R23 se obtienen 18 condicionalmente
  listos, nueve bloqueados y nueve omitidos por supuestos; se mantienen las
  72 exclusiones de R23.
- Los oráculos anteriores no sustituyen las pruebas completas en Prometheus,
  las pruebas de contrato P8 ni la validación experimental física.

## Pendientes

**A1_FULL=NOT_CLOSED; A2_FULL=NOT_CLOSED; A3_FULL=NOT_CLOSED.**
**P8_OPERATIONAL=NO-GO.** Ningún control queda autorizado o aplicado.

Faltan hechos con procedencia acreditada, frescura y custodia, control de
consumo real, ventanas y presupuestos operacionales, guardas con fuente
confiable, política de capacidades AL-07, publicación transaccional A9,
integración completa A1–A10 y evaluación experimental.
