# P14-R27: A4 exacto + A5 benigno + A6 documental (alcance parcial)

**Origen:** PR #92, commit `983f4e00899223189f8b38d84e639657396e33df`.
**Referencia:** tesis `Tesis ARDREC(20261114-012812).pdf`, 3.2.6, 3.4.2, figuras 3.13–3.20.

## Qué hace software real y qué no

- `greedy_development.py` aplica la clave exacta de A4 `(-PA, prec, idServicio, idCaso)` con `Fraction`, usando pesos 1/3, y rechaza ND, FALSO, estado no PENDIENTE o caso no aplicable. Comprueba igualdad ante permutaciones.
- A4 directo sobre el estado R26 devuelve NINGUNO: las tres unidades están PREPARADO. Esto **es lo correcto** y no debe falsificarse como trabajo técnico habilitado.
- A4 sobre **proyección explícita no confirmada** de SSH_DEV produce dos alternativas empatadas con prioridad 1/4. El desempate por precedencia elige `CASE_REFERENCE`, no autoriza despacho.
- A5 usa `ardrec.benign_pipeline.BenignPipeline` ya existente para un **único fixture local** `ok`, con reserva durable, aceptación, inicio acotado, recibos SHA y replay idempotente. No se construye otro ejecutor ni se ejecutan perfiles de VM.
- A6 produce un recibo de integridad y conserva `ND` por procedencia local: **un fixture de Python no acredita condición de seguridad SSH**. Ausencia de soporte o estado ambiguo no habilita conclusión.
- Cada ejecución usa `r27.dev_tutor_001.ssh_case_reference`, fija la identidad del intento, verifica cadena y soportes y no contabiliza un segundo inicio al repetir con el mismo diario.

## Límite de aceptación

Es una **vertical de desarrollo A4–A6 parcial**, NO A4/A5/A6 completos conforme al capítulo III: no se ha confirmado una transición PENDIENTE mediante A9; las guardas de A3 aún bloquean despacho; no existe prueba en vivo en VM; A6 necesita la semántica completa de revisión, conflictos y clasificación dimensional del modelo. A7/A8/A9/A10 continúan pendientes.

La TUI futura podrá consumir el JSON de este recorrido, que preserva origen, algoritmo, decisión, intento, soporte, incertidumbre y huellas, sin mezclar con evidencia de VM.

## Entrada local (solo fixture)

`python3 -B scripts/demo_p14_r27_a4_a6_local.py --preview`

`python3 -B scripts/demo_p14_r27_a4_a6_local.py --run-local-benign --journal-root /RUTA/PRIVADA/r27-journal`

Probar dos veces con el mismo `journal-root` y comparar JSON. Una ruta nueva permite una ejecución benigna nueva (no duplicación del mismo intento). No introducir rutas de VM, credenciales, red o comandos arbitrarios.
