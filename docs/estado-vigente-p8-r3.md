# ARDREC — Estado verificable al 8 de noviembre de 2026

## Español

La información de arranque en `README.md`, `docs/pendientes.md` y `docs/entorno.md` pertenece a la línea base inicial. **No debe leerse como el inventario actual**, ni debe borrarse retrospectivamente para reescribir la historia.

**Repositorio contrastado:** `DrewSC13/ardrec`, rama `main`, commit `29b6fcf741ff7092730a49c6d2c6d5f53b9adabb`; PR #34 integrado el 7 de noviembre de 2026; verificación GitHub de la firma del merge: `valid`. CI de `main` para ese SHA: [run 42412712719](https://github.com/DrewSC13/ardrec/actions/runs/42412712719), éxito según la evidencia de continuidad. Estas afirmaciones describen ese corte; **no certifican** código posterior ni equipos físicos.

**Fuentes:** tesis PDF SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, §§ 3.7.5 y 3.9.2; P6 PR #31; P7 PR #32; P8 PR #33 y #34. Este incremento P8 R3 tiene que superar pruebas propias y su nueva CI; no se da por integrado por generarse el parche.

| Punto | Alcance documentado | Obligación que permanece |
|---|---|---|
| P1 | Revisión y obligaciones registradas | Alineación funcional global |
| P2 | Matriz de trazabilidad | Cumplimiento de cada requisito |
| P3 | Diseño del laboratorio | Verificación de despliegues no cubiertos |
| P4 | Servicios de desarrollo registrados | Prototipo A1–A10 |
| P5 | Restauración/aislamiento acotados en desarrollo | Runner, corte de energía, piloto y experimento |
| P6 | Contratos de etapas y procedencia | Escenarios reales (0 registrados) |
| P7 | 25 familias operacionales | Casos derivados reales (0) |
| P8 | 29 plantillas y Rust deny-only; R3 añade matriz de preparación | Binarios/referencias/materiales/permiso, despacho denegado |
| P9–P46 | Pendientes en su orden, sin alterar dependencias | Implementación, piloto, 54 unidades, estadística, defensa |

**Pendientes transversales:** AL-06, AL-07, custodia de frescura de `expected_head`, comportamiento ante pérdida física de energía, AL04-R01/R02/R03, siete obligaciones de desarrollo. Una firma o CI exitosa no valida la hipótesis; ninguna prueba sintética acredita una autorización operacional.

**Prueba local de P8 R3:** `python3 lab/verify_p8_readiness.py --format markdown` y `python3 -m unittest discover -s lab/tests -p test_p8_readiness.py -v`. El comando emite una **matriz de requisitos**, no una lista de comandos ejecutables. El hecho de generar la matriz no significa que haya escenarios, autorizaciones o acciones físicas registradas.

## English

The original README and pending-items files are historical bootstrap documentation, not the current inventory. As of 8 Nov 2026, `main` is `29b6fcf741ff7092730a49c6d2c6d5f53b9adabb` after merged PR #34. P1–P7 have bounded, explicitly documented accomplishments; P8 has 29 unbound profile slots and a Rust deny-only validator. P8 R3 adds a read-only readiness inventory, not real binaries, authorization, dispatch or system acceptance. Steps P9–P46 retain their order. AL-06, AL-07, seven residual obligations and experimental validation remain open.
