# ARDREC P8 R3 — Preparación verificable, sin ejecución

## Español

**Objeto.** Este incremento examina los contratos actuales P6→P7→P8 y produce una matriz de **29 posiciones** de perfil, con su familia, variante, precedencia, operación mínima de P7, requisitos materiales, precondiciones, soportes y política de limpieza. No añade perfiles operativos y no modifica los registros históricos.

**Anclas:** `main` `29b6fcf741ff7092730a49c6d2c6d5f53b9adabb`; tesis SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`; P7 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`; P8 `fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3`. La evidencia antecedente es PR #34 y su CI de `main`; el nuevo código todavía requiere CI del nuevo head y no hereda esa evidencia como prueba de sí mismo.

**Comprobación sin acciones externas:**

```bash
python3 lab/verify_execution_profiles.py
python3 lab/verify_p8_readiness.py --format markdown
python3 -m unittest discover -s lab/tests -p test_p8_readiness.py -v
```

La verificación llama primero al validador histórico P8, que verifica fuente y correspondencia P7/P8 y se apoya en P6. Solo después construye la matriz de lectura. Los oráculos nuevos son adversariales e independientes de la lógica del verificador precedente. Una salida `0` significa únicamente **estado denegado y coherente con el baseline**: **no es autorización ni aceptación funcional**. Un cambio material del inventario provoca fallo cerrado y exige nueva versión y revisión de la procedencia; NO debe deshabilitarse el control ni editar sus anclas para «hacerlo pasar».

### Cuatro estados que no deben confundirse

| Estado | Prueba requerida | Situación de P8 R3 |
| --- | --- | --- |
| Especificado | Familia/variante y requisitos P7/P8 con bytes y vínculos comprobados | 29 posiciones declaradas |
| Materialmente vinculado | Ejecutable y auxiliares por ruta real, hash **medido**, versión, permisos, opciones específicas, argumentos tipados, directorio, entorno y destino de caso | 0 |
| Autorizado para un caso | Dueño autorizante, alcance, etapa, escenario, caso, herramienta, recursos, vigencia y revocación en registro privado auténtico | 0 |
| Habilitado para despacho | Además de lo anterior: aislamiento físico, límites efectivos, custodia AL-07, reserva del intento, integridad, limpieza planificada y supervisor P9 | 0; denegado por diseño |

Los 12 campos históricos P8 continúan a `null`. Once corresponden a insumos que deberán verificarse antes de una ejecución. El duodécimo, `cleanup_receipt_ref`, **se refiere a la constancia posterior** de una limpieza efectivamente comprobada, y no puede existir legítimamente antes de ejecutar. Se necesita **por separado** una política/plan previo de limpieza y un recibo posterior que incluya estado satisfactorio, fallido o indeterminado. Este documento no reescribe el registro P8 histórico ni fabrica el recibo.

`fixed_resource_budget` debe mantenerse pendiente hasta límites explícitos y calibrados por etapa; los máximos sintácticos del borrador Rust NO son un presupuesto autorizado. En ningún caso `ND`, `FALSO`, resultado ausente, hash autodeclarado, versión de paquete o código de salida cero habilitan una acción.

**Fuentes de tesis:** §§ 3.7.5 y 3.9.2 (páginas impresas 142–143 y 153–155): autorización y ámbito, contador finito y repetición previamente admitida, limpieza independiente, rechazo de cambios materiales, separación de aceptación/inicio/término y responsabilidad Rust sin calificar evidencia.

**Siguientes dependencias:** registrar escenarios reales de desarrollo con procedencia sin tocar piloto/experimento; derivar casos solo de esos registros; documentar candidatos de herramientas y su semántica por variante; fijar artefactos de autorización privados; añadir un revisor material que compruebe hashes **leyendo bytes**, recursos y guardas de fuentes confiables. P9 queda bloqueado. AL-06, AL-07 y siete obligaciones permanecen.

## English

P8 R3 is a **read-only, deny-only readiness inventory** for the 29 P8 slots, anchored to the exact existing P6/P7/P8 contracts. It separates specification, material binding, per-case authorization and dispatch eligibility. It never resolves binaries, spawns tools, inspects a VM, accesses credentials, alters a scenario, grants authorization or registers evidence. The 12 historical binding slots remain null; `cleanup_receipt_ref` is a **post-execution receipt**, not a pre-execution permission. Current status: 29 declared, zero materially bound, zero authorized, zero dispatchable. P9, AL-06, AL-07, the seven retained obligations, pilot and experiment remain open.
