# ARDREC R84 — Matriz de preparación funcional DEV A5–A8

**Base exacta:** `3654dbfb5d0491749868240c20c06a88c1084239` (merge R83). **Alcance:** exclusivamente *software DEV sintético*, sin ejecución física ni habilitación P8. Este incremento agrupa vinculación exacta A5, revisión conservadora A6, intervalos racionales A7, denegación A8 y criterios de aceptación DEV.

## Objetivo funcional

La conciliación R83 cubre 25 familias del catálogo frente a 29 variantes de la máquina de estados R58, pero no acredita que sean las mismas observaciones. R84 crea una decisión tipada para **cada uno de los 25 intentos R76**, usando los campos inmutables `(session_id, service_id, derived_case_id, assessment_index, attempt_id)`, el hash de la intención y el enlace al caso A7. Rechaza duplicados y relaciones incompatibles. La pertenencia a una misma familia de catálogo solo permite un vínculo **de cobertura**, nunca una unión experimental ni una transición válida.

Los tres resultados declarados R76 son no verificados; las otras 22 entradas son `NO_START`. A6 es `NOT_ADMITTED/ND` en las 25, y cualquier declaración de verdad técnica, riesgo confirmado o autorización operativa se rechaza. R84 verifica aritmética racional y monotonicidad `0 ≤ E0 ≤ Ehalf ≤ E1 ≤ 1` sobre los tres puntos contrafactuales R78; los intervalos permanecen **sin resolver**. A8 retiene los 29 rechazos documentados del modelo R58-S, sin transferir estados de las 29 variantes a los 25 intentos. A9 no crea otra generación y A10 sigue reproduciéndose desde R81.

## Criterios de aceptación delimitados

La matriz emite **13 criterios `PASS_DEV_CONTRACT_ONLY`**, que demuestran coherencia del software mediante verificadores previos, e **6 criterios `PENDING_EXTERNAL_ATTESTATION`**. No se informa aceptación funcional total `PASS`; se conserva `system_functional_acceptance=PENDING`, `experimental_validation=NOT_RUN`, `A6=ND`, `Rf=null`, `P8=NO-GO`. Los criterios externos incluyen acreditación de inicio físico, soporte A6 independiente, Rf confirmado, transición autorizada A8, contención F11 y validación experimental.

## Contrato de reproducibilidad

`python3 -B scripts/ardrec_p14_r84_dev_acceptance_gate.py` acepta `--create` o `--verify`, `--work-dir`, `--r81-receipt`, `--r82-receipt`, `--r83-receipt` y `--expected-r83-sha256`. `--create` no ejecuta A5, no cambia SQLite R82, y escribe únicamente `MANIFEST.json` canónico en una carpeta privada (directorio `0700`, archivo `0600`). `--verify` reconstruye R83/R82/R81 desde las fuentes privadas con sus verificadores existentes, no se limita a comprobar un hash autodeclarado ni crea procesos nuevos. Un recibo corrupto, un enlace simbólico, un permiso inseguro o una incompatibilidad de caso detienen la revisión. Si hay un recibo parcial, no reiniciar `--create` sin análisis.

## Evidencia y pruebas

`lab/tests/test_p14_r84_dev_acceptance_gate.py` incorpora 25 pruebas nuevas: identidades A5, intervalos exactos, denegaciones y rechazo de duplicados, autoridad falsa, riesgo falsificado, reporte alterado, modo inseguro y mutación operacional. Las pruebas unitarias utilizan fixtures sintéticos. **La validación integral del CLI con recibos reales debe realizarla el ejecutor Prometheus antes del commit**; las regresiones históricas completas permanecen bajo la CI obligatoria de GitHub. Un resultado verde de tests no sustituye el experimento aprobado.

Los recibos fijados son R81 `e9cdf34c13074ed42b48282c642912c26fc27bf98aaa281c16f1dc29b7188ac5`, R82 `d7ec7fe3efde5f04c43e5530ba4f00e0f346ddc843a5c2c330d8ed18b76e66c1` y R83 `9e3131f558915167b512c4cd22a198e28829bc246e35b7be878f111b13566e1c`. La prueba sobre recibos reales no modifica esos archivos.
