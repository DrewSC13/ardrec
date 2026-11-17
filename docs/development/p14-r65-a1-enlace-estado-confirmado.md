# P14-R65 — A1: enlace de decisión contextual al modelo de estado confirmado

**Fuente académica:** *Tesis ARDREC*, versión 17-11-2026, SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, §3.6.1, figura 3.4, página impresa 105 (PDF p. 120).

**Base de desarrollo:** `c07c355f3282e10f10043dc3d11479b38329d21f`, PR #162 (R64), CI Python/Rust/SSH aprobada.

## Criterio implementado

En R64, el invocador proporcionaba `current_state` como una declaración explícita. R65 introduce `FrozenRulePreview.evaluate_service_confirmed`, que recibe un objeto real `ConfirmedState` de `ardrec.state` y deriva `estado_actual` de la instancia `ServiceState` identificada en dicho objeto. Rechaza servicios no presentes en el estado, identidades inválidas y estructuras de estado alteradas. Conserva:

- Huella SHA-256 del registro de estado modelado, compuesta por identidad de registro, generación, referencia de generación, huella de configuración global, versiones, eventos incorporados y proyección canónica de sus servicios.
- Huella independiente de la fuente de reglas congeladas R17.
- Resultado A1 de R64 realmente recomputado, sus evaluaciones trivalentes y la salida declarativa.
- Vinculación verificable por reproducción exacta; si cambian estado, configuración, reglas, ambiente o identificadores de caso/condición/contexto, el recibo anterior se rechaza.

**Alcance deliberadamente acotado:** la identidad del tipo Python `ConfirmedState` y su consistencia interna **no acreditan** que el objeto haya sido recuperado de la generación durable por A9, que proceda de un actor confiable, que la configuración global y la huella de reglas R17 correspondan al mismo origen, ni que un caso configurado tenga permiso operacional. El recibo registra `model_external_origin_attested=false`, `full_configuration_to_rule_source_attested=false`, `operational_dispatch=false`, `published_generation=null` y `p8_operational=NO-GO`.

Esta extensión **no modifica** `DECIDIR`, el formato R17 congelado, el contenido de R26/R58, el cálculo A7, la máquina de estados o el motor P8. Su API es aditiva y de solo lectura. El siguiente trabajo debe unir el origen confirmado en el coordinador normal con la fuente R17 y demostrar reapertura de generación durable sin aserciones de autoridad inmerecida.

## Criterios de prueba

`lab/tests/test_p14_r65_a1_confirmed_context.py` verifica 26 casos independientes con resultados literales: selección, ND, rechazo de ambigüedad y campo requerido, estado y generación derivada del modelo, referencias de identidad, ausencia de servicio, hashes por separado, alteración/rehash/replay, permutación de servicios, no acreditación de procedencia y política P8. La CI agrega esta suite sobre el mismo commit sometido al PR. Las regresiones P14 completas, Rust, trazabilidad y CI de `main` deben aprobar antes de integración.

**A1 100 %: pendiente.** Este incremento resuelve la vinculación a `ConfirmedState` *como modelo*, pero no acredita fuente externa ni la ruta normal de ejecución. La validación física SSH/FTP/SMB y la hipótesis experimental con 54 unidades permanecen separadas.

**EN.** Adds a replay-verifiable, read-only A1 contextual envelope deriving service phase from the existing `ConfirmedState` model, preserving separate rule-source and global-configuration fingerprints. A Python model is not an independently attested durable generation or operational authority. P8 remains NO-GO.
