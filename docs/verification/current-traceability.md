# Verificación de trazabilidad vigente / Current traceability verification

## Español

Este incremento relaciona los 44 requisitos registrados (27 criterios AC y 17 obligaciones MET) con sus algoritmos o responsables, módulos actuales y previstos, comprobaciones, evidencia y trabajo pendiente. Conserva 10 algoritmos, 15 invariantes, 51 oráculos y siete obligaciones de desarrollo. No afirma exhaustividad de cada oración de la tesis.

La matriz v1, sus evidencias, la aceptación histórica y el cierre del punto 1 se conservan. `development-v2.json` es la vista vigente; `development-v2.md` se deriva del mismo contenido y el verificador rechaza divergencias. Las asociaciones de suites son soporte parcial del componente, no cobertura completa de cada afirmación del requisito.

El inventario de base contiene 405 métodos Python —incluidos los generados dinámicamente—, 73 pruebas Rust y siete verificadores de integración. El descubrimiento identifica pruebas sin ejecutarlas. Su ejecución se acredita por separado. La evidencia EV-MAIN26-CI procede de la salida de integración recibida: commit `228bdedf09d06906ddfa184525e9a7c60f4e2dc6`, ejecución `41358531943`. Las huellas de logs son recibidas; los logs no están archivados en el repositorio ni fueron consultados independientemente en este incremento.

Se añaden 20 pruebas del verificador. La suite Python esperada al aplicar el cambio es 425, no 405. Esas 20 pruebas nuevas no heredan resultados del CI anterior. El instalador genera registros locales; la publicación y la integración deben verificar CI sobre el nuevo commit antes de declarar cerrado el punto 2.

Comprobaciones requeridas:

```bash
python3 scripts/verificar_trazabilidad.py
python3 scripts/verificar_trazabilidad_actual.py
PYTHONPATH=src python3 -m unittest discover -s tests/unit -p 'test_*.py' -v
```

El verificador vigente comprueba identidades, fuentes por SHA256, inventarios, pruebas dinámicas, referencias inversas, condiciones de entrada y coherencia del documento. Rechaza desaparición de requisitos u obligaciones, rutas externas, evidencia de otro commit/ejecución y promoción de componentes, oráculos o metodología a aceptación funcional.

Cierre del punto 2: 44 requisitos con seguimiento explícito; controles aprobados localmente y por CI; PR y merge identificados; CI de main aprobado. Un requisito no implementado conserva módulo previsto, prueba pendiente y evidencia requerida. AL-06/AL-07 no necesitan presentarse falsamente como cerrados para completar su trazabilidad. El laboratorio y A1–A10 corresponden a etapas posteriores.

## English

This change traces all 44 registered requirements (27 AC criteria and 17 MET obligations) to algorithms or accountable owners, current/planned modules, checks, evidence and pending work. It preserves 10 algorithms, 15 invariants, 51 reference oracles and seven development obligations; it does not claim sentence-level thesis exhaustiveness.

Historical v1 files, acceptance records and point 1 closure remain unchanged. The current JSON and its derived Markdown must agree. Component-suite associations denote partial support, not full assertion-level requirement coverage.

The baseline inventory contains 405 Python methods including dynamic tests, 73 Rust tests and seven integration scripts. Discovery does not execute them. EV-MAIN26-CI is user-reported integration output for commit `228bdedf09d06906ddfa184525e9a7c60f4e2dc6`, run `41358531943`. Reported log hashes are not archived logs or independent acquisition in this increment.

Twenty new checker tests make the expected Python suite 425. New tests cannot inherit old CI evidence. The installer writes local logs; publication and integration must verify the new commit and merged-main CI before point 2 closure.

The checker verifies source hashes, identifiers, inventories, dynamically generated tests, reverse indexes, gates and rendered documentation. Negative tests reject missing requirements/obligations, external paths, mismatched evidence and unsupported acceptance claims. Pending requirements retain planned modules, verification and required evidence. AL-06/AL-07 remain open; laboratory work and A1–A10 follow their roadmap gates.
