# P8-R8 — Puente estructural sintético sin efectos / Pure synthetic state boundary

Este incremento integra **solo la observación estructural** entre los diagnósticos
P8-R7 y la máquina de estados pura (`src/ardrec/state.py`): ocho estados, once
variantes de T1–T10 (incluidas las dos rutas de T5), referencias a generación,
identidad de caso/perfil y guardas de tres valores. Se comparan entradas no
confiables contra el estado ya cargado; no se inventa fuente de autoridad.

El resultado `BoundaryReview` es inmutable y siempre devuelve
`decision=BLOCKED_UNBOUND_NO_EXECUTION`, `authorized=false`,
`dispatch_allowed=false`, `transition_applied=false`,
`publication_allowed=false`, `real_cases_authorized=0`.

Un `hypothetical_target` es únicamente **el destino de la tabla T1–T10** si el
origen y los valores sintéticos de las guardas son compatibles. No significa
que una guarda haya sido acreditada, que el emisor sea fiable ni que exista
permiso de despachar, cambiar el estado o publicar una generación. ND y FALSO
no acreditan ninguna guarda. Las operaciones `transition_service`,
`reserve_attempt`, `record_report` y las API de persistencia no se invocan.

Pruebas: 8 estados × 11 rutas; casos de guardas VERDADERO/FALSO/ND; identidad,
configuración, duplicados JSON, terminales e inmutabilidad; corpus R7 de
106 vectores y los 29 perfiles. Ejecutar:

```text
PYTHONPATH=src python3 -m unittest discover -s tests/unit -p test_p8_state_bridge.py -v
python3 scripts/verificar_p8_state_bridge.py
python3 scripts/verificar_trazabilidad_actual.py
```

El marco teórico, los diez algoritmos A1–A10 y su ejecución completa **no se
consideran implementados** por este contrato. Ninguna evidencia experimenta-
l, laboratorio físico, fuente privada, reloj autorizado o revocación verificada
forma parte del alcance. AL-06, AL-07 y siete obligaciones permanecen abiertos.

**EN:** In-memory read-only diagnostic over the existing state model and R7
synthetic messages. No state transition, trusted evidence, process dispatch,
persistence, operational authority, system acceptance or experiment.
