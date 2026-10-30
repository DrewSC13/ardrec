# Verificación de identidad del par / Peer identity verification

## Español

Esta nota define verificaciones requeridas; su presencia no acredita una ejecución
local ni CI exitosas. Los registros de aplicación y CI deben asociarse al commit exacto.
Base: `5306f15e0057dfa205168a23fd3b3b6196becc20`.

| Comprobación | Evidencia requerida |
| --- | --- |
| Suite Python completa | 349 pruebas, cero fallos, errores u omisiones |
| Identidad Python | 20 pruebas en `test_peer_identity.py`, incluidas conexiones de procesos distintos |
| Suite Rust | 73 pruebas de biblioteca; cero fallos u omisiones |
| Calidad Rust | formato, build y clippy con warnings denegados y lock sin cambios |
| Empaquetado | sdist, wheel e instalación limpia |
| Regresión de conciliación | once pruebas Rust del canal y escenarios F10 existentes |
| Integración de identidad | siete escenarios de `scripts/verificar_identidad_par.py` |

Los siete escenarios son `accepted`, `python_pid`, `python_uid`, `python_gid`,
`rust_pid`, `rust_uid`, `rust_gid`. Cada rechazo mantiene los bytes de ambos diarios
y la consulta pendiente, sin habilitar una ejecución. El éxito debe recuperar el
resultado exacto incluso después de reabrir el diario Python. Solo se crean recursos
sintéticos en directorios temporales privados y procesos propios de las sondas.

El preparador comprobó las pruebas Rust, formato/build/clippy y las pruebas Python
permitidas en su entorno. La creación de sockets Unix mediante `socket()` está
restringida allí: tres pruebas Python, el intercambio histórico por ruta Unix y la
nueva integración por ruta requieren ejecución
en Linux sin esa restricción. No se omiten ni se convierten en aprobadas. El instalador
comprueba la capacidad antes de cambiar la rama y exige la suite completa y los siete
escenarios antes de firmar el commit. Cualquier fallo conserva el estado para diagnóstico.

Comandos sobre un checkout del incremento, usando Python 3.14.7, Rust 1.98.1 y uv 0.12.13:

```bash
cargo fetch --locked
PYTHONPATH=src python3 -m unittest discover -s tests/unit -v
cargo test --workspace --all-targets --locked --offline
python3 scripts/verificar_ci.py python
python3 scripts/verificar_ci.py rust
python3 scripts/verificar_conciliacion_transporte.py
python3 scripts/verificar_identidad_par.py
```

Los dos comandos `verificar_ci.py` esperan un checkout sin diferencias seguidas por Git.
Durante la aplicación, el instalador llama sus verificadores internos y comprueba por
separado las huellas exactas y el conjunto de cambios antes de firmar. Los demás pasos
históricos de CI siguen siendo obligatorios para integrar el incremento.

AL-07 permanece abierto: falta verificar perfiles congelados, referencias cruzadas,
ausentes o alteradas, permisos y cambios de artefactos en los caminos operacionales.
La credencial del canal no sustituye esas verificaciones ni resuelve AL-06.

## English

This document specifies required checks, not a claim that local or remote CI passed.
Evidence must be associated with the exact commit. Requirements are 349 Python tests,
73 Rust library tests with no skips, formatting/build/clippy, clean packaging, existing
reconciliation regressions, and seven pathname-socket identity scenarios listed above.
Rejected peers must preserve both journals and the pending query; successful recovery
must return the exact original result after reopening persistence.

The preparation environment restricts Unix socket creation through socket(). Three
Python tests, the existing pathname transport check and new pathname integration
therefore require an unrestricted Linux test host.
They remain mandatory: no skips or fabricated passes. The installer checks socket
capability before branch creation, then requires every test and scenario before signing.
It uses the existing packaging/build verifier functions while independently checking
all source hashes because the application tree has intentional tracked changes.

CI retains every prior step. This is synthetic verification, not physical execution
or experimental acceptance. Trusted identity policy and operational reference, profile,
permission and artifact controls remain pending. AL-06 and AL-07 stay open.
