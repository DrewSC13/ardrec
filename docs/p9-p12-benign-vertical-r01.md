# ARDREC — P9–P12 / Entrega vertical de desarrollo, no operacional

**Tipo:** demostrador funcional con procesos benignos inmutables; no sustituye las interfaces P8 ni acredita cierre operacional de los puntos 9–12. **Base Git:** `78a8e4f64cc367feb4acc596f929dd90c1ea4c0c`. **Prerequisito:** R11 instalado y probado en `feat/p9-r11-readonly-pidfd-attribution`.

## Pregunta técnica y criterio

¿Puede ARDREC reservar una solicitud de desarrollo, aceptarla, persistir irrevocablemente la intención de iniciar un proceso, ejecutar un fixture benigno, conservar evidencia acotada y recuperar un inicio incierto sin duplicarlo? El demostrador responde esta pregunta con **procesos Python fijos**, un almacenamiento SQLite y artefactos de salida con SHA-256. Ningún resultado da autoridad para ejecutar SSH, FTP o SMB.

**Modelo de estados de desarrollo:** `RESERVED → ACCEPTED → START_INTENT → RECORDED_LIMITED`; ante un inicio sin finalización acreditada: `START_INTENT → RECOVERY_UNCERTAIN`. Una nueva solicitud idéntica conserva su identidad; la misma ID con otra carga se rechaza. `START_INTENT` se confirma en SQLite antes de `Popen`. La recuperación jamás relanza un intento con inicio incierto y jamás señaliza un PID previamente guardado. `ACCEPTED` aún no ha despachado y puede continuar tras reinicio; `RESERVED` tampoco implica ejecución. `start_count` no puede superar uno para el mismo identificador.

**P10:** los fixtures son `ok`, `nonzero`, `noisy`, `slow` y no aceptan comandos externos. Se ejecutan mediante Python `-I -c` con código fijo. Se registra la huella de la solicitud, aceptación, intención, identidad observada del líder y resultado. El identificador `pid/start_ticks` es informativo y **no** acredita custodia después del crash. No hay red, credenciales, `argv` libre ni conexión con la puerta de admisión P8.

**P11:** stdout/stderr se drenan con `selectors`; se retienen como máximo `output_cap` bytes **por canal** y se informa el número total observado, truncamiento y EOF. Las muestras se escriben con permisos 0600, fsync de archivo y directorio y SHA-256, y las referencias se vinculan al resultado en una transacción. La prueba de integridad detecta alteraciones de muestras o resultados y registra una cadena hash de eventos por intento. La cadena no tiene ancla externa y, por tanto, **no detecta por sí sola un rollback íntegro del almacén**. Se recoge al líder propio; **nunca** se declara limpieza general del árbol. La salida `BENIGN_EXIT_ZERO` expresa exclusivamente el código del fixture, no una validación P8.

**P9:** la observación Rust R11 de identidad con pidfd y la prueba Python R10 del nieto escapado son aportes separados. Este recorrido tiene limpieza acotada del líder, pero no acredita cgroups delegados, pertenencia global, recuperación de nietos escapados, límites de CPU/memoria/FD ni manejo general de cierre del supervisor. Si falta pidfd, el vencimiento no pretende haber enviado una señal; el fixture lento termina por su máximo declarado. La instancia sigue siendo **NO-GO** para despachos arbitrarios.

**P12:** una caída real con `os._exit(77)` justo después del commit `START_INTENT` queda reproducida; el siguiente proceso marca `RECOVERY_UNCERTAIN`, mantiene `start_count=1`, no reintenta y no asigna éxito. Esto demuestra la política de recuperación en ese punto de inyección, **no** recuperación general con procesos huérfanos, cortes eléctricos, pérdida de comunicación persistente, ni *exactly-once execution* ante todos los fallos.

## Reproducción local

Todos los comandos desde la raíz del worktree con Python 3.14.7 y Rust 1.98.1; no usar `sudo`:

```bash
python3 -B -m unittest discover -s lab/tests -p test_p9_p12_benign_pipeline.py -v
state=$(mktemp -d /tmp/ardrec-p9p12-demo.XXXXXXXX)
python3 -B scripts/demo_p9_p12_benign.py --state-dir "$state"
PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p 'test_*.py' -v
cargo test --locked --offline --workspace --all-targets
cargo fmt --all --check
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
```

No borrar artefactos ni evidencias del ensayo antes de conservar sus hashes. Usar directorios de prueba independientes. La ejecución de desarrollo se confina a su identidad de proceso y su UID local; no equivale a contención de sistema operativo.

## Matriz de cierre — resultados no intercambiables

| Punto | Alcance implementado en este incremento | Restante antes de declarar completo |
|---|---|---|
| **8. Perfiles autorizables** | Se conserva el dictamen contractual de 29 variantes P8 y la denegación; ninguna entrada adquiere autoridad | **348 campos**, **261 comprobaciones**, cinco limpiezas de perfiles mutadores, revisión humana de semántica y autorización individual; **0 casos habilitados** |
| **9. Supervisor** | R01/R03/R09 y R10/R11 independientes; inicio y recolección del líder propio | API supervisora integrada para el árbol, atribución estable de descendientes, cgroup delegado o equivalente, límites OS efectivos, crash recovery y pruebas adversariales |
| **10. Solicitud a ejecución** | Ruta real de fixture benigno: reserva, aceptación, inicio persistido, resultado, idempotencia concurrente | Adaptador autorizado P8, identidades confiables, rechazo de permisos ajenos, reserva/confirmación distribuida, protección de capacidades y política temporal operacional |
| **11. Recolección/limpieza** | Captura incremental limitada, fsync, SHA y auditoría; zombi líder recogido | Árbol, FD, archivos temporales ajenos, límites de recursos garantizados, limpieza de todas las ramas, recolección ante muerte del supervisor |
| **12. Recuperación** | Reinicio tras START_INTENT sin reintento, resultado durable verificable | Supervisor durable independiente, interrupciones durante/tras ejecución, energía, roturas de comunicaciones, anclaje de frescura y recuperación de artefactos parciales |

**Veredictos:** `P8_CONTRACTUAL=AS_RECORDED`, `P8_OPERATIONAL=NO-GO`, `P9_P12_BENIGN_VERTICAL=DEVELOPMENT_CANDIDATE`, `P9_P12_OPERATIONAL=NOT_CLOSED`. La aprobación de pruebas del demostrador no cierra AL-06, AL-07, FRESHNESS-CUSTODY ni FILESYSTEM-POWER-LOSS.

## Oráculos y evidencias mínimas

1. `test_zero_exit_result_and_evidence`: salida auténtica, evidencia y sin afirmación global.
2. `test_nonzero_is_not_success`: código 7 distinto de cero, sin falso éxito.
3. `test_bounded_capture_and_truncation_proof`: 131072 bytes observados, 512 almacenados, truncamiento.
4. `test_concurrent_requests_cannot_double_start` y `test_same_request_is_idempotent`: solo un `START_INTENT` bajo carrera.
5. `test_real_process_exits_after_start_intent_before_launch`: muerte abrupta, reconciliación sin segundo inicio.
6. `test_tampered_artifact_is_detected`, `test_database_result_tampering_is_detected` y `test_tampered_event_is_detected`: integridad de artefactos, resultados y eventos.
7. `test_arbitrary_commands_and_path_like_ids_rejected`: no se admiten ejecutables externos ni rutas como ID.
8. Integración de CI: paso adicional en job Python existente (no altera nombres de checks obligatorios) más regresión Rust por `cargo test --all-targets` ya existente.

Registrar SHA Git antes y después, distribución de Python y Rust, SHA ZIP, contenido de evidencia, exit codes y SHA de logs. La aceptación exige inspección y ejecución real en Prometheus, revisión de diferencias exactas, commit firmado, PR, checks obligatorios y CI posmerge.
