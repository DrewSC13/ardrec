# P8-R7 — Contrato interoperable de diagnóstico denegado

La nueva API Python (`src/ardrec/p8_diagnostic.py`) y Rust (`crates/ardrec-executor/src/p8_diagnostic.rs`) interpretan **afirmaciones sintéticas no confiables** y emiten siempre una respuesta de denegación con código estable. Los campos de R5 y R6 son referencias al **estado declarado**, no resultados verificados por una autoridad privada. El mensaje incluye únicamente identificadores simbólicos y huellas declaradas, sin secretos ni binarios.

Se verifican estrictamente: versión y nombre del contrato, 20 claves exactas, documento JSON acotado a 4096 bytes, Unicode/UTF-8, ausencia de claves duplicadas, tipos sin coerción, 29 perfiles conocidos, correspondencia familia–caso, sintaxis de huella, igualdad de identidad, coherencia de época/revisión y ausencia de promoción de autoridad. Un diagnóstico coherente mantiene el código `P8_R7_UNVERIFIED_AUTHORITY` y nunca concede permiso.

`tests/fixtures/p8-diagnostic-v1.json` almacena los vectores de ensayo compartidos; `tests/unit/test_p8_diagnostic.py` los comprueba con Python y `crates/ardrec-executor/tests/p8_diagnostic_deny.rs` con Rust. `scripts/verificar_p8_diagnostico.py --probe <ruta>` realiza la comparación **byte a estructura** entre la función Python y una sonda Rust compilada. La sonda solo lee `stdin` y escribe un JSON de denegación; la ejecución del ejecutor operacional no participa.

Para validar tras aplicar el overlay:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/unit -p test_p8_diagnostic.py -v
cargo test --workspace --all-targets --locked --offline
cargo build --package ardrec-executor --example p8_diagnostic_probe --locked --offline
python3 scripts/verificar_p8_diagnostico.py --probe target/debug/examples/p8_diagnostic_probe
```

**No cubre:** procedencia de datos R5/R6, verificación de emisor, reloj confiable, integridad futura entre observación y uso, FD a Rust, registro de revocación real, aislamiento de VM, AL-06, AL-07, ni los requisitos pendientes de P8. No hay socket de despacho, red ni ejecución real.

**EN:** Shared, strict synthetic denial diagnostic: no authority, no execution, no operational capability and no experiment.
