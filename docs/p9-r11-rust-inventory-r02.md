# P9-R11-R02 — Conciliación del inventario de pruebas Rust

**Base:** `78a8e4f64cc367feb4acc596f929dd90c1ea4c0c`. **Rama:** `feat/p9-r11-readonly-pidfd-attribution`. **P8 operacional: NO-GO**.

## Causa observada

Tras integrar R11 y el recorrido benigno P9–P12 en el worktree, la suite `tests/unit` falla en `scripts/verificar_trazabilidad_actual.py` porque su inventario permite exactamente 97 pruebas unitarias Rust (73 históricas + 24 P8 R53/R54). R11 incorpora dos pruebas `#[test]` adicionales en `p9_r11_witness_probe.rs`: `parses_stat_with_inner_parentheses` y `parses_uid_without_accepting_missing_data`. Un aumento de cobertura no debe eliminar la comprobación de integridad.

## Enmienda acotada

El verificador conserva la base congelada de 73, la extensión P8 exacta de 24 y añade un inventario explícito de dos pruebas de parsing R11; total esperado: **99**. Se sigue rechazando toda prueba faltante, renombrada, duplicada o inesperada. Los 73 métodos históricos y las huellas en `development-v2.json` no se reescriben. Las nuevas pruebas R11 son observación de componente, **no** aceptación operacional ni limpieza global.

Se añade `lab/tests/test_p9_r11_rust_inventory.py` con pruebas positivas y negativas y un paso de CI asociado al job Python, sin renombrar los dos checks requeridos por `main`. El cambio del script está autenticado por el blob Git de la base y tres reemplazos textuales únicos. No modifica Rust, herramientas ejecutadas, perfiles P8, autoridad de despacho, credenciales o catálogo.

## Aceptación de Prometheus

Ejecutar la nueva suite y el verificador completo, luego volver a correr `PYTHONPATH=src python3 -B -m unittest discover -s tests/unit -p 'test_*.py' -q`, la regresión completa de `lab/tests`, `cargo test --workspace --all-targets --locked --offline`, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` y la CI del PR. Guardar logs y hashes fuera del repositorio; no inventar resultados ni marcar cerrados P8–P12. Los escenarios P9–P12 siguen restringidos a procesos benignos predefinidos.
