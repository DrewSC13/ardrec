# ARDREC P14-R47-F2 — Corrección de formato Rust y trazabilidad estricta

## Causa confirmada en GitHub (PR #122)

HEAD exacto: `26c0d3bdeec3abd44fdc387510891a097f53d799`.
CI Python falló por `ARDREC_CURRENT_TRACEABILITY=FAIL: Inventario Rust incompleto`.
CI Rust falló en `cargo fmt --all --check` (no falló por código/compilación Rust).

R47-F1 sumó dos tests Rust a `p9_r11_witness_probe.rs`, pasando de 99 a **101** tests `#[test]` de `src/`.
El inventario exacto permitido queda: 73 históricos + 24 P8 R53/R54 + 4 P9-R11 = 101.
La corrección no modifica el registro histórico `development-v2.json`, la frontera P8, ni el flujo de CI.

## Alcance del ZIP

- Modifica `crates/ardrec-executor/src/p9_r11_witness_probe.rs`: **solo formato** que exige `rustfmt`.
- Modifica `scripts/verificar_trazabilidad_actual.py`: incorpora por nombre exacto las dos pruebas R47-F1, cambia los totales a 101 y conserva el comportamiento fail-closed.
- Modifica `lab/tests/test_p9_r11_rust_inventory.py`: comprueba los totales, faltantes y rechazos.
- Crea este documento.

No ejecuta Cargo, Git write, libvirt, nftables, red, sudo ni procesos de la VM. La aplicación se limita al árbol Git. Los recibos del laboratorio quedan privados. P8=NO-GO.

## Secuencia obligatoria

1. Desde la misma rama R47, mismo HEAD y árbol limpio: `python3 apply_patch.py --repo /home/cicada/Development/GitHub/ardrec --check`.
2. Si PASS: ejecutar sin `--check`, verificar diff y `cargo fmt --all --check`.
3. Correr tests del inventario, trazabilidad, tests Rust y transporte Python-Rust, suite P14.
4. Commit SSH **nuevo** en la rama actual, push del PR #122, 3 checks requeridos PASS, merge normal.

No reintentar staging físico R47; ya tiene recibo verificado. No modificar filtros ni VMs.
