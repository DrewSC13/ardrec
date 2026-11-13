# P9-R11 — Sondeo Rust de identidad de testigo benigno mediante pidfd

**Base exacta:** `78a8e4f64cc367feb4acc596f929dd90c1ea4c0c` (merge #76).
**Alcance:** implementación de un observador Linux de solo lectura en la crate Rust.
**Estado de P8:** contractual completo según corte R78-R2; operacional **NO-GO**.

## Propiedad que se comprueba

La prueba R10 demuestra que un testigo de doble fork puede salir del PGID del líder, ser adoptado por un subreaper Python y terminar recogido. R11 añade una API Rust para inspeccionar la identidad de **un testigo ya conocido** en un momento de observación, sin enviarse señales ni lanzar comandos desde la biblioteca.

`observe_owned_witness(WitnessClaim)` exige: PID > 1, padre esperado igual al proceso observador, UID real igual al del observador, PGID distinto del grupo original y tick de inicio positivo. Abre un `pidfd` antes de consultar `/proc/<pid>/stat` y `/proc/<pid>/status`, conserva el descriptor durante dos lecturas y compara la identidad anunciada. Devuelve uno de cinco estados sin autorizar ninguna acción:

- `BoundAtProbe`: identidad, padre, UID y PGID observados coherentemente durante el sondeo, sin certificar ascendencia histórica ni ausencia de otros procesos.
- `NotPresentAtProbe`: `pidfd_open` respondió ESRCH; ausencia **puntual**, nunca acreditación global de limpieza.
- `ZombieNotReaped`: el testigo ya figura como zombi y requiere recolección.
- `AttributionNotProven`: identidad, precondiciones, procedencia o lectura de `/proc` insuficientes, incluidos permisos y cambios concurrentes.
- `UnsupportedPidfd`: el kernel no ofrece esa operación.

Ningún estado autoriza P8, concede permiso de proceso, envía señales, recoge hijos, confirma una limpieza global o justifica repetir una ejecución incierta.

## Diferencia respecto a R10 y limitaciones

Las pruebas Rust generan un hijo local acotado en PGID distinto mediante el *harness*, únicamente para ejercer la API Rust. **No recrean todavía la adopción por subreaper ni un descendiente arbitrario que cambió de PGID.** R10 sigue siendo el ensayo independiente de ese fenómeno. R11 introduce observación de identidad con pidfd y una frontera de evidencia reutilizable; aún falta conectar la captura efectiva de identidad, la propiedad de descendientes de múltiples generaciones y una limpieza controlada desde el supervisor real. No hay durabilidad tras caída del supervisor, ni cgroups, ni aislamiento del árbol completo.

La validación local de Prometheus debe registrar cargo `test --locked --offline -p ardrec-executor --test p9_r11_witness_probe`, la regresión `p9_process_group`, `cargo fmt --all --check`, `cargo clippy --locked --offline --workspace --all-targets -- -D warnings`, y las pruebas Python vigentes. Conservar códigos, SHA de logs, `main` base y versión de toolchain. No considerar pruebas no ejecutadas como PASS.

| Obligación | Implementación | Oráculo | Pendiente |
|---|---|---|---|
| P9: identidad de testigo del observador | `p9_r11_witness_probe::observe_owned_witness` | `observes_owned_benign_fixture_in_another_pgid` | Correlación causal con árbol supervisado |
| P9: incertidumbre es no autorización | `AttributionNotProven`, `UnsupportedPidfd` | Mutación de tick, padre y UID | Manejo operacional de capacidades |
| P9: ausencia puntual no es limpieza | `NotPresentAtProbe` | `reaped_witness_is_only_absent_not_certified_clean` | Recolección y comprobación global |
| P8, AL-07 | Biblioteca sin señales ni despacho | Inspección estática y control de alcance | Permisos/recuperación del ejecutor |

**Criterio de cierre acotado R11:** pruebas Rust, Python y CI según el entorno de Prometheus, commit firmado, PR con ruleset y CI, merge y CI posmerge sobre SHA exacto. No confundir este resultado con la aceptación operacional de P9 ni P8.
