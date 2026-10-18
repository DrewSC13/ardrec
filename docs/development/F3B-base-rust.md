# F3B — Base compilable de Rust / Rust build baseline

## Español

Se establece un workspace Cargo con la biblioteca `ardrec-executor`,
versión de desarrollo `0.1.0-dev`, edición 2024 y Rust 1.98.1 como
requisito declarado. Esta etapa se comprueba con Rust 1.98.1.

El paquete hereda los metadatos y las reglas de análisis del workspace.
Se prohíbe código unsafe y se exige documentación de la interfaz pública.
La publicación mediante Cargo está deshabilitada.

La biblioteca contiene únicamente su identidad de versión.
Todavía no implementa ejecución de herramientas, comunicación con Python,
protocolo, reconciliación ni algoritmos A1–A10.

No se incorporan dependencias externas. Cargo.lock se genera sin conexión
y queda versionado. La compilación y Clippy se ejecutan con --locked
y --offline. Se comprueba además el formato mediante rustfmt.

Las comprobaciones utilizan un directorio temporal de compilación,
eliminado al finalizar. Se verifica que Cargo.lock y el compilador
predeterminado del usuario permanezcan sin cambios.

El registro JSON adjunto identifica versiones, comandos, resultados y
huellas de los archivos. Los resultados acreditan la compilación y las
comprobaciones estáticas de esta base; las pruebas funcionales y de
algoritmos no se han ejecutado. CI permanece pendiente.

## English

A Cargo workspace is established with the `ardrec-executor` library,
development version `0.1.0-dev`, edition 2024 and Rust 1.98.1 as its
declared requirement. This stage is checked using Rust 1.98.1.

The package inherits workspace metadata and lint rules.
Unsafe code is forbidden and public interfaces require documentation.
Publishing through Cargo is disabled.

The library contains only its version identity.
Tool execution, Python communication, the protocol, reconciliation
and algorithms A1–A10 are not implemented yet.

No external dependencies are introduced. Cargo.lock is generated offline
and tracked in version control. Building and Clippy use --locked and
--offline. Formatting is also checked with rustfmt.

Checks use a temporary build directory that is removed upon completion.
Cargo.lock and the user's default compiler are checked for changes.

The accompanying JSON record identifies versions, commands, results and
file hashes. Results establish successful compilation and static checks
of this baseline; functional and algorithm tests have not been run.
CI remains pending.
