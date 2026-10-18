# F4 — Integración continua / Continuous integration

## Español

El workflow `ci.yml` contiene dos trabajos independientes:
`Python - empaquetado / packaging` y `Rust - compilación / build`.

Ambos utilizan Ubuntu 24.04. Python se obtiene de `.python-version`;
uv se fija en 0.12.13 y Rust en 1.98.1. Las tres acciones externas
se fijan mediante SHA completos, obtenidos durante F4A.

El token del workflow tiene permiso `contents: read`.
Checkout no conserva credenciales. No se configura caché de dependencias.
Cada trabajo tiene un límite de quince minutos.

El workflow se activa en los PR dirigidos a main, incluidos los borradores,
y al publicar cambios en main. En los PR se comprueba la referencia de
integración proporcionada por GitHub; en push, el commit publicado.

El script `scripts/verificar_ci.py` comparte las comprobaciones entre
el entorno local y CI. Python construye la distribución fuente y su wheel,
instala el wheel en un entorno vacío y verifica su importación y versión.
Rust comprueba formato, compilación y Clippy. Los archivos de bloqueo
deben permanecer sin cambios y los artefactos temporales se eliminan.

Ejecución local desde la raíz del repositorio:

    .venv/bin/python scripts/verificar_ci.py python
    .venv/bin/python scripts/verificar_ci.py rust

F4B registra las ejecuciones locales del script. La aceptación remota
requiere posteriormente una ejecución satisfactoria de ambos trabajos
en GitHub para la revisión correspondiente.

Estas comprobaciones cubren la base de desarrollo. No constituyen pruebas
funcionales, validación de A1–A10 ni validación experimental.

## English

The `ci.yml` workflow contains two independent jobs:
`Python - empaquetado / packaging` and `Rust - compilación / build`.

Both use Ubuntu 24.04. Python comes from `.python-version`;
uv is pinned to 0.12.13 and Rust to 1.98.1. The three external actions
are pinned to full commit SHAs obtained during F4A.

The workflow token has `contents: read` permission.
Checkout does not persist credentials. No dependency cache is configured.
Each job has a fifteen-minute timeout.

The workflow runs for PRs targeting main, including drafts,
and for pushes to main. PRs check GitHub's integration reference;
pushes check the published commit.

The `scripts/verificar_ci.py` script shares checks between local
development and CI. Python builds the source distribution and its wheel,
installs the wheel into an empty environment and checks import and version.
Rust checks formatting, compilation and Clippy. Lockfiles must remain
unchanged and temporary artifacts are removed.

Local execution from the repository root:

    .venv/bin/python scripts/verificar_ci.py python
    .venv/bin/python scripts/verificar_ci.py rust

F4B records local executions of the script. Remote acceptance subsequently
requires both GitHub jobs to complete successfully for the relevant revision.

These checks cover the development baseline. They are not functional tests,
A1–A10 validation or experimental validation.
