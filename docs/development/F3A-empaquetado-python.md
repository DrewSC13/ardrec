
# F3A — Empaquetado de Python / Python packaging

## Español

Se establece el paquete `ardrec`, versión de desarrollo `0.1.0.dev0`,
con código ubicado en `src/ardrec`. Esta versión identifica la base
de desarrollo; no representa una entrega funcional de los algoritmos.

Se exige Python 3.14.7, conforme al entorno de referencia F2.
La compatibilidad con otras versiones queda pendiente de evaluación.

Hatchling 1.29.0 constituye el backend de construcción.
El grupo `build` incorpora ese backend y sus dependencias transitivas
a `uv.lock`. La aplicación todavía no declara dependencias de ejecución.

La comprobación utiliza un entorno temporal con las dependencias
del grupo `build` instaladas mediante `uv sync --locked`.
La construcción usa ese entorno con `uv build --no-build-isolation`,
por lo que el backend se obtiene del entorno previamente preparado.

Se construye la distribución fuente y, a partir de ella, el wheel.
El wheel se instala sin consultar índices ni resolver dependencias
en otro entorno temporal vacío. Se comprueban la importación desde
ese entorno y la coincidencia entre la versión del módulo y los
metadatos de la distribución, usando Python en modo aislado.

El registro JSON adjunto contiene los resultados y las huellas SHA-256.
Los entornos y artefactos temporales se eliminan al finalizar.
La equivalencia binaria entre construcciones independientes no se ha
evaluado. Las huellas identifican los artefactos observados.

El paquete conserva el estado preliminar de A1–A10.
Su construcción e importación no verifican el comportamiento de esos
algoritmos. Quedan pendientes el proyecto compilable Rust, las pruebas
funcionales, CI y la validación experimental.

## English

The `ardrec` package is established with development version
`0.1.0.dev0` and source code under `src/ardrec`. This version identifies
the development baseline; it is not a functional algorithm release.

Python 3.14.7 is required, following the F2 reference environment.
Compatibility with other versions remains to be evaluated.

Hatchling 1.29.0 is the build backend.
The `build` group includes that backend and its transitive dependencies
in `uv.lock`. The application declares no runtime dependencies yet.

Verification uses a temporary environment with the `build` dependencies
installed through `uv sync --locked`.
The build uses that environment with `uv build --no-build-isolation`,
so the backend comes from the previously prepared environment.

The source distribution is built first, followed by its wheel.
The wheel is installed without querying indexes or resolving dependencies
into another empty temporary environment. Importing from that environment
and agreement between module and distribution versions are checked,
using Python in isolated mode.

The accompanying JSON record contains results and SHA-256 hashes.
Temporary environments and artifacts are removed after verification.
Binary equivalence across independent builds has not been evaluated.
The hashes identify the observed artifacts.

The package retains the preliminary status of A1–A10.
Building and importing it do not verify algorithm behavior.
The buildable Rust project, functional tests, CI and experimental
validation remain pending.
