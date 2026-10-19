# Entorno de desarrollo de referencia

## Español

Se fijan Python 3.14.7 y Rust 1.98.1 como versiones de referencia
para la preparación inicial de ARDREC.

El intérprete Python se utiliza mediante .venv/bin/python.
El archivo .python-version declara la versión para herramientas compatibles;
por sí solo no cambia el comando python3 del sistema.
El entorno .venv permanece excluido de Git y debe recrearse en cada equipo.

Rust se selecciona mediante rust-toolchain.toml, con perfil minimal y
componentes rustfmt y clippy. No se modifica el compilador predeterminado
del usuario. Las opciones explícitas de Rustup y los overrides pueden
prevalecer sobre este archivo; debe comprobarse la versión efectiva.

Las verificaciones iniciales comprueban aislamiento de Python, aritmética
racional exacta con Fraction, disponibilidad de sockets Unix y capacidad
de compilar y ejecutar un programa Rust que utiliza un socket Unix local.

Estas comprobaciones validan capacidades del entorno. No prueban los
algoritmos A1–A10 ni implementan el protocolo de mensajes de ARDREC.

Quedan pendientes el empaquetado, las dependencias y sus archivos de bloqueo,
las pruebas del software, CI, las reglas del repositorio y el laboratorio.
La fijación de versiones no constituye todavía un entorno completamente
reproducible ni demuestra compatibilidad con dependencias futuras.

## English

Python 3.14.7 and Rust 1.98.1 are pinned as reference versions
for the initial preparation of ARDREC.

The Python interpreter is used through .venv/bin/python.
The .python-version file declares the version for compatible tools;
it does not change the system python3 command by itself.
The .venv environment remains excluded from Git and must be recreated
on each machine.

Rust is selected through rust-toolchain.toml, using the minimal profile
and the rustfmt and clippy components. The user's default compiler is
not changed. Explicit Rustup options and overrides may take precedence
over this file; the effective version must be checked.

Initial checks verify Python isolation, exact rational arithmetic with
Fraction, Unix socket availability and the ability to compile and run
a Rust program that uses a local Unix socket.

These checks validate environment capabilities. They do not test
algorithms A1–A10 or implement the ARDREC message protocol.

Packaging, dependencies and lockfiles, software tests, CI, repository rules
and the laboratory remain pending.
Version pinning does not yet establish a fully reproducible environment
or demonstrate compatibility with future dependencies.
