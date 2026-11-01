# Verificación de contadores / Counter verification

## Español

Base: PR #24 integrado, commit `415d758d813f46f975d5c9b72ef64ad6ff40ffb7`.
La evidencia de sus 374 pruebas no se presenta como evidencia del incremento nuevo.

En el entorno de preparación se ejecutaron 31 pruebas nuevas satisfactoriamente,
incluidos 20 procesos terminados con SIGKILL y recuperación por HEAD. Los oráculos
comprueban explícitamente un recibo iniciado = 1, uno no iniciado = 0, dos recibos
iniciados = 2, descubrimiento = 0 y ausencia de recibo = 0. También comprueban que
los rechazos anteriores a publicación no cambian los archivos del almacén.

El entorno de preparación dispone de Python 3.12 y restringe la creación de ciertos
sockets Unix. Cinco pruebas existentes dependen de capacidades ausentes aquí: tres
de sockets de identidad del par y dos de normalización temporal de Python 3.14.
No se cambian ni omiten esas pruebas. La suite completa se debe ejecutar con Python
3.14.7 en Linux; el aplicador exige las 405 pruebas sin fallos ni omisiones antes de
firmar el commit, además de las 73 Rust y los verificadores existentes.

La validación incluye activación inicial, adopción sin reescritura, rechazo de descenso
de modo, apertura con reproducción, corrupción y 20 fronteras de publicación.
No acredita caída eléctrica, semántica de las otras seis cargas, límites de casos,
autorización operacional, ejecutor real o alineación completa de la especificación.

## English

All 31 new tests passed in preparation, including 20 SIGKILL/recovery boundaries.
Explicit count oracles distinguish started, not-started, duplicate, pending and
discovery cases. Existing full-suite target requirements remain mandatory: Python
3.14.7/Linux, 405 Python tests without skips, 73 Rust tests and existing verifiers.
Five existing tests require unavailable preparation capabilities (three pathname or
datagram Unix-socket tests and two Python 3.14 timestamp-normalization tests).
No tests are bypassed or modified to obtain a pass. This is scoped counter validation,
not power-loss testing, operational authorization or complete analytical semantics.
