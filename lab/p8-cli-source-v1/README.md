# ARDREC P8-R11 — Fuentes documentales locales de interfaces CLI

## Español — finalidad, procedencia y límites

**Roadmap: punto 8 exclusivamente.** Base protegida de origen: merge P8-R10 `4412a1093eafbfcf61b52c647963511f01725576` (PR #43). R11 no implementa P9, A1–A10, ejecución de SSH/FTP/SMB ni cambios de configuración del laboratorio.

`evidence.json` fija la evidencia **comunicada por el operador** tras inspeccionar la imagen base `runner-base.qcow2` con herramientas del anfitrión y acceso de solo lectura. Incluye huellas SHA-256, tamaños comprimidos y descomprimidos de siete manuales instalados (`ssh`, `ssh_config`, `ssh-keyscan`, `sftp`, `curl`, `smbclient`, `rpcclient`); versiones exactas y campos **Depends** de cuatro paquetes (`openssh-client`, `curl`, `smbclient`, `python3`); y 29 vínculos de **documentación candidata** con las intenciones de P8-R10. La imagen QCOW2 y sus cuatro paquetes y quince hashes del runner ya fueron registrados en P8-R9.

El campo `documentation_candidates` **no afirma que una operación esté soportada**. Los manuales se han cotejado a nivel de bytes, **no se han leído/interpretado normativamente sus opciones de CLI**; la existencia de un manual no prueba que el ejecutable real acepte una opción determinada. `Depends` es una declaración del paquete, no una validación del grafo recursivo de dependencias, del cargador dinámico ni del origen del binario. Las siete fuentes están subordinadas a la identidad de la imagen original, no constituyen una custodia futura de materiales.

En las 29 filas, los controles permanecen en **denegación estricta**: sin gramática de flags, `argv`, shell remoto SSH, lenguaje de órdenes `smbclient -c`, contenedor privado de credenciales, entorno, auxiliares resueltos, caso autorizado, presupuesto piloto o recibos de limpieza. Cinco perfiles de escritura mantienen condiciones de limpieza definidas anteriormente en P8-R10, pero aquí no se produce ni acredita ninguna limpieza. SSH-T03 sigue sin mecanismo de contraseña autorizado: la ausencia de `sshpass` es una observación, no un mandato para instalarlo.

### Validación

- `python3 lab/verify_p8_cli_sources.py`: valida los archivos versionados, la identidad de R9/R10 y los 29 perfiles, **sin ejecutar programas externos**.
- `python3 -m unittest discover -s lab/tests -p test_p8_cli_sources.py -v`: pruebas adversariales y anclaje de las fuentes reales del repositorio.
- `sudo -v` seguido de `python3 lab/verify_p8_cli_sources.py --offline-image`: relectura de la misma QCOW2 mediante `sudo -n` y **solo** `stat`, `sha256sum`, `qemu-img`, `virt-cat` del anfitrión. Nunca ejecutar el Python del repositorio con `sudo`. **No ejecutar clientes del guest**. No publicar los manuales ni material de credenciales en el repositorio.

R11 verifica el contenido físico de los siete manuales y la declaración exacta de dependencias, no la semántica de flags. La revisión semántica de opciones por versión y la especificación segura de serializadores de operaciones quedan para incrementos posteriores de P8. AL-06, AL-07 y siete obligaciones permanecen abiertas; 29 perfiles bloqueados, 0 casos autorizados, 0 despachos y 0 validación experimental.

## English — scope

Operator-reported QCOW2 documentation and dpkg `Depends` pins, without option-semantic review, dynamic-library closure, runnable argv, remote command language, trusted materials, permissions, real case, pilot limits, dispatch or algorithms. Seven manuals and four package declarations, mapped as **source candidates** to 29 disabled variants. No tool, VM or laboratory network execution.
