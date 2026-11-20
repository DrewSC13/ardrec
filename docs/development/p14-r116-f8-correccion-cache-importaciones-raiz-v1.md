# R116-F8 — Corrección de importaciones que contaminan paquetes raíz estrictos

## Incidencia observada (Prometheus, 20-11-2026)

R116-F7 autenticó los paquetes R113 y R114 en modo lectura. Al ejecutar la comprobación DENY mediante R116-F1, el proceso detuvo su ejecución con `DenyGuardError:root_bundle_file_scope`. El origen que reproduce ese patrón es la carga `importlib.util.spec_from_file_location(...).loader.exec_module(...)`: Python intenta escribir `__pycache__` en el directorio del módulo histórico antes de que `root_bundle()` valide su lista exacta de archivos.

La presencia real de esta caché en el anfitrión deberá confirmarse mediante inspección root. La reproducción aislada demuestra la causa de software; no certifica el estado actual de nftables.

## Cambios funcionales

1. `R116-F1.historical()`: autentica los bytes de R113 mediante SHA-256, compila los bytes en memoria y ejecuta el módulo con `__file__` fijado al origen protegido. No usa importadores que escriban caché antes de `root_bundle()`.
2. `R116-F3.old_ftp_material()`: autentica el SHA-256 fijo del ejecutor R114 y lo carga en memoria antes de verificar el material histórico de FTP. No utiliza la ventana antigua de 120 segundos.
3. `R116-F3.root_guard_library()`: comprueba el SHA-256 firmado de F1 y compila en memoria sin crear una caché que alteraría el conjunto de archivos raíz permitido por F1.
4. F3 establece `sys.dont_write_bytecode=True` antes de cargar las dependencias Python de su árbol de ejecución protegido.
5. Manifiestos de F1 y F3 recalculados exactamente contra las fuentes nuevas. Los manifiestos anteriores **no** se sobrescriben por este parche de repositorio.
6. Dieciséis pruebas nuevas de importación sin caché, integridad, adulteración y alcance. La suite R116 se descubre en el CI ya registrado mediante `test_p14_r116*.py`.

## Alcance y límites

Este parche es **SOURCE-ONLY**, con commit firmado y regresión completa. No instala código privilegiado, no mueve ni borra `__pycache__`, no arma temporizadores, no inicia VM, no altera `nftables`, no abre sockets, no crea documentos de autoridad y no habilita P7/P8.

Las instalaciones protegidas de F1 y F3 correspondientes al commit anterior aún existen en `/var/lib/ardrec`. La actualización operacional posterior deberá inspeccionar sus contenidos, preservar cualquier caché de R113/R114 como evidencia, preparar nuevas copias desde fuentes firmadas y efectuar una sustitución controlada y reversible, sin iniciar ninguna ventana FTP. Hasta completar ese proceso y atestar el DENY físico se conserva `A5=NO-GO`, `A6=ND`, `P8=NO-GO`.

## Pruebas de aceptación de fuentes

R116: 168; R115: 440; R114: 250; R113: 350; R112: 303. Total: **1.511**, cero pruebas omitidas. La ejecución fuente no es una prueba física del recuperador o de una expiración real.
