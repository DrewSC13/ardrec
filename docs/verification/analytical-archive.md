# Verificación del archivo analítico / Analytical archive verification

## Español

Alcance: escritura y recuperación del conjunto de proyecciones, manifiesto y objetos
del contrato del PR #21. No verifica semántica de cargas, autoridad global o A1–A10.
Datos sintéticos de desarrollo; no pertenecen a la muestra experimental.

| Grupo | Evidencia prevista |
| --- | --- |
| Persistencia | Recuperación tras cierre, bytes exactos y selección explícita de generación |
| Inmutabilidad | Escritura repetida conserva inodos y tiempos; corrupción no se sobrescribe |
| Resolución | Objetos ausentes, metadatos corruptos y huellas incorrectas se rechazan |
| Frontera previa | Un candidato inválido no deja archivos del conjunto |
| Aislamiento | Bloqueo de escritor, propietario, permisos, hilo y sesión cerrada |
| Rutas | Rechazo de symlinks, hardlinks, FIFO, sustitución de raíz y bloqueo |
| E/S | Escrituras cortas, cero progreso, ENOSPC y fallos de fsync |
| Interrupciones | Siete puntos de fallo inyectado y cinco puntos de SIGKILL real |
| Recuperación | Conjunto anterior intacto; el nuevo es íntegro o no está instalado |
| Límites | Tamaños de objeto/conjunto; sin promoción de temporales o huérfanos |

El módulo añade 27 pruebas descubiertas por la CI Python existente. Total esperado:
329 pruebas en el entorno del proyecto, Python 3.14.7. Los ensayos iniciales de estas
27 pruebas se ejecutaron en Linux con Python 3.12; el script de aplicación exige
aprobar las 329 y empaquetado limpio en el entorno del proyecto antes del commit.
Los resultados locales y de CI se registran después, sin reescribir esta previsión.

```bash
PYTHONPATH=src python -m unittest discover -s tests/unit -p 'test_analytical_archive.py' -v
```

Las pruebas SIGKILL usan procesos hijos identificados de la propia prueba y archivos
temporales. No matan procesos externos. Se ejecutan antes de la prueba de hilo para
evitar heredar hilos activos; cada hijo se espera y libera. El código solicita
explícitamente el método `fork` en Linux. No se afirma portabilidad a Windows.

Faltan validación del sistema de archivos y pérdida de energía en el laboratorio,
anclaje de frescura y origen confiable de la huella, publicación global y recuperación
integrada. Ningún resultado del archivo cierra por sí solo AL-06, AL-07 o el punto 1.

## English

Twenty-seven storage tests cover exact reopening, explicit snapshot selection,
idempotence, corruption, missing objects, private permissions, nonregular files,
symlinks/hardlinks, exclusive writers, replaced paths, session ownership, short/zero
writes, disk-full and synchronization failures. Seven injected fault boundaries and
five real child-process SIGKILL boundaries verify preservation of the prior snapshot
and rejection of incomplete candidates. Initial component tests ran on Linux/Python
3.12; the apply script requires all 329 tests and clean packaging on Python 3.14.7.

Tests use synthetic temporary data and kill only their own children. No laboratory
services are invoked. Filesystem/power-loss validation, trusted/fresh anchors, global
publication and integrated recovery remain pending. This is not full-system,
algorithmic or experimental acceptance.
