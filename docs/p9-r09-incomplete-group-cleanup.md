# ARDREC — P9/R09: terminación incompleta del grupo

## Problema corregido

Una salida natural del proceso líder no demuestra
que todos los procesos del grupo hayan terminado.

P9/R09 introduce el resultado tipado:

`LeaderExitedGroupNotProvenAbsent`

Se utiliza cuando el líder ya ha terminado pero
la ausencia del grupo no quedó acreditada.

Este resultado:

- No equivale a limpieza completada.
- No habilita despacho ni autorización.
- Conserva el código de salida del líder.
- Impide que el supervisor vuelva a señalizar
  un PGID después de recoger al líder.
- Permanece estable ante consultas repetidas.

## Pruebas

Se agrega un segundo proceso benigno al mismo grupo
POSIX que el líder.

El miembro superviviente permanece como hijo directo
del test, que conserva su propiedad y lo recoge.

Estas pruebas acreditan clasificación de un grupo
superviviente; no acreditan todavía gestión completa
de descendientes huérfanos o separados.

## Límites pendientes

- Seguimiento completo del árbol de procesos.
- Tratamiento de descendientes que cambian de grupo.
- Limpieza verificada mediante mecanismos de aislamiento.
- Recuperación tras fallo del supervisor.
- Límites de recursos aplicados y observados.
- Aceptación operacional.

P8 contractual: COMPLETO.
P8 operacional: NO-GO.
P9 operacional: NO-GO.
AL-06 y AL-07: ABIERTOS.

Los 29 perfiles P8 permanecen bloqueados.
