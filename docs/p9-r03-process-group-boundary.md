# ARDREC — P9/R03: supervisión Linux de grupos

Se extiende el supervisor de procesos P9 existente.

Se utiliza rustix con la característica process y sin FFI
unsafe dentro del código ARDREC.

El supervisor valida que el proceso líder pertenezca a
un grupo independiente, aplica un plazo monotónico,
envía SIGTERM, espera una gracia acotada y escala
mediante SIGKILL antes de recoger al líder.

Las pruebas utilizan únicamente procesos locales benignos
generados por el propio ejecutable de pruebas.

## Límites y garantías pendientes

- El estado DeadlineEscalated prueba el envío de SIGKILL,
  no que fuera necesario ni que se limpiaran todos los recursos.
- La ausencia puntual del PGID no certifica limpieza global.
- Los descendientes pueden cambiar de grupo o sesión.
- No hay supervisión mediante cgroups ni namespaces.
- No existe garantía de recuperación si muere el supervisor.
- Una salida natural del líder no demuestra limpieza del árbol.
- Un proceso que no responda a SIGKILL puede impedir wait.
- No se autoriza ninguna solicitud P8.

P8 contractual: COMPLETO.
P8 operacional: NO-GO.
P9 operacional: NO-GO.
AL-06 y AL-07: ABIERTOS.
