# R116-F13 — Cierre de integración de fuentes, NO-GO operacional

## Objetivo académico y alcance

Se integran las mejoras de código de R116-F1–F12 sobre la rama de trabajo y se someten a CI obligatorio. El cierre es **SOURCE_ONLY** y mantiene **NO-GO** operacional. No autoriza la utilización física del catálogo ni acredita los resultados A1–A10 de tesis en un laboratorio ejecutado bajo R116.

## Funcionalidad y evidencias que sí se conservan

- Guardián F1 para DENY 5/1 y recuperación, controlador de sesión FTP-T01 F3 con presupuesto acotado, verificación de autorización F2 y revisión de instalación F4.
- Corrección F8 de importaciones sin `__pycache__` en paquetes raíz; migración física F9B ya registrada en expediente privado externo al repositorio.
- Las verificaciones reportadas por Prometheus de F10/F11: lectura DENY 0/6 y re-aplicación idempotente tras temporizadores configurados en 60 segundos, con duración observada de ~63 segundos. No implican restauración desde reglas permisivas ni recuperación 5/1.
- F12 rebase de arranque SSH → runner → FTP sobre HEAD vigente y respaldo DENY programado a **45** segundos para una ventana declarada de máximo **60** segundos; sin afirmar garantía dura de 60 segundos.
- Catálogo P7 25 familias SSH/FTP/SMB fijado, `DRAFT_NOT_CALIBRATED`, no ejecutable.

## Limitaciones explícitas y separación de autoridades

- **NO_ADMITIDO**: la observación histórica R114 de FTP `220` es un intento físico consumido y conservado, con A6=ND. No se reabre ni se convierte en vulnerabilidad automáticamente.
- El código raíz R116-F12 no ha sido reinstalado ni probado físicamente en Prometheus. Se requieren migración raíz versionada y revisión administrativa independiente.
- La autoridad independiente de alcance, boot y piloto **no está provisionada**; las firmas de desarrollo/test no sustituyen una autorización real.
- No están acreditados los arranques R116 actuales, los cinco vínculos DENY activos y uno ausente con SMB apagada, ni el watchdog ante fallo y restauración de reglas permisivas.
- El respaldo a 45 segundos no prueba un cierre físico estricto antes del segundo 60. Deberán acreditarse restricciones adicionales capaces de fallar en modo cerrado incluso ante latencia/suspensión del anfitrión.
- **P7=DRAFT; A5 físico nuevo=NOT_ATTESTED; A6=ND; A7 confirmado=NONE; A8 aplicado=NONE; A9=NOT_PUBLISHED; P8=NO-GO**.

## Criterios de aceptación de este cierre

1. Guardar hashes SHA-256 de 87 archivos firmados del baseline R116-F12, sin contar dos veces los archivos modificados, más la actualización de CI de F13.
2. Ejecutar el gate F13 que comprueba integridad, semántica de no aceptación, 25 familias, respaldo 45/60 y documentación de requisitos abiertos.
3. Ejecutar 210 pruebas R116, 440 R115, 250 R114, 350 R113 y 303 R112, sin pruebas omitidas (1.553 total); Git firmado y árbol limpio.
4. Publicar PR a `main`, comprobar CI independiente Python y Rust, revisiones obligatorias y protección de rama; merge normal sin bypass ni force.
5. Conservar todos los recibos físicos privados; sin arranque, tráfico, `sudo`, `systemd-run`, cambios en nftables, root deploy o emisión de autoridad durante F13.

## R117 — Funcionalidad pendiente

R117 debe empezar con validación y migración del código raíz F12 y atestación física del watchdog con red cerrada, luego autorizaciones externas, cadena SSH→runner→FTP, piloto limitado P7 y validación de soporte A5/A6, riesgo A7, transiciones A8, generaciones A9, TUI A10. El merge F13 **no cambia estos resultados** ni constituye permiso de laboratorio.
