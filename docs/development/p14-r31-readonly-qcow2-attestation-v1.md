# P14-R31 — Verificación acotada de artefactos QCOW2 (solo lectura)

## Procedencia y dependencia

Se aplica únicamente después de integrar R30-H1 (`f44c38c6cb3780559d7bc7ba0354c226f4591301`), como segundo padre de un merge cuyo primer padre sea `8231b8da5db66f918d812d8305b6243c568c53ae`. Consume el reporte R30 efectivamente registrado, con SHA-256 del archivo suministrado por el operador y validado **antes de toda llamada privilegiada**.

## Capacidad de software

- **PLAN_ONLY:** valida R30 y enumera exactamente cuatro bases y cuatro overlays conocidos, sin procesos externos ni acceso al anfitrión.
- **EXPLICIT_SUDO_READONLY:** requiere bandera explícita y usa `sudo -n` sin shell sobre tres binarios absolutos: `/usr/bin/stat`, `/usr/bin/sha256sum`, `/usr/bin/qemu-img`. El código Python permanece bajo el UID del operador; **nunca se ejecuta Python como root**.
- Antes de abrir los QCOW2 valida metadatos de cada padre (tipo, propietario y escritura), tipo, propietario y permisos del archivo. Verifica metadatos antes y después de leer, hashes completos de las bases contra huellas históricas fijadas, y la relación backing overlay → base de cuatro roles. Los hashes actuales de overlays se registran como observación, sin un oráculo histórico que acredite su integridad.
- Si `sudo -n` no está autorizado, un archivo cambia durante la lectura o se observa una discrepancia, se produce `CURRENT_ASSET_CUSTODY_INCOMPLETE`. No se pide contraseña, no se cambian permisos y no se reintenta en secreto.

## Semántica y límites

`READONLY_VERIFIED` es **verificación de metadatos y lectura de bytes de una ruta concreta en un instante**. No certifica imagen arrancable, identidad del invitado, frescura de custodia externa, aislamiento, ausencia de todas las condiciones de carrera, ni autoriza una acción operacional. Para todo reporte: `can_restore=false`, `operational_dispatch=false`, `vm_started=false`, `images_mutated=false`, `backing_chain_custody_accredited=false`, `p8_operational=NO-GO`, sin generación ni Rf.

Un lector privilegiado puede acceder a archivos sensibles. El operador debe contar con autorización local para inspeccionar estas imágenes. Si `sudo -n` no funciona, registrar `ACCESS_OR_PATH_GUARD_FAILED` y resolver la autorización mediante su administración habitual; **no editar sudoers o ACL automáticamente**.

## Ensayos de aceptación

- Pruebas de scope estricto: no rutas variables, no comandos arbitrarios, no shell.
- Rechazos: hash original alterado, backing distinto, padre inesperado, fallo sudo, cambio de metadatos y campos de autoridad falsificados.
- Reproducibilidad de PLAN_ONLY en bytes. La auditoría física se ejecuta una vez: repetir un hash voluminoso no sustituye la custodia externa de origen.
- Ejecutar las regresiones P14, oráculos y trazabilidad, conservar recibos externos y crear commit firmado solo después de la aprobación.

Este paso aún **no** genera reactivación, pentesting, evidencia A6 acreditada ni transición A8/A9. La restauración autorizada requiere un incremento ulterior, verificación física nueva y aprobación operacional explícita.
