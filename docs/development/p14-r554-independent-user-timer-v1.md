# ARDREC P14-R55.4 — Prueba física de independencia de temporizador de usuario (NO-GO)

**Base exacta**: merge R55.3 `ce3b9e9f30751f99d2915cef8041c82eeb3c2aec`, PR #126. R55.2-F1 privado, hash `b32855a66b5a7df8960e29c805a17f11b2e3b9902cd53ba8a44d6193b5fe33eb`.

El contrato de R55.4 **no otorga autoridad física para cambiar R34 o los bindings**. Su aportación es una prueba de proceso independiente contra un fichero sintético privado, usando un temporizador transitorio administrado por `systemd --user`. El temporizador se arma antes de escribir un estado `ALLOW_SIMULATED`, posteriormente el proceso subordinado `sleep` es terminado con SIGKILL por el propio test y el temporizador ejecuta `/usr/bin/mv` para restituir `DENY_SIMULATED`. La operación se realiza bajo la cuenta del usuario sin sudo, nft, virsh, QGA, paquetes ni cambios de servicios.

**Importante:** este experimento muestra continuidad de un temporizador de usuario respecto a la terminación de *un proceso subordinado* y no respecto a caída de `systemd --user`, logout, reinicio, interrupción del manager, falta de privilegios o fallo del host. No demuestra la recuperación de reglas R34 ni de los bindings; tampoco acredita aislamiento. Para el futuro permiso ARP/ICMP se exige una unidad supervisada por el gestor de sistema con restauración real, pruebas de falla físicas, armamento con comprobación previa al cambio, y que NO pueda desactivarse antes de restaurar el estado deny.

La ejecución del modo `--verify-offline` autentica la fuente privada R55.2-F1, no crea temporizador ni escribe evidencias. El modo `--probe-user-timer` requiere la autorización separada `--i-authorize-synthetic-user-timer-only`, crea bajo `/home/cicada/ardrec-lab/r55-watchdog/` un único directorio `0700`, archivos `0600` y manifiesto SHA256. Un test en caso de `systemd --user` inexistente bloquea sin fallback privilegiado. No vuelve a ejecutar temporizadores automáticamente. Si el temporizador queda armado pero no ha ejecutado al terminar la observación, no se cancela y el resultado es NO-GO; su efecto restante solo afecta al fichero sintético privado.

Pruebas unitarias: rechazo de nombres anómalos, delays fuera de límite, comandos manipulados, intrusión sudo/nft/virsh/shell, rutas distintas, permisos o symlinks, falsos resultados y autoridad P8; también resultados sintéticos positivos/negativos. El workflow CI ejecuta estas pruebas sin systemd ni efectos físicos.

## Instrucciones

1. Preflight fuente y test unitario en rama de PR.
2. Ejecutar `--verify-offline`, y **solo con autorización independiente** el modo físico sintético `--probe-user-timer`. Este es el único paso que crea un temporizador de usuario.
3. Verificar `SHA256SUMS`, registrar resultado, pruebas Python/Rust y trazabilidad; commit firmado y PR de merge protegido.
4. No manipular reglas ni conexiones reales hasta construir y probar la supervisión privilegiada de deny y la restauración de bindings bajo fallo parcial.

En todo resultado: `P8=NO-GO`, `physical_restore_tested=false`, `operational_dispatch=false`.
