# ARDREC — P9-R12: servicio transitorio benigno aislado (`systemd --user`)

**Base exacta:** `1c6ea04489a685cbd9b12c9e6e0bd956839cefe9` (PR #77).

**Estado:** candidato de prueba activa acotada, NO cierre de supervisión operacional.

**P8 operacional:** **NO-GO**; 29 perfiles sin despacho, 348 vinculaciones y 261 pruebas pendientes.

## Hipótesis comprobable

El operador observó Linux 7.2.15+kali-amd64, cgroup v2, controladores `cpu memory pids`, `pidfd_open` funcional, `systemd-run` instalado y gestor de usuario en estado `degraded`. Ello **no demuestra delegación**: el cgroup actual corresponde a una pestaña de Konsole, que debe permanecer intacta. No se crearán subcgroups dentro de la terminal.

R12 intenta **una unidad `.service` transitoria nueva, con nombre impredecible y exclusivo**, a través del gestor `systemd --user` sin `sudo`. El servicio ejecuta solo Python fijo, no acepta ningún comando externo y crea un hijo benigno que cambia de PGID mediante `setsid`. El testigo permanece en el mismo cgroup mientras el líder está vivo y supera su duración. El gestor debe detenerlo al terminar el líder bajo `KillMode=control-group`.

## Propiedades solicitadas y evidencia exigida

- `TasksMax=16`, `MemoryMax=134217728`, `CPUQuota=100%`, `KillMode=control-group`, `RuntimeMaxSec=11s`, `TimeoutStopSec=2s` y `NoNewPrivileges=yes`.
- El observador independiente lee `cgroup.procs`, `pids.max`, `memory.max` y `cpu.max` **mientras la unidad está viva**. Una respuesta del gestor o un archivo de propiedades nominales no basta.
- Verifica ambas identidades `(PID, start_ticks)` y grupos POSIX distintos. Tras completar `systemd-run --wait --collect`, comprueba la ausencia puntual de **ambas identidades**. No usa `kill(PID)`, `kill(-PGID)` ni escribe `cgroup.kill`.
- Únicamente se emite `PASS_BENIGN_TRANSIENT_UNIT` cuando todas esas condiciones se cumplen. La carencia de capacidad o evidencia genera `UNSUPPORTED`/`INCONCLUSIVE`, jamás PASS.
- `systemctl --user stop` se emplea únicamente para la unidad aleatoria propia, incluso en caso de error. El límite `RuntimeMaxSec` respalda su terminación si desaparece el cliente observador.

**No certifica:** contención universal frente a evasiones del contenedor, recuperación tras muerte del gestor `systemd` o corte eléctrico, reenlace seguro de intentos durables, límites I/O o de red, ni limpieza de servicios SSH/FTP/SMB. No integra todavía `BenignPipeline`, `GroupSupervisor` ni `WitnessObservation` en una única autoridad operacional. La salida correcta del fixture es una observación local, no un permiso de ejecución.

## Reproducción en Prometheus

En una rama/worktree limpio de esta base, con Python 3.14.7, sin `sudo` y sin modificar el cgroup de Konsole:

```bash
python3 -B -m unittest discover -s lab/tests -p test_p9_r12_systemd_user_probe.py -v
state=$(mktemp -d /home/cicada/Development/GitHub/ardrec-patches/P9_R12_USER_UNIT_EVIDENCE_XXXXXXXX)
python3 -B lab/p9_r12_systemd_user_probe.py --evidence-dir "$state"
sha256sum "$state"/ready.json "$state"/report.json
```

Guardar siempre `report.json`, SHA-256, código de salida, versión del kernel/systemd y SHA del commit. `ready.json` incluye únicamente identidades de procesos benignos propios. El script nunca inventa capacidad. Antes de activar una unidad nueva, comprobar que `main` y el worktree conservan la base.

## Oráculos y continuidad

La suite de 16 pruebas (sin `systemd-run` activo en CI) comprueba denegación por cgroup ajeno, límite `max`, cuota CPU incorrecta, identidad ausente, PGID no cambiado, PID/ticks, permisos de evidencia, comandos fijos y ausencia de gestor. La prueba **activa** en Prometheus es adicional, necesaria para acreditar la capacidad allí.

Si la prueba activa funciona, el siguiente incremento integra un adaptador de ejecución benigna con reserva durable por intento y supervisor independiente de la sesión; si no, conservar NO-GO y evaluar delegación de unidad systemd o un backend alternativo explícito. Sin aprobar operaciones P8 hasta completar pruebas y autorización por caso.

## English summary

R12 is a bounded, non-operational test of an independent transient *user* service. It probes actual cgroup v2 `pids`, `memory` and `cpu` controls, observes an owned descendant that changes process group, and checks post-stop absence by PID/start-time identity. It never manipulates the terminal's cgroup, uses root privileges, executes user-selected commands or authorizes P8. Lack of proof remains an explicit failure, not success.
