# ARDREC — P9-R14: parada positiva de unidad benigna activa

**Base exacta:** `1a50e30a37e43bddb8897dbf0b21b79662bb5ad9` (PR #79).

**Objeto:** incorporación reproducible del ensayo activo de terminación controlada P9-R14, aislado de los perfiles P8.

## Resultado observado antes del incremento

El ensayo local en Prometheus (`P9_R14_ACTIVE_STOP_459NKlKV`) confirmó la pertenencia de dos procesos benignos de UID 1000 al mismo cgroup transitorio `systemd --user`, con grupos POSIX distintos, `pids.max=16`, `memory.max=134217728` y `cpu.max=100000 100000`. Ambos tenían identidades PID/start_ticks presentes antes de la parada; `systemctl --user stop` sobre la unidad propia devolvió 0. Tras la orden, las dos identidades estaban ausentes y el cgroup de esa unidad dejó de existir. Se conservan `active.log` SHA-256 `0582b7ea65750e5a2fd680cce999d2f0b970c7cba28d7df1f5fa597907934e4b` y `r14_report.json` SHA-256 `d683269152c21af07667eba201de086f7ad6074b4e8afed4c70b69c8331edb6b` en custodia local. Este resultado **no** acredita limpieza de todos los procesos posibles.

## Implementación reproducible

`lab/p9_r14_active_stop_probe.py` utiliza exclusivamente el ejecutor benigno R12 fijado por SHA-256; no modifica R12 ni R13. Genera un nombre aleatorio `ardrec-p9r12-<12 hex>.service`; lo inicia mediante `systemd-run --user` con `KillMode=control-group`, `TasksMax=16`, `MemoryMax=134217728`, `CPUQuota=100%`, `RuntimeMaxSec=11` y `NoNewPrivileges=yes`. Nunca recibe un comando libre ni un PID o nombre de servicio proporcionado por el solicitante.

La aceptación verifica (1) dos identidades vivas y el cgroup propio antes de la orden, (2) estado `is-active` de systemd, (3) código 0 de `systemctl --user stop`, (4) ausencia posterior de ambas identidades, (5) ausencia o `populated 0` del cgroup observado y (6) código 0 del wrapper. Toda lectura incompleta/denegada, límite distinto, parada fallida o ausencia no acreditada da `INCONCLUSIVE`, nunca éxito. Los recibos JSON se escriben con exclusión, permisos 0600 y fsync mediante la función fijada de R12; no se sobrescribe un resultado previo.

La prueba real activa **no se ejecuta automáticamente en CI**: GitHub Actions únicamente corre las pruebas negativas e independientes del oráculo. Prometheus debe reproducirla expresamente sobre su entorno Linux para evaluar esta versión.

```bash
python3 -B -m unittest discover -s lab/tests -p test_p9_r14_active_stop_probe.py -v
state=$(mktemp -d /home/cicada/Development/GitHub/ardrec-patches/P9_R14_ACTIVE_UNIT_XXXXXXXX)
python3 -B lab/p9_r14_active_stop_probe.py --evidence-dir "$state"
sha256sum "$state"/ready.json "$state"/r14_report.json
```

Los controles siguen aplicándose al ámbito benigno de una unidad generada para la prueba, sin `sudo`, sin escrituras en `/sys/fs/cgroup` ni señales a procesos ajenos. Si una prueba queda inconclusa, conservar el directorio y su contenido para análisis, sin inferir `PASS`.

## Alcance que **no** se cierra

La salida correcta **no demuestra** propiedad universal del árbol, limpieza de nietos arbitrarios, invariancia bajo fuga de sesiones, reinicio/crash de systemd, pérdida de energía, recuperación universal de P12, ni ejecución *exactly once* de operaciones reales. Aunque la prueba inspecciona `cgroup.events`, esto no confiere una autorización de despacho. El puente durable P9-R13 permanece separado del comando de parada R14; combinar ambas rutas exige una fase posterior y comprobación adicional.

**P8 operacional: NO-GO.** Se mantienen los 29 perfiles simbólicos sin autorizar, 348 vinculaciones materiales y 261 pruebas de puerta pendientes. `AL-06`, `AL-07`, aceptación funcional integral y validación experimental siguen abiertos.

## English summary

Bounded user-systemd active-stop test, pinned to the R12 benign fixture. Requires live identity ownership, effective resource limits, a successful scoped stop command, subsequent absence of the two observed identities, and disappearance/empty state of that transient cgroup. CI tests exercise negative gates only; the active test must run on Prometheus. No universal cleanup or operational P8 authority is claimed.
