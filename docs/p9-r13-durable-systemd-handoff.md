# ARDREC — P9-R13: puente durable hacia la unidad benigna systemd R12

**Base exacta:** `cd5f4eb1d1e975f25c5a482f24ced07e541577a5` (merge PR #78). **P8 operacional: NO-GO**.

## Pregunta verificable

¿Puede una reserva durable impedir un segundo inicio de la prueba systemd R12 cuando desaparece el coordinador, y puede una nueva instancia registrar el recibo dejado por el observador sin relanzar el servicio? **R13 ensaya esa propiedad solo con el fixture benigno R12 fijado por SHA-256.** No acepta comandos, destinos de red, credenciales, perfiles P8 ni parámetros `argv` arbitrarios.

## Contrato de integración

- `BenignPipeline` conserva sus cuatro fixtures existentes y agrega exclusivamente `r12_systemd`, que **rechaza la ruta `execute()` tradicional**. La única ruta de inicio para esta variante es `DurableR12Handoff.start()`.
- `RESERVED → ACCEPTED → START_INTENT` es una transacción durable en SQLite, junto con el registro del intento R13 y su fecha. Cada ID acepta **como máximo un inicio**. Una repetición jamás vuelve a llamar a `Popen`.
- El ejecutable es Python `-I`; el script fijo `lab/p9_r12_systemd_user_probe.py` se comprueba mediante su SHA-256. La ruta de evidencias se deriva de SHA-256 del identificador y tiene permisos privados.
- El observador R12 es un proceso separado del coordinador; él solicita una unidad systemd con `TasksMax=16`, `MemoryMax=134217728`, `CPUQuota=100%`, `KillMode=control-group` y `RuntimeMaxSec=11`. La unidad, no la sesión de Konsole, contiene al testigo y su descendiente. El coordinador R13 **no controla por señal un PID histórico**.
- R12 escribe `report.json` mediante reemplazo atómico y sincronización. R13 valida esquema, versión de base, resultado, límites, pertenencia declarada al cgroup y ausencia posterior observada. Custodia una muestra acotada con SHA-256 y referencia de evento transaccional. Si el recibo es válido, el resultado es `RECORDED_LIMITED` con `R12_OBSERVATION_REPORTED_PASS` o `R12_OBSERVATION_INCONCLUSIVE`. Un reporte **no equivale** a un certificado universal.
- Si no hay recibo, la reconciliación conserva `START_INTENT` hasta el plazo conservador. Después registra `RECOVERY_UNCERTAIN`, sin otro inicio ni supuesto éxito. No hay *exactly-once* operativo: se acredita una sola intención de despacho para el ID bajo el modelo SQLite.
- La ruta `recover()` del ejecutor original excluye el fixture R12 para evitar un cierre prematuro. `DurableR12Handoff.recover()` es su reconciliador específico.
- Se preservan R12 `targeted_stop_rc=5` y `general_cleanup_certified=false`; el puente **no los convierte** en éxito de parada ni de limpieza global.

## Modelo de fallos y límites

La evidencia de R13 es local al mismo UID y se respalda en SQLite FULL/WAL, hashes y recibos. La cadena hash no tiene ancla externa inmutable. Un atacante con control del mismo usuario o del sistema de archivos puede modificar a la vez almacén y evidencias. No se certifica prevención de rollback, aislamiento ante root, apagado durante escrituras, recuperación general de servicios ni limpieza de nietos arbitrarios.

Después de muerte del coordinador, el observador puede sobrevivir y completar su recibo; la unidad systemd dispone de `RuntimeMaxSec`. **Debe ejecutarse en Prometheus una prueba real de `os._exit(77)` después de `Popen` y reconciliación desde otro proceso**. Los 20 oráculos unitarios solo demuestran la lógica y las denegaciones en un entorno simulado.

## Reproducción

Con Python 3.14.7 y un worktree de la base exacta:

```bash
PYTHONPATH=src python -B -m unittest discover -s lab/tests -p test_p9_r13_durable_handoff.py -v
state=$(mktemp -d /home/cicada/Development/GitHub/ardrec-patches/P9_R13_ACTIVE_XXXXXXXX)
python -B scripts/demo_p9_r13_durable_systemd.py --state-dir "$state"
```

El demostrador ejecuta una observación normal y otra con terminación abrupta del coordinador, ambas con una unidad benigna y nueva. La segunda debe concluir con un recibo recuperado **sin repetir el inicio**. Si falta systemd o la prueba real no acredita el resultado, devolverá un estado inconcluso, no un PASS. Registrar el SHA del reporte, el código de retorno, las observaciones y la identidad exacta del commit.

## Criterios de aceptación de R13

1. Las 20 pruebas propias y todas las regresiones históricas Python/Rust pasan.
2. La prueba activa en Prometheus devuelve `PASS_TWO_BENIGN_SCENARIOS_WITH_DURABLE_RECOVERY`, conserva `start_count=1` en ambos intentos y `p8_operational=NO-GO`.
3. El archivo de alcance contiene solo los archivos del incremento; ZIP, fuente, commit y evidencias tienen hashes.
4. CI obligatoria Python/Rust, PR firmado, reglas de `main` y CI posmerge completados.

**No cierra:** P8 operacional (348 campos y 261 comprobaciones pendientes), limpieza arbitraria del árbol y del sistema, energía, custodia externa de frescura, autorización caso por caso ni conexión de A1–A10. **P9–P12 siguen parciales en su alcance operacional.**
