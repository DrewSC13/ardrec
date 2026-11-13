# ARDREC — P9-R15: entrega durable para parada activa benigna

**Base exacta:** `4dc793293eb9dd38792e1a0b643b110c4b1b99dd` (PR #80).

**Frontera:** P9–P12 en desarrollo con dos fixtures diferentes: `r12_systemd` (R13) y `r14_systemd_stop` (R15). No existen argv, comandos de servicio ni perfiles SSH/FTP/SMB controlados por el solicitante. P8 operacional permanece **NO-GO**.

## Reglas de custodia

1. El coordinador valida el código R14 por SHA-256 y registra una sola transición durable `START_INTENT` con `start_count = 1` en SQLite (`WAL`, `synchronous=FULL`), antes de ejecutar el observador.
2. El observador R14, de código fijo, solicita un **servicio transitorio benigno de systemd --user**, con nombre aleatorio y propio. Únicamente él puede ordenar su parada. El puente R15 **nunca** envía `stop` a partir de PID, nombre o cgroup histórico ni llama a `systemctl`.
3. El observador escribe `ready.json` y `r14_report.json` privados. R15 acepta `PASS_OWNED_ACTIVE_STOP` solamente cuando identidad de unidad, UID, PID, start_ticks, PPID, PGID, cgroup y límites efectivos son concordantes, y cuando se observó `targeted_stop_rc = 0`, las dos identidades ausentes y el cgroup ausente/no poblado.
4. Dos artefactos (`stdout`=reporte, `stderr`=ready) reciben hashes SHA-256 y forman parte del registro de eventos encadenado. Los nombres de artefactos no representan salida de terminal ni capturas arbitrarias; contienen exclusivamente JSON propio acotado.
5. Si el coordinador desaparece, una nueva instancia **solo reconcilia** recibos. No relanza el observador. Sin recibo suficiente al vencer el plazo, clasifica `RECOVERY_UNCERTAIN` y prohíbe el reintento automático.
6. El método `BenignPipeline.execute` y el recuperador legado niegan tanto `r12_systemd` como `r14_systemd_stop`. Las dos familias tienen diferentes reservas, recibos y fingerprints.

## Pruebas y límites

La CI ejecuta las pruebas negativas y la recuperación sintética por separado; **no crea servicios systemd**. La prueba activa en Prometheus debe demostrar dos escenarios R15: ejecución directa y caída real del coordinador (`exit 77`) seguida de reconciliación sin relanzamiento, ambas con parada activa de la unidad propia.

El resultado de R14 en Prometheus acreditó parada efectiva de **una unidad propia** con `systemctl --user stop` código 0 y ausencia posterior de dos identidades y su cgroup. R15 no transforma esa evidencia en limpieza general ni en control sobre unidades preexistentes o externas.

**Pendientes explícitos:** muerte del gestor systemd, power loss, pérdida de disco/SQLite, garantías de durabilidad entre dispositivos, identidad de todos los descendientes arbitrarios, custodia externa de frescura y autorización concreta P8. `AL-06`, `AL-07` y aceptación experimental siguen abiertos hasta cumplir sus pruebas correspondientes.

## English summary

R15 attaches a bounded R14 active-stop observation to a separate durable, single-intent SQLite workflow. A crashed coordinator can reconcile pinned private receipts **without restarting or stopping historical units**. Negative evidence cannot become a positive stop result. System-wide cleanup, power-loss survivability and operational P8 authority remain unproven.
