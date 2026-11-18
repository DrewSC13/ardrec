# ARDREC R82 — Integridad transaccional de estados sintéticos y recuperación

**Base:** merge R81 `717b9ac713c2db2bc6d43d1a4ef067a4f2f74afa`. Incremento de pruebas de software, no de capacidades operacionales.

## Funcionalidad demostrada

R82 recibe una sesión DEV R81 previamente generada y autenticada. Conserva la base R81 **sin ejecutarla otra vez**. Construye una simulación independiente R58-Q/R/S/T/U usando el catálogo sintético histórico de 29 casos; estos casos **no son** las 54 unidades de A2 ni las 25 familias A5–A7. La separación está declarada en el manifiesto.

El motor R58-S deniega todas las transiciones operacionales. Dentro de bases SQLite privadas y aisladas, R58-T simula dos T1 `PREPARADO→PENDIENTE` con control de revisión. R58-U simula una secuencia T8 `PAUSAR`, T9 `REANUDAR`, T10 `DETENER`, verifica la inmutabilidad de `DETENIDO` y mantiene una segunda unidad simulada en `PENDIENTE`. Son transiciones del **modelo contrafactual**, no transiciones del estado real ARDREC.

R82 inyecta fallos **antes de COMMIT** tanto para T1 como para T8, verifica rollback atómico, repite los requests por ID sin duplicación y reconstruye los hashes enlazados del libro de eventos y sus proyecciones SQLite. Después persiste `MANIFEST.json` en un directorio nuevo. Una segunda lectura `--verify` no invoca A5 ni procesos externos, y rechaza cambios en R81, el journal de eventos, el manifiesto, permisos y estructura.

## Garantías y no garantías

- A1–A10 R81: verificados como origen del software DEV, *no se vuelven a ejecutar*.
- R58-S: sin autorizaciones, todas las solicitudes operacionales denegadas.
- R58-T: dos T1 **simulados**, con un rollback y un replay.
- R58-U: T8, T9, T10 **simulados**, con un rollback, un replay y rechazo de reentrada en fase terminal.
- No hay correlación de esas identidades R58 con las 25 intenciones de R76: esto **no** valida la unión operacional completa A3–A8 de la tesis.
- `A6=ND`, `Rf` confirmado `null`, cero transiciones operacionales, cero acciones VM, cero GEN2 y `P8=NO-GO`.
- Aceptación funcional del sistema `PENDING`; validación experimental `NOT_RUN`. Hallazgos AL-06 y AL-07 abiertos.

## Contrato del ejecutor

```zsh
cd /home/cicada/Development/GitHub/ardrec
umask 077
PYTHONPATH=src python3 -B scripts/ardrec_p14_r82_model_transition_recovery.py \
  --create --work-dir /home/cicada/ardrec-lab/r82-demo-NUEVO \
  --r81-receipt /home/cicada/ardrec-lab/r81-demo-20261118T150017Z-17325 \
  --expected-r81-sha256 e9cdf34c13074ed42b48282c642912c26fc27bf98aaa281c16f1dc29b7188ac5 | more

PYTHONPATH=src python3 -B scripts/ardrec_p14_r82_model_transition_recovery.py \
  --verify --work-dir /home/cicada/ardrec-lab/r82-demo-NUEVO \
  --r81-receipt /home/cicada/ardrec-lab/r81-demo-20261118T150017Z-17325 \
  --expected-r81-sha256 e9cdf34c13074ed42b48282c642912c26fc27bf98aaa281c16f1dc29b7188ac5 | more
```

Crear una sola vez. Si se interrumpe la creación, no reiniciarla sobre el mismo directorio; revisar el artefacto parcial. No se usan sudo, root, host-network, VM, Rust executor, sockets o systemd. El manifiesto local y sus hashes **no son una certificación científica ni una cadena de custodia independiente**.
