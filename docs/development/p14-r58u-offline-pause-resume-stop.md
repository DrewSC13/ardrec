# ARDREC R58-U — T8/T9/T10 contrafactuales auditables

## Alcance

- Base fija: `6099ec3ed37688ee9a3e494eba4db0c1a581bac6` (R58-T fusionado).
- **No** muta `src/ardrec/state.py`, la base R58-T, las máquinas virtuales, redes ni el diario A5.
- Crea una base SQLite **separada**, únicamente en un directorio absoluto, privado y proporcionado explícitamente; la demostración emplea `TemporaryDirectory`.
- Antes de cada operación verifica el recibo denegatorio R58-S y la base R58-T con su cadena de T1. El encabezado SHA y el conjunto de casos se fijan a la nueva base.
- `T8`: `PENDIENTE → PAUSADO`; `T9`: `PAUSADO → PENDIENTE`; `T10`: `PREPARADO/PENDIENTE/PAUSADO → DETENIDO`, **solo dentro del modelo**.
- Las referencias `SIM_*` de los tres cambios **son supuestos de fixture**, no autorizaciones ni evidencias acreditadas. No se invoca `transition_service`, ninguna capa de despacho ni mecanismos de host.

## Propiedades comprobables

- CAS de revisión, escritura transaccional de evento y estado, `PRAGMA synchronous=FULL`, `BEGIN IMMEDIATE`, y rollback antes del commit.
- Repetición idéntica por `request_id`, rechazo de conflictos, hash encadenado y reconstrucción de la máquina simulada desde un origen T1 verificado.
- Detención absorbente, bloqueos de transición fuera de fase, preservación de referencias de espera y cambio de autorización **en el fixture** al reanudar.
- Regla de presupuesto: máximo ocho eventos por caso; no hay reclasificación A6, riesgo final Rf ni publicación A9.
- El hash encadenado detecta modificaciones accidentales e inconsistencias, pero **no sustituye una firma externa, una ancla de confianza independiente ni protege contra reescritura coherente por un adversario con control completo del archivo**.

## Validación

```
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58u_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58u_pause_recovery_demo.py --synthetic-offline
```

## Invariantes permanentes

`R34 DENY`, F11 inactivo, `P8=NO-GO`, A6=`ND`, `operational_transitions_applied=0`.
El proyecto todavía no tiene una campaña física ni un A1–A10 validado experimentalmente.
