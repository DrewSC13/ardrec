# ARDREC P14 / R58-L — Integración A4 y control de intención A5, exclusivamente sintético

**Base de desarrollo / Development base:** merge firmado PR #143: `8aad0fd43e451de2c33a1e42fe9b6240fcd23c8f`.

**Fuentes fijadas:** catálogo P7 original SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`; tesis SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

## Alcance comprobable / Verifiable scope

`build_a4_a5_review` recibe 1 a 54 entradas explícitas con servicio, unidad de familia, riesgo matemático y bandera **simulada** de aplicabilidad. Reutiliza **sin modificar** el coordinador R58-K que integra 8 familias SSH, 8 FTP y 9 SMB, así como sus variantes independientes CONTROL/DATA, SIGNING/ENCRYPTION, READ/WRITE. Cada caso mantiene su identificador académico; para los cálculos A4/A7 se utiliza exclusivamente `case_id_a7`, hash con separación de dominio que también incorpora servicio, sesión, caso e índice.

A4 llama al selector original `ardrec.selection.greedy_development.select_development`, conservando su orden exacto `(-PA, precedencia, idServicio, idCaso)` y sus guardas `PENDIENTE`, `VERDADERO`, aplicabilidad explícita. No infiere aplicabilidad de la clasificación positiva o negativa. El contexto de sesión A4 queda asociado a la huella del reporte unificado y al supuesto de aplicabilidad. La evidencia A4 es siempre `'0'` en la **proyección sintética** porque A6 no ha acreditado evidencia; esa convención no representa medición de evidencia real ni debe alimentar una selección operacional. El motor A4 heredado solo maneja prioridades de desarrollo.

A5 introduce un **contrato de revisión de intención**, sin lanzar ni reservar intentos. Una intención opcional debe coincidir exactamente con el ganador A4 e indicar `SYNTHETIC_REVIEW_ONLY`. Un historial simulado puede contener a lo sumo un intento ordinario por identidad completa; incluye estados `RESERVED`, `START_INTENT`, `RECOVERY_UNCERTAIN` o `RECORDED_LIMITED`. El historial nunca se afirma como verificado físicamente. Cuando el caso elegido figura en él, cualquier intención nueva queda `BLOCKED_ORDINARY_BUDGET_CONSUMED_NO_RETRY`, incluso ante recuperación incierta. No existen reintentos ocultos ni contadores autoritativos. El presupuesto es una **guarda de revisión** de un intento ordinario, no una aprobación ni calibración de tiempos, transferencia o memoria.

Los resultados A6 de H/I/J conservan seis clases **hipotéticas**; la clasificación acreditada sigue `ND`. R58-K continúa generando intervalos exactos A7 de evidencia no resuelta `[0,1]` y recomendación A8 `PAUSAR_HASTA_EVIDENCIA_AUTORIZADA`. Se prohíbe promover resultados a A6, reducir la incertidumbre A7, aplicar transiciones A8/A9, despachar P8, activar F11, iniciar VM o cambiar configuraciones de host. R34 DENY y P8 NO-GO permanecen sin cambios.

## Límites explícitos

Este incremento **no implementa** todavía el ejecutor físico A5, ni reemplaza el diario durable de `BenignPipeline`, ni la máquina de estados autoritativa A1–A3/A9. No hay límites numéricos calibrados de piloto, acreditación técnica independiente, 54 unidades experimentadas o validación de hipótesis. El supuesto `applicable=True` y el historial son datos de un ejercicio reproducible, **nunca autorizaciones**. Los lotes con múltiples sesiones se rechazan para evitar seleccionar entre campañas no comparables. El estado de máquina verdadero no se altera.

## Pruebas / Tests

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58l_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58l_a4_a5_review_demo.py --synthetic-offline
```

Se comprueban identidad, normalización por permutación, estado no PENDIENTE, guardas `ND`/`FALSO`, aplicabilidad, precedencias de variantes, rechazo de intención no seleccionada, duplicación de intentos, ausencia de reintentos, clasificación no acreditada, integridad de reportes y conservación de A7/A8. La demostración usa **exclusivamente** el catálogo original fijado, nunca un archivo modificado.

## English summary

R58-L adds a source-only synthetic A4 ranking and A5 attempt-intent *review* over the previously unified R58-K family-to-A6/A7/A8 chain. It preserves exact R27 selection ordering, one-session identity separation, one ordinary-intent budget and no hidden retries. Neither a selected candidate nor synthetic attempt history grants execution authority. A6 remains ND, A7 fully unresolved, A8 advisory, and P8 NO-GO. No real-world or experimental acceptance is claimed.
