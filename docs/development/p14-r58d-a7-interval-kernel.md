# ARDREC P14 / R58-D: A7 exact interval engine (offline)

**Baseline:** merge PR #135 `5f69b6d61eb62e8b1451730ea8df1d38ad68c434`.

## Funcionalidad implementada

El módulo `ardrec.analytics.r58d_interval_kernel` procesa de una a 54 unidades de caso por evaluación, con hasta 25 entradas de evidencia por unidad, y reutiliza el oráculo matemático `preview_bounds` de A7 ya versionado. Ordena entradas para garantizar igualdad ante permutaciones, identifica duplicados de unidad/caso/generación e identificadores de evidencia, valida fracciones canónicas y pesos positivos de suma uno, y recalcula el informe para detectar falsificaciones aun si alguien actualiza su SHA-256.

Las observaciones `SYNTHETIC_FIXED` representan valores puntuales **exclusivamente simulados**. Las `UNRESOLVED` abarcan obligatoriamente todo `[0,1]`; no se admite inventar una cota favorable a partir de evidencia incompleta. El agregado de evidencia por unidad es el máximo. Se aplican las fórmulas matemáticas A7 ya implementadas a los extremos y se devuelve `rf_lower` y `rf_upper`. El resultado no es una probabilidad ni un intervalo de confianza estadístico: es la envolvente matemática bajo las entradas hipotéticas.

**Límite fundamental:** no implementa acreditación independiente A6, ni aplica estado A8, ni publica una generación A9. Aunque la envolvente sea puntual, ello no la convierte en `Rf` técnico. En toda salida: `technical_truth_accredited=false`, `confirmed_final_risk=null`, `published_generation=null`, `operational_dispatch=false`, `p8_operational=NO-GO`.

No se inician máquinas, no se accede a red ni se altera nftables, libvirt o systemd. Los valores de la demostración CLI son sintéticos. Un máximo de 54 y 25 son límites de recursos para este módulo; no acreditan que se hayan completado las 54 unidades ni las 25 familias experimentales de la tesis.

## Pruebas

```
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58d_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58d_a7_intervals.py --synthetic-offline
```

El siguiente incremento integrará estas cotas con la clasificación A6 correspondiente a cada unidad. El valor `Rf` final seguirá bloqueado hasta existir evidencia técnica acreditada y autorización operacional independiente.
