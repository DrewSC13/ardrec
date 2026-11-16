# ARDREC P14 / R58-E — Vinculación conservadora por unidad A6 → A7 → A8

**Base exacta:** PR #136, commit de integración `9a0be067330b98aa3b22f2c67273b5151435d469`.

## Funcionalidad nueva

`ardrec.coordination.r58e_evidence_risk_bridge` integra las implementaciones existentes:

- **A6 / R37:** `validate_admission` verifica un informe admitido **solo para revisión documental**, sin acreditación física. Conserva las afirmaciones originales como `observed_claim_unverified`; jamás las transforma en VERDADERO/FALSO ni en contribuciones numéricas.
- **A7 / R58-D:** `build_intervals` calcula los extremos con fracciones exactas por `(service_id, case_id, assessment_index)`. Toda unidad sin aportes técnicamente acreditados usa un `UNRESOLVED` `[0,1]`, incluso si tiene un recibo documental. El resultado es una envolvente matemática, NO un intervalo estadístico ni un `Rf` confirmado.
- **A8 / R28:** `preview_stop` registra `PAUSAR_HASTA_EVIDENCIA_AUTORIZADA`, pero jamás invoca `transition_service` ni cambia la fase real. `confirmed_phase`, `applied_transition` y `confirmed_rf` permanecen nulos.
- **A9:** No se publican generaciones ni se escribe un diario. La integración de generación técnica exige autorización, procedencia física independiente, estados y guardas reales de A1–A10.

Las entradas no pueden traer evidencia arbitraria a A7: cada `unit.evidence` DEBE ser `[]`. Para los 54 casos máximos del núcleo A7, la ausencia de A6 se conserva como incertidumbre, nunca como contribución cero acreditada. El importador documental R37 actual solo admite una sesión/caso SSH de desarrollo, no soporta aún admitir FTP o SMB desde registros físicos.

## Guardas de correlación

- La clave completa de A7 incluye `assessment_index`, pero el recibo A6/R37 no lo contiene. Por eso se **rechaza** asignar un mismo recibo a varias ventanas de evaluación del mismo par servicio/caso.
- Se rechazan recibos con identificadores duplicados, dos admisiones para la misma unidad, contradicciones de afirmación, unidades inexistentes, campos inesperados, digests alterados y acreditaciones fabricadas aunque se recalculen los SHA-256.
- Las entradas se ordenan para independencia del orden. El informe se reconstruye íntegramente durante su verificación para detectar modificaciones posteriores.

## Aceptación de código, no de riesgo físico

```
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58e_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58e_unit_bridge.py --synthetic-offline
```

Las pruebas unitarias incluyen entradas adversariales y ejecución de CLI sobre el fixture original R37. Los fixtures son sintéticos. Se ejecutan en CI sin privilegios. Nunca se ejecutan hooks, `nft -f`, `virsh start`, `systemctl`, ni pruebas técnicas a las VM.

**Invariantes:** `technical_truth_accredited=false`, `confirmed_final_risk=null`, `published_generation=null`, `applied_state_transition=null`, `operational_dispatch=false`, `p8_operational=NO-GO`.

## Próxima funcionalidad

Extender A6 con un **contrato genuino de acreditación independiente**, versiones y ventana temporal para SSH, FTP y SMB, seguido de procesamiento de estados real bajo autorización separada. No incorporar ningún valor de R58-E al estado confirmado todavía. La instalación física F11 sigue pendiente y no está autorizada por este incremento.
