# P14 R25 — Conciliación documental sintética A3 (solo lectura)

**Base fijada**: `d59bbca3962f3a0995d6ffa5b2ba70e42224c0ba` (merge PR #90). Incremento nuevo, no reapertura histórica de R24.

## Alcance

R25 consume la cadena R16–R24: reglas, condiciones iniciales, dependencias, controles simbólicos, contrato integrado, diagnóstico trivalente, candidatos y escenario hipotético. Reconcilia un lote explícito de **declaraciones documentales sintéticas** por caso/control con un soporte binario también sintético. Comprueba correspondencia exacta de servicio, elemento, categoría y valor, y la huella SHA-256 del soporte. Produce un reporte canónico y determinista que diferencia `SIN_DECLARACION`, `COINCIDE_SUPUESTO` y `DIFIERE_SUPUESTO` contra R24.

- Una huella SHA-256 verifica bytes, **no** la veracidad técnica de una declaración ni su procedencia externa.
- Un supuesto R24 no constituye evidencia acreditada. Una declaración R25 con soporte binario tampoco.
- La única procedencia permitida para este incremento es `SYNTHETIC_DECLARATION_ONLY`; no se aceptan etiquetas autoproclamadas `VERIFIED_PRODUCTION`.
- Cada declaración `VERDADERO` o `FALSO` requiere soporte canónico referenciado, tamaño acotado, huella y correspondencia estricta. `ND` exige soporte ausente.
- El lote es exhaustivo respecto de los casos y controles declarados en la fuente A2; no acepta identidades ajenas, duplicadas o extras. Las permutaciones se normalizan canónicamente.
- Se limita la cantidad total de bytes y se rechazan claves JSON repetidas, documentos no canónicos, payloads excesivos, campos no declarados y alteraciones de huellas.
- `accredited=False`, `executable=False`, `operational_dispatch=False`, `generation_published=None`, `controls_applied=False`, `executable_agenda=None` y `p8_operational=NO-GO` son invariantes, incluso cuando una declaración coincida con un supuesto.

## Demostración fijada

54 unidades sintéticas: 18 SSH, 18 FTP, 18 SMB. Cuatro posiciones documentales por unidad (dos casos y dos controles) dan **216 posiciones**. Se aportan **36 soportes sintéticos**: 18 coinciden con el supuesto R24 y 18 difieren; 180 posiciones permanecen sin declaración. No se infiere evidencia de pruebas de penetración reales ni se altera un resultado operativo.

## Contrato y límites de aceptación

`src/ardrec/scheduling/observation_preview.py` expone `reconcile_documentary_observations(...)` y `.verify(...)` reevalúa las fuentes de entrada, bytes del lote, hash y consistencia del reporte. El resultado representa una reconciliación documental sintética. La entrega no cierra A1, A2, A3, AL-06, AL-07 ni P8; tampoco habilita A4–A10 operacionales.

Para evolucionar hacia hechos acreditados se requerirá una cadena de custodia externa, vinculación a intentos/journals/generaciones, política de validez y controles antifalsificación con oráculos independientes. Ninguno de esos requisitos se satisface mediante un SHA suministrado por el mismo productor del documento.

## Trazabilidad y pruebas

- R25: `lab/tests/test_p14_r25_a3_documentary_observations.py` (49 pruebas específicas).
- Demostración: `scripts/demo_p14_r25_a3_documentary_observations.py`.
- CI Python: prueba específica y demostración; CI Rust existente queda intacta.
- Regresiones completas Python/Rust, trazabilidad y P8 se ejecutan en Prometheus antes de firmar un commit.
