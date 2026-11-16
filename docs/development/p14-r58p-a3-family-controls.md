# P14 / R58-P — A2/A3 typed case controls for 25 families (synthetic only)

Base `ed0bd75f9388c2f0c61166d1a895cb62e64d8438` (signed R58-O merge). Reuses the original R17–R22 implementation to assemble a **new** A2 typed case/dependency/control snapshot covering the 29 synthetic SSH/FTP/SMB case-window variants from R58-L. It then runs the genuine R22 A3 trivalent diagnostic over this new synthetic source. Does not overwrite, rebind or publish the previously recorded R26 controls.

## Contract

- Cases: `CASE_` + 48 hex from the R58-K full-identity SHA, unique across all 29 case-windows. Corresponding A2 control `CTRL_` + 48 hex; `guard_rule_id=ALLOW`, precedence inherited from the verified R58-L A4 record; requires=[] for this zero-dependency *diagnostic only* scenario.
- Three services, fixed R26 fixture `DEV_TUTOR_001`: SSH FACT VERDADERO, FTP FACT AUSENTE, SMB FACT FALSO. Source A1 rules must share the SHA-256 of the R26 rule source. R22 computes one independently typed control diagnostic per case.
- A2 phase remains PREPARADO. The R58-L A4 selection assumes PENDIENTE and is therefore **not** an authorized continuation of the real R26 phase. A3 guarda VERDADERO remains insufficient: `AUTORIDAD_OPERACIONAL_NO_ACREDITADA` must be present in every control.
- No A5 starts, durable journal writes, VM operations, evidence admission, generation publication or P8. A6=ND, Rf=None. The typed A3 mapping closes the reference-coverage gap **only**. Case-level authorization, rule applicability to physical evidence, transition PREPARADO→PENDIENTE and independently attested provenance remain pending.
- Exact replay verifier rebuilds all R17–R22 source objects and the complete result; tampering, unbound identity, replaced sources or forged authority must fail closed.

## Tests and CLI

`PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58p_*.py' -v`

`PYTHONPATH=src python3 -B scripts/ardrec_p14_r58p_a3_family_demo.py --synthetic-offline`

No `--synthetic-offline`, or any working directory other than repository root, is refused. CI should run both steps after R58-O and before the laboratory design check.
