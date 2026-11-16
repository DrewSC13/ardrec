# R58-V — Verifiable, read-only A5/A6 model handoff

**Scope:** source-only, offline, no privilege, no service/VM activity.

R58-V reconstructs the R58-U overlay from its R58-T source and the immutable
R58-S *deny-only* gate, with R58-R provenance. It emits one canonical report
for up to 54 case identities and *optionally* writes a private, immutable report
receipt in a fifth, independent caller-provided development directory.

On the fixed P7/R26 example (29 case-windows, 25 families), the demonstration
has 2 sandbox T1 and 3 sandbox T8/T9/T10 events. The model ends with 27
`PREPARADO`, 1 `PENDIENTE`, and 1 `DETENIDO` case. The one **model-only**
`PENDIENTE` case is marked for *review*; it is not an accepted, dispatched,
reserved, started, or executed A5 request. No A6 evidence is accredited:
classification remains `ND`, with no confirmed final risk or A9 publication.

The source SQLite is opened using `mode=ro`, not through the operational
pipeline; R58-T/R58-U inspectors are repeated to detect snapshot drift. The
immutable report is bound to the deny gate, T1 event-head, overlay event-head,
source catalog, thesis, session and each A7 case identity. Repeated identical
writes are idempotent; changed snapshots or receipts are rejected.

**Security limitations:** SHA-256 validates report consistency, not author
identity or resistance to a hostile actor able to rewrite all source stores and
hashes. SQLite consistency across two separate databases is not an atomic
multi-database snapshot. A5 is never invoked. R34 DENY, F11 not activated,
`P8=NO-GO`. Do not interpret model state as authorization or test evidence.

Testing: `PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58v_*.py' -v`

Demonstration: `PYTHONPATH=src python3 -B scripts/ardrec_p14_r58v_a5_a6_handoff_demo.py --synthetic-offline`
