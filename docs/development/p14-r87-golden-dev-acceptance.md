# ARDREC R87 — Golden oracles and functional DEV acceptance boundary

**Scope:** strictly software/synthetic, read-only replay of existing R81–R86 receipts. No new A5 process, VM, socket, operational transition, generation, or P8 authority.

## What it checks

- 1 previously recorded R81 DEV session, 25 typed attempt identities and all 250 A1–A10 derived events from R86.
- Independent, fixed stage-status oracles including A1 GEN1, A2 population separation, A3/A4 deny, A5 **three unverified declarations** and **22 nonstarts**, A6 **25 ND not admitted**, A7 **25 exact hypothetical rational tuples** 1/4, 5/12, 7/12, A8 denial, A9 unchanged GEN1, A10 original R38 read-only.
- The **29 separate R82 model variants** remain distinct from the 25 typed R81 intents and from the 54 synthetic R75 units. No authoritative cross-population join.
- Recomputed/private R86 source proof; original R84 criteria (13 PASS DEV-only and 6 pending independently validated) and R85 fault campaign (156 rejected/0 undetected).
- Deterministic canonical JSON result with 18 DEV-only golden checks and 25 per-case findings, SHA-256, private 0700 directory, 0600 file, exact replay and adversarial rejection tests.

**Explicit limitations:** 18/18 DEV golden checks passing is **not** system acceptance, evidence accreditation, a physical penetration test, or empirical validation. `A6=ND`, `Rf confirmed=NULL`, operational A8=0, system acceptance `PENDING`, experiment `NOT_RUN`, `P8=NO-GO`. R87 does not prove an integrated operational physical engine A1–A10: its inputs are replayable derived DEV software artifacts.

## Contract

`scripts/ardrec_p14_r87_dev_acceptance.py` accepts `--create` or `--verify` plus `--work-dir` and the exact six original private receipt directories `--r81-receipt` … `--r86-receipt`. It re-verifies R86 against the R81–R85 origin chain, uses fixed reference oracles, stores one immutable canonical private JSON document and replay-verifies it. Re-running `--create` over an existing output is denied.

The acceptance verdict is `PASS_SOFTWARE_DEV_GOLDEN_SCOPE_ONLY`, **never** `PASS_SYSTEM_FUNCTIONAL` or `PASS_EXPERIMENTAL`.

## Prometheus and CI

Use the authenticated source-only R87 patch and its exact SHA-pinned Zsh runner. No changes to source receipts; verify unchanged source SHA-256 before commit. CI runs R87 tests plus inherited Python, Rust and F11 safeguards. GitHub PR merge only after three required checks succeed; postmerge CI checked independently.
