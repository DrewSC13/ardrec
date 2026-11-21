# R117-F5D-G — Atomic source-release activation

## Purpose

F5B must not expose a completed release to F4 until the
transaction journal, approval and receipt are durable.

## Implementation

- The F5B installer retains its unconditional APPLY blocker.
- A candidate is staged and audited before publication.
- The F5B transaction writes and synchronizes complete.json.
- F5B generates one canonical activation record.
- Activation is published by rename within /var/lib/ardrec.
- F4 requires and verifies the activation record before
  recognizing the release.
- Candidate, approval, manifest, receipt and completion hashes
  are linked to the same HEAD and transaction.
- Ed25519 approval verification remains mandatory.

## Limitations

This is source-only implementation and regression testing.
It does not certify operational durability across power failures.
Actual provisioning, independently rooted trust, recovery testing
and a privileged deployment remain outstanding.

The previously staged F5D-E archive is historical evidence,
not an authorized current release.

No guest start, network access, firewall changes or boot
permission are added. P7=DRAFT, A6=ND, P8=NO-GO.
