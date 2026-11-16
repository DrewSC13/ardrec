# P14 / R58-S — Deny-only documentary transition decision

## Scope

R58-R persists a SHA-256 linked proposal, not a state. R58-S consumes **only**
that verified private proposal and writes a separate, immutable and
session-scoped **deny-only assessment**. No approval-bearing input is accepted.

For the fixed R26 scenario and pinned P7 catalogue, 29 cases are still
`PREPARADO`: eight SSH cases have a logical A3/A4 counterfactual, while the ten
FTP and eleven SMB cases are not logically eligible. All eight requests are
denied for lack of independently attested authorization, signed review and a
committed transition protocol. Zero cases advance to `PENDIENTE`.

## Contracts

- Verify the exact persisted R58-R proposal, trace, identity, session and
  catalogue/thesis pins before deriving a decision.
- Preserve one typed immutable outcome for every case, without dropping variants.
- Record `DENIED` on every case. Distinguish no logical eligibility from
  missing independent approval and durable state commit.
- Create/replay exactly one private gate receipt per session. `O_EXCL`, private
  mode, `fsync`, no-follow reads, canonical JSON and SHA-256 are mandatory.
- An altered receipt, changed trace or replay conflict fails closed. The gate
  never writes to the proposal directory or to operational state storage.
- No A5 attempt, evidence admission, recalibrated confirmed Rf, A9 generation,
  VM action, P8 dispatch or host mutation is permitted.

## Development boundary

The `DENIED` status is a programmatic documentary disposition, **not** a human
approval, authorization verdict from P8, nor an experimental observation. The
missing true authority chain must be designed, separately reviewed and tested
before any state transition can be applied. R34 DENY, F11 not activated,
A6 `ND`, P8 `NO-GO`.
