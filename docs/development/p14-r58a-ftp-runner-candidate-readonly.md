# ARDREC — P14 / R58-A / FTP runner NIC: deterministic candidate, READONLY

## Status / Estado

**Offline candidate generation only. NO physical authorization. P8=NO-GO.**
**Solo genera la candidata en memoria. SIN autorización física. P8=NO-GO.**

Host observations (operator, 2026-11-15): 22/22 preflight tests passed;
`BLOCKED_FTP_RUNNER_NIC_MISSING`, read-only return code 21. The FTP domain
and its isolated network were defined, both inactive. The runner's inactive
XML had a single SSH NIC `a33d30r`. The physical guard F11 had been enabled
but first execution and independently enforced manual VM boot blocking were
NOT attested. The original F11 enable-only receipt reported a BLOCKED state.

**Never infer operational clearance from a software candidate.**

## Exact scope / Alcance exacto

The script `scripts/ardrec_p14_r58a_ftp_runner_candidate.py`:

1. Requires CWD `/home/cicada/Development/GitHub/ardrec`, pinned baseline
   `be7bc497bbbb45b585ac308066d6ff08b07775bd` and exact prior preflight
   source SHA256 `9b778d8414241d2f69dd53c8a90b944441d82b17b365378edc38ca53a3adad6d`. The base must remain an ancestor of
   the observed `HEAD`; it is not required to equal the current HEAD.
2. Executes the **previous already-installed READONLY preflight twice**,
   including its double nft structural readback, filtered libvirt domain
   inventory, isolated FTP network and DENY filter verification.
3. Retrieves the runner inactive XML twice using
   `/usr/bin/virsh --readonly -c qemu:///system dumpxml ardrec-r33-dev-runner --inactive`
   and rejects XML drift between those reads.
4. Requires the runner still have ONLY the original correctly filtered SSH
   NIC. A preexisting FTP or SMB NIC is not silently overwritten.
5. Forms one additional NIC in **process memory only**:
   - network: `ardrec-r33-dev-net-ftp`
   - MAC: `52:54:00:ad:31:01`
   - TAP: `a33d31r`
   - model: `virtio`
   - nwfilter: `ardrec-r33-block-until-containment`
6. Verifies the source XML's original bytes can be recovered exactly by
   removing just that inserted NIC block, and checks original XML device
   nodes stay identical. Prints original and candidate SHA256 values, but
   never prints/writes private XML.
7. It provides NO `--apply`, `--define`, `--start`, `--enable`, `--rollback`,
   or output-write option, and has no `subprocess` direct invocation.

This does **not** attest effective nwfilter bindings, first boot after F11,
independent watchdog or guest protocol service availability. The read-only
current nft structure does not itself prove future boot persistence. The
libvirt-defined FTP network may omit the explicit `ipv6=no` attribute on
readback; this increment does not assert IPv6 status from its absence.

## Return codes / Códigos

- `22`: in-memory candidate computed, still **not authorized for physical apply**
- `23`: fail-closed blocked, source drift, host mismatch, or missing permission

No `0` for authorization, no VM starts, host writes or packets. `P8=NO-GO`.

## Running from the main repository / Ejecución desde repositorio

**Zsh** (terminal stays open):

```bash
cd /home/cicada/Development/GitHub/ardrec
python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58a_ftp_runner_candidate.py' -v 2>&1 | more
print -r -- "TEST_RC=${pipestatus[1]}"
python3 -B scripts/ardrec_p14_r58a_ftp_runner_candidate.py --host-plan-readonly 2>&1 | more
print -r -- "HOST_PLAN_RC=${pipestatus[1]}"
```

No modifications to the systemd unit, host firewall, libvirt definitions,
network, VM state, source branch, or private receipts. The source-only patch
adds 4 previously nonexistent files to the current branch and is suitable for
review prior to PR/merge. Do NOT commit or publish host-derived XML.

## Next physical gate (separate, NOT implemented here)

To modify the inactive runner definition later, require an explicit
maintenance authorization **after** reconciliation of F11 persistence and
independent watchdog/recovery evidence; attest live-vs-inactive bindings and
storage; take a private authenticated before-image; apply one mutation only;
validate source-vs-target identities, post-change R34 full DENY and rollback
under fault injection; restore deny and original bindings; never enable P8.

---

**English:** Prepared XML is a hypothesis for a safe configuration change,
not proof of secure execution, not an implementation of the watchdog, and
not a completed FTPS smoke test.

## Integration F2 / Integración F2

The candidate additionally checks that `observed_git_head` is stable
across both read-only host snapshots. `baseline_commit` remains immutable.
This avoids a false block after Git commits without relaxing the exact
source SHA-256 pin or permitting a history unrelated to the baseline.
