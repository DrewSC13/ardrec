# ARDREC P14 · R58-A/FTP-NIC: conciliación de solo lectura / Read-only reconciliation

**Código base / Base HEAD:** `be7bc497bbbb45b585ac308066d6ff08b07775bd` (PR #131 integrated).

## Objetivo / Goal

Diagnosticar en la **máquina anfitriona** si la definición *inactiva* de `ardrec-r33-dev-runner` contiene la interfaz FTP `a33d31r` que exige la topología R33. La salida se detiene antes de cambios físicos. Este incremento no intenta resolver ni atribuir el `enable` de F11.

Inspect the runner's *inactive* libvirt XML for the missing FTP NIC without attaching devices or starting guests.

## Contrato exacto / Exact contract

- Runner SSH: `a33d30r`, `52:54:00:ad:30:01`, red `ardrec-r33-dev-net-ssh`.
- Runner FTP: `a33d31r`, `52:54:00:ad:31:01`, red `ardrec-r33-dev-net-ftp`.
- Target FTP: `a33d31t`, `52:54:00:ad:31:02`, red `ardrec-r33-dev-net-ftp`.
- Todas las NIC observadas deben referenciar `ardrec-r33-block-until-containment`; ninguna adicional fuera de R33.
- Red FTP inactiva, puente `br33d31`, sin `forward`, IP propia ni DNS habilitado en su XML.
- Cuatro VM apagadas; tabla bridge `ardrec_r34_guard` leída dos veces y validada estructuralmente, cuatro DROP sobre seis TAPs; nwfilter DENY verificado.
- **No hay garantía de IPv6 basada únicamente en la ausencia del atributo XML.** El reporte lo declara expresamente.

Fuentes: `src/ardrec/coordination/r33_offline_topology.py`, `src/ardrec/coordination/r34_containment.py`, `src/ardrec/coordination/r553_transition_guard.py`, `docs/development/p14-r560-triple-service-program-v1.md`.

## Ejecución / Run

Desde `/home/cicada/Development/GitHub/ardrec`, con Python 3 y binarios `git`, `virsh`, `sudo -n` y `nft` disponibles en las rutas del host registradas:

```bash
python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58a_ftp_runner_readiness.py' -v 2>&1 | more
python3 -B scripts/ardrec_p14_r58a_ftp_nic_preflight.py --host-readonly 2>&1 | more
```

Códigos: 21 = falta FTP-NIC en runner, 22 = presente pero NO autoriza arranque, 23 = drift/lectura insuficiente (fail-closed). En Zsh, obtener el código inmediatamente después de cada tubería con `print -r -- "RC=${pipestatus[1]}"`.

**Controles de exclusión:** sin `virsh define/start/attach-*`, sin systemctl mutate, sin `nft -f`, sin tráfico, sin escrituras en host; sin cambios en `default`, Docker, SSH personal o piloto/experimento. Nunca convertir ausencia de actividad en evidencia de bloqueo del tráfico. No publicar A6/A9 ni `Rf` confirmado.

## Límites / Limitations

La coherencia estructural de R34 (nft + definición nwfilter) **no** prueba que los bindings futuros estén aplicados ni que la unidad de primer arranque F11 haya sido ejecutada. También es necesario verificar consistencia de almacenamiento, identidad de dominio, watchdog independiente, recuperación con prueba adversarial y autorización específica antes de modificar XML/activar la red o arrancar VM. Esta entrega deja `P8=NO-GO` y 54 observaciones experimentales sin ejecutar.

## Trazabilidad / Traceability

| Requisito | Fuente del contrato | Código | Prueba | Estado |
| --- | --- | --- | --- | --- |
| R33 NIC runner FTP | R33 `RESOURCE.runner.nics` | `audit_domain_nics` | `test_expected_ssh_only_runner_blocks_ftp` | SOLO_LECTURA |
| R34 filtrado por seis TAP | R34 `nft_bytes` | `audit_nft` | `test_nft_missing_drop_fails` | SOLO_ESTRUCTURA |
| R33 filtro DN | R34 `verify_filter` | `audit_filter` | `test_deny_filter_allow_fails` | SOLO_DEFINICION |
| Red FTP aislada | R33 `_network_xml` | `audit_network` | `test_network_forward_fails` | SOLO_XML |
| No autoridad física | R56 programa DEV | `decide` | `test_ftp_present_is_not_authorization` | NO-GO |

## Post-integration provenance / Procedencia tras integrar

The immutable base `be7bc497bbbb45b585ac308066d6ff08b07775bd` must be an
ancestor of current HEAD (`git merge-base --is-ancestor`). The read-only
result reports `source_git_head` (base) and `observed_git_head` (current).
This avoids the former exact-HEAD false failure on signed commits while
rejecting rewritten, non-descendant history. No mutation or authorization.
