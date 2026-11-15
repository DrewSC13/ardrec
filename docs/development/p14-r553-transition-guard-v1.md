# ARDREC P14-R55.3 — Guardia del cambio ARP/ICMP (código comprobable, NO-GO)

## Estado y antecedente

**Base del código:** merge `e1c2083a30343b22d602e3368a631377133b6478`.

**Recibo R55.2-F1:** `r552-f1-plan-20261115T152309Z-39487`, digest `plan.json` `b32855a66b5a7df8960e29c805a17f11b2e3b9902cd53ba8a44d6193b5fe33eb`.

R54.3 y R55.1 acreditan SSH+runner **RUNNING** sobre la única red `ardrec-r33-dev-net-ssh`; FTP/SMB inactivos. R55.2-F1 constata 2 bindings R33, filtros candidatos R45 definidos pero no asociados, `<parameter name="MAC" .../>` y `<backend name="iptables"/>`, y sintaxis `nft -c` PASS. **Aislamiento de paquetes todavía no demostrado.**

## Implementación de esta entrega

- `r553_transition_guard.py`: autentica 9 archivos exactos, SHA-256 y plan R55.2-F1 fijado; valida XML originales y candidatos con identidades MAC/TAP/IP/propietario estables, parámetros MAC exactos y backend `iptables`; recompone exactamente ambas políticas nftables R55.2-F1, acepta únicamente cuatro reglas de ARP/ICMP y cuatro reglas DROP y exige restauración sin ACCEPT. Rechaza `flush ruleset`, TCP/UDP, FTP/SMB, symlinks, permisos inseguros, derivación SHA, modificaciones de identidad y aprobaciones operacionales falsas.
- `ardrec_p14_r553_transition.py`: `--verify-offline` y `--live-readonly`. La segunda ruta consulta los dominios y bindings en vivo, dos filtros candidatos, estados de las redes, bridge sin IPv4 y R34 deny; ejecuta `nft -c`, que solo comprueba sintaxis; genera recibo privado nuevo. Ningún modo emite escrituras de host.
- `test_p14_r553_transition_guard.py`: pruebas deterministas y adversariales de políticas, XML, recibos, fallo de secuencia, denegación P8 y ausencia de watchdog.
- Workflow `ci.yml`: nueva ejecución de pruebas R55.3 en PR/main, además de los controles existentes Python/Rust.

## Por qué **no** se habilita todavía el tráfico

`virsh nwfilter-binding-delete` retira inmediatamente el filtro del TAP; el posterior `nwfilter-binding-create` lo restaura o sustituye. Durante el intervalo entre ambas operaciones, la protección sigue dependiendo de R34. Por ello no es seguro aplicar una apertura ARP/ICMP antes de haber modificado y revalidado ambas asociaciones mientras R34 permanece en DROP.

La carga `nft -f` puede aplicar transacciones de una sola tabla de forma atómica, pero **la atomicidad no cierra la ventana en caso de SIGKILL, caída del proceso o del anfitrión**. R55.3 modela las fases `BASE_DENY → BINDINGS_CANDIDATE_R34_DENY → BOUNDED_ALLOW → R34_RESTORED_DENY → ALL_ORIGINAL_DENY` y bloquea el ingreso a la ventana si no hay guardia independiente verificable. Un simulador no acredita que el mecanismo real exista.

**Aún falta implementar y demostrar** un cierre fuera del proceso principal, un bloqueo exclusivo de mantenimiento, control de autorizaciones independientes, testigos origen/destino del tráfico, procedimientos ante fallo parcial y restauración físicamente ensayada. El simulador tiene `physical_write=false`, `restoration_tested=false`, `P8=NO-GO` sin excepciones. No se proporcionan banderas `--apply`, `--execute`, `--rollback` ni contacto con QGA o SSH.

## Aplicación y pruebas

Revisar que el árbol fuente esté limpio y en la base exacta. Crear rama `feat/p14-r553-transition-guard-main`, aplicar el ZIP, comprobar el manifiesto y la inserción CI, ejecutar:

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r553*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r553_transition.py --verify-offline
sudo -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r553_transition.py \
  --live-readonly \
  --receipt-dir /home/cicada/ardrec-lab/r55-transition/r553-readonly-$(date -u +%Y%m%dT%H%M%SZ)-$$
```

Preflight físico no autoriza cambios de tráfico. Todas las fuentes de pruebas y documentación permanecen en Git; los recibos físicos se conservan en `/home/cicada/ardrec-lab/` (0700/0600). El ZIP se conserva exclusivamente en `/home/cicada/Development/GitHub/ardrec-patches/`.

## Próxima acción sustantiva

R55.4 debe implantar la recuperación automática **independiente** y ensayarla con fallos adversariales del proceso principal ANTES de un interruptor real de políticas. Tras PR, commit SSH firmado y CI protegida, otra autorización humana específica podrá habilitar solamente un intervalo ARP/ICMP con observadores positivos/negativos. TCP/UDP, pruebas de SSH y pentesting siguen excluidos.
