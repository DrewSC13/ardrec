# ARDREC P14–R41.1 — Reconciliación de ejecución SSH iniciada fuera de R41

Base exacta `80430ca74ba37018b0f1ecf95fd78a737c33d928`, rama de trabajo no integrada `feat/p14-r41-ssh-explicit-resume-main`. R41 y R41.1 se integran en el **mismo PR** y en secuencia: R41 permanece funcional para futuras reanudaciones autorizadas, R41.1 reconcilia la desviación de este primer recorrido físico.

## Hecho observado y límite de atribución

El 14 de noviembre el operador ejecutó directamente `virsh start ardrec-r33-dev-ssh` antes de invocar el ejecutor R41. El comando externo devolvió «Dominio iniciado»; el ejecutor R41 después emitió `R35Error:domain_not_shut_off`, sin llegar a registrar una intención o enviar un segundo arranque. Un readback separado posterior validó `SSH_RUNNING` con solo `ardrec-r33-dev-net-ssh`, `ardrec-r33-dev-ssh`, `br33d30` y `a33d30t` entre los recursos ARDREC activos; el nwfilter y la política nftables están presentes.

El resultado **no** acredita por sí solo la identidad del huésped, quién causó el arranque mediante evidencia independiente, ni el bloqueo real de paquetes. La declaración del operador se mantiene como declaración, no como prueba causal independiente. La presencia de políticas no equivale a probar su eficacia. El recibo R41 histórico no vuelve a conceder permiso para arrancar nada.

## Qué hace R41.1

- Autentica `r41_preflight.json`, el recibo R40 fijado por su digest, R39 y los recibos R36.5, reusando verificadores semánticos y SHA256SUMS locales.
- Obtiene **dos** capturas sucesivas de `r365.current(...,phase='SSH_RUNNING')` mediante el Host restringido de solo lectura; exige coincidencia exacta, inventario y MAC autorizados, y políticas de contención presentes.
- No usa `virsh start`, `destroy`, `shutdown`, `net-start`, `qemu-agent-command`, `ping`, conexiones SSH ni cambios de red. No inspecciona con qemu-img ni calcula SHA del overlay SSH mientras QEMU lo mantiene abierto y potencialmente mutable.
- Escribe un nuevo recibo privado `r411_external_start.json` + `SHA256SUMS` en directorio nuevo, `0700`, archivos `0600`; nunca modifica los recibos antiguos.
- Mantiene `p8_operational=NO-GO`, `guest_isolation_tested=false`, `real_service_testing=NOT_EXECUTED`, `final_risk=null`, `experimental_validation=NOT_RUN` y `operational_dispatch=false`.

## Operación limitada en Prometheus

```bash
cd /home/cicada/Development/GitHub/ardrec
sudo -v
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
python3 -B scripts/ardrec_p14_r411_external_ssh_observation.py \
  --r365-preflight "$BASE/recibos-preflight-r365-20261114T200434Z-94940" \
  --r365-first-boot "$BASE/recibos-first-boot-r365-20261114T200824Z-98270" \
  --r39-reconciliation "$BASE/r39-ssh-reconciliation-20261114T215708Z-5663" \
  --r40-preflight "$BASE/r40-ssh-preflight-20261114T221736Z-5663" \
  --r41-preflight "$BASE/r41-ssh-preflight-20261114T223009Z-5663" \
  --acknowledge-start-outside-r41 \
  --receipt-dir "$BASE/r411-external-ssh-$(date -u +%Y%m%dT%H%M%SZ)-$$"
```

Resultado válido: `EXTERNAL_SSH_RUNNING_OBSERVED_NO_GO`. El estado no pretende demostrar que R41 realizó la reanudación ni que el laboratorio superó el aislamiento. El siguiente incremento R42 diseñará validación positiva y negativa del tráfico aislado bajo autorización separada, sin suposiciones sobre su éxito.
