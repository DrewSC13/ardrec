# ARDREC P14-R42.1 — Intento negativo ICMP único desde SSH

## Contrato de seguridad y procedencia

Base Git exacta: `0770059dfadb829b9b8e119db7a2defa9a058931` (PR #113). Historial privado obligatorio: recibo R42.0 (`r42_counter_baseline.json`, digest interno `8ccd4f7374ce8f4b030b191185d527b8886f55edddd40229e7798c14be4930b1`), más R41.1, R41, R40, R39, R36.5. Se usan verificadores de digest, inventario y semántica ya existentes. Los recibos privados nunca se incorporan a Git.

El dominio `ardrec-r33-dev-ssh` y la red `ardrec-r33-dev-net-ssh` deben permanecer activos, sin FTP/SMB/runner encendidos, sin TAP extra y con nftables/nwfilter deny-first íntegros. No se modifica ninguna política, configuración, máquina, imagen ni puente. El modelo no acredita identidad externa del huésped ni autenticidad de la salida de QEMU Guest Agent.

## Dos fases explícitamente separadas

1. **`--preflight-only`**: autentica historial privado, obtiene dos lecturas de estado `SSH_RUNNING` y de contadores de las cuatro reglas `drop` de `bridge/ardrec_r34_guard`. Comprueba `handle` estable, contadores monótonos y **delta previo cero**; no abre canal QGA, ejecuta nada dentro de la VM ni transmite un solo paquete.
2. **`--execute-one-icmp --i-authorize-r421-guest-agent`**: el operador autoriza una acción acotada y el código vuelve a ejecutar el preflight. Crea un recibo privado de intención antes del primer comando QGA. El único proceso que puede solicitarse al huésped mediante QGA es `/usr/bin/ping -n -I 10.203.30.2 -c 1 -W 1 10.203.30.1`, con locale `C`. Esto limita a **un intento de ICMP Echo**, no a un paquete Ethernet total: puede generarse ARP para resolver la ruta. QGA puede devolver error, carecer de `ping` o no tener la dirección configurada; el resultado debe ser inconcluso, no repetible automáticamente.

Se comprueba antes que QGA comunica y declara la NIC `52:54:00:ad:30:02` con IPv4 `10.203.30.2/28`. Después de la solicitud al huésped se hacen hasta ocho consultas de estado con espera acotada, y se comparan nuevamente estado del host y contadores de nftables. No se usan `shell`, SSH, sudo dentro de la VM, escaneos, fuerza bruta ni contactos con la red física o Internet. El destino `10.203.30.1` pertenece al **runner apagado**; por tanto, cero respuestas ICMP **no** prueba eficacia de aislamiento.

## Corrección R42.1-F1: prefijo real del huésped SSH

El primer intento expresamente autorizado generó un recibo de fallo
`r421-guest-icmp-20261114T235115Z-5663`: el verificador impidió `guest-exec`
porque exigía `/24`, mientras QEMU Guest Agent informó para `ens3` la MAC
`52:54:00:ad:30:02` y `10.203.30.2/28`. La validación posterior de solo lectura
confirmó el valor `/28`; los dos recibos del intento pasaron SHA256SUMS.

R33 indica conservar la configuración estática del huésped sin imponer `/24`.
Se fija `/28` como condición **exacta** de R42.1 y se comprueba que el destino
reservado `10.203.30.1` permanezca en esa subred. Se rechazan `/24`, otros
prefijos, direcciones IPv4 adicionales y NIC/MAC no coincidentes. Este cambio
no reconfigura la VM ni autoriza repetir acciones. Toda operación activa requiere
**nuevo recibo exclusivo** y autorización explícita; no reutilizar el intento
fallido ni borrar evidencia. La aceptación de aislamiento sigue pendiente.

## Interpretación científica y límites

Un `BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO` requiere salida QGA con exactamente un intento transmitido, cero respuestas y código de salida esperado; representa **evidencia local del intento**, no prueba del bloqueo en tránsito. Incrementos de nftables sin observación independiente permanecen `counter_delta_unattributed`. Los filtros `nwfilter` pueden interceptar antes de que se incrementen los contadores nftables, de modo que cero delta no invalida ni confirma por sí solo el bloqueo.

Si hay respuesta (`UNEXPECTED_REPLY_REVIEW_NO_GO`) o el huésped no informa un paquete (`INCONCLUSIVE_GUEST_PROBE_NO_GO`), no se acepta aislamiento. Si ocurre una excepción tras crear la intención, se preserva `r421_failure.json` y `SHA256SUMS`, estado `REVIEW_REQUIRED_GUEST_ACTION_POSSIBLE`: nunca reintentar automáticamente. El inicio y apagado de las VM, modificaciones nftables/libvirt, inspección del QCOW2 activo y activación FTP/SMB/runner están fuera de alcance.

El resultado **siempre** mantiene `p8_operational=NO-GO`, `final_risk=null`, `technical_truth_accredited=false`, `operational_dispatch=false`, `isolation_proven=false`. Un test integral posterior debe incorporar un testigo independiente de entrega/bloqueo, con controles positivo y negativo y estímulos atribuibles, antes de cualquier pentesting operativo.

## Uso terminal (preflight sin contacto con el huésped)

```bash
cd /home/cicada/Development/GitHub/ardrec
BASE=/home/cicada/Development/GitHub/ardrec-patches/r35-private-Z9vpswND
sudo -v
python3 -B scripts/ardrec_p14_r421_bounded_negative_probe.py \
  --r420-baseline "$BASE/r42-counter-baseline-20261114T230203Z-5663" \
  --r411-observation "$BASE/r411-external-ssh-20261114T224307Z-5663" \
  --r41-preflight "$BASE/r41-ssh-preflight-20261114T223009Z-5663" \
  --r40-preflight "$BASE/r40-ssh-preflight-20261114T221736Z-5663" \
  --r39-reconciliation "$BASE/r39-ssh-reconciliation-20261114T215708Z-5663" \
  --r365-preflight "$BASE/recibos-preflight-r365-20261114T200434Z-94940" \
  --r365-first-boot "$BASE/recibos-first-boot-r365-20261114T200824Z-98270" \
  --receipt-dir "$BASE/r421-unused-preflight" \
  --preflight-only
```

El preflight no crea `--receipt-dir`. La modalidad activa se autoriza separadamente después de analizar el preflight físico y confirmar que QGA y la topología están bajo el control del operador. No ejecutar la ruta activa como diagnóstico automático.

## Pruebas y desarrollo

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r421*.py' -q
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14*.py' -q
python3 -B scripts/verificar_trazabilidad_actual.py
```

Commit SSH firmado, PR hacia `main` protegido, CI 3/3, merge convencional. Ningún recibo local se publica en GitHub.
