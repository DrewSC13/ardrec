# ARDREC — R111-F1 / Reconciliación de un inventario físico real

## Alcance

R111 registró en Prometheus 29 lecturas reales de libvirt, systemd y NFT bajo
`/home/cicada/ardrec-lab/r111-real-host-readiness-v1/`. Ese recibo es **histórico
inmutable**, no una certificación de aislamiento vigente ni de capacidad de
arranque. El script original se conserva sin modificaciones como
`scripts/ardrec_p14_r111_legacy_host_snapshot.py` para poder reproducir su
interpretación original.

## Defecto observado y corrección

`virsh --readonly ... domstate` devolvió `APAGADO` en el anfitrión en español.
La interpretación inicial solo reconocía `SHUT OFF` y `SHUTOFF`, por lo que
agregó erróneamente cuatro avisos `NOT_CONFIRMED_SHUTOFF`. R111-F1 reabre el
recibo original, lo verifica con el mismo analizador histórico, y emite un
**nuevo recibo privado y vinculado al SHA-256 original** que reconoce solo esas
tres traducciones literales. Estados ambiguos o distintos siguen siendo
`UNKNOWN` y no se convierten en `SHUTOFF`.

El hallazgo de configuración persiste: el runner tenía únicamente la NIC SSH;
para la topología R33 faltan las NIC FTP y SMB (no una sola). Que el XML de red
contenga `br33d30`, `br33d31` o `br33d32` **no demuestra que sus puentes estén
activos**. R111-F1 interpreta el `net-info` capturado, si es inequívoco, y no
emite lecturas nuevas del anfitrión.

## Evidencia y límites

- Referencias: recibo R111 original, SHA-256 y 29 sondas de solo lectura.
- El recibo original **no se modifica ni se reescribe**.
- El nuevo recibo se guarda con permisos `0700`/`0600`, y conserva la conexión
  al resumen y los bytes de origen. No se publica en GitHub.
- 11 pruebas de análisis y seguridad, incluidos rechazo de estados inesperados,
  RC fallido, resumen manipulado y rehash de informe alterado.
- Este incremento ejecuta **cero** comandos de VM, `sudo`, política de red o
  servicios. El código legado únicamente se usa en modo `verify`.
- Un SHA-256 no equivale a una firma externa del anfitrión.
- `F11` continúa deny-only, `A6=ND` y `P8=NO-GO`.

## Ejecución de solo lectura del recibo histórico

Desde `/home/cicada/Development/GitHub/ardrec`:

```sh
PYTHONPATH=src:scripts .venv/bin/python -B -m unittest discover -s lab/tests -p 'test_p14_r111_*.py' -v
PYTHONPATH=src:scripts .venv/bin/python -B scripts/ardrec_p14_r111_real_reconcile.py --reconcile --r111-original /home/cicada/ardrec-lab/r111-real-host-readiness-v1/run-28c7aj6w
```

Guardar y verificar el nuevo directorio `R111_F1_SESSION` obtenido en pantalla.
El próximo paso R112 se enfocará en el plan físico de interfaces, F11 y red
cerrada, seguido de un cambio autorizado y reversible; no más lotes sintéticos.
