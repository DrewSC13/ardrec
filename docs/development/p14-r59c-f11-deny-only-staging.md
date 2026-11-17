# ARDREC P14 — R59-C / preparación de transacción F11 (sin instalación)

**ES.** Verifica por huella exacta los cuatro archivos candidatos F11 ya versionados en `lab/f11-runtime-v1`, prepara sus rutas y ensaya la instalación, lectura, repetición idempotente y reversión ante fallo en un árbol **privado y temporal** de usuario. No escribe en `/etc` ni `/var/lib/ardrec`, no añade hooks, no habilita timers, no reinicia libvirt y no emite tráfico. El motor no contiene una función `--apply` privilegiada. `P8=NO-GO`.

**EN.** The source-only stage verifies the four pinned F11 candidate files and rehearses atomic creation, readback, replay and fault-injection rollback in a user-private sandbox. No privileged deployment or operational clearance is implemented.

## Origen y hechos del host proporcionados por el operador

- `libvirtd.service`: activo y cargado, `virtqemud.service`: no encontrado.
- Ninguna VM activa en `virsh --readonly list --name`.
- Inventario del directorio de hooks sin entradas (orden `find` con RC=0).
- Cuatro destinos de instalación `NOT_INSTALLED` según R58-C F11; no implica que los directorios padre carezcan de conflictos o restricciones.
- F11-P: bundle R34 validado; nft DENY doble lectura; nwfilter DROP ALL; cuatro VM R33 apagadas; FTP red inactiva; arranque físico independiente, dependencia fuerte y watchdog todavía no acreditados.

## Objetivos posteriores que aún NO están cubiertos

1. Comprobar versión **efectiva del daemon**, soporte de hooks `qemu.d`, eventos reales y rutas de instalación.
2. Hacer una revisión host de conflictos completa y confirmar el impacto sobre invitados ajenos y sockets libvirt.
3. Autorizar **separadamente** la aplicación física con control de cambios, recibo anterior, restauración y supervisión.
4. Realizar pruebas negativas sobre el bloqueo efectivo de arranque manual, sin abrir tráfico ni poner `P8=GO`.
5. Demostrar guardia en primer arranque y recuperación por watchdog independiente bajo fallas; el timer periódico no equivale a garantía temporal continua.

## Ejecución

Desde el repositorio de Prometheus:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r59c_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59c_f11_stage.py --source-only \
  --scratch-parent /home/cicada/ardrec-lab/r59c
```

La segunda orden crea **únicamente** un directorio temporal dentro del scratch privado para ensayar el árbol ficticio `F11_SANDBOX_SIMULATED_NOT_ETC`, lo verifica, lo reabre y lo elimina automáticamente. No necesita sudo. El resultado PASS no es aceptación F11.

## Controles y límites

- PIN SHA-256 de cuatro blobs, permisos de lectura, defensa ante enlaces simbólicos y huellas cambiadas.
- Cuatro rutas fijas y cuatro modos esperados (hook 0755, drop-in y unidades 0644).
- Comprobación y rollback ante fallo inyectado después de cualquier archivo en el árbol ficticio.
- Modo de repetición idempotente y rechazo de archivos agregados, manipulaciones o permisos abiertos.
- TUI R38/R42.5 y motor A1–A10 intactos. Nunca modifica resultados A5/A6/A7/A9.

**Resultado comprobable:** `R59C_SOURCES=PINNED_FOUR_VERIFIED`, `R59C_SANDBOX_STAGE=PASS_AND_REPLAY_IDENTICAL`, `host_mutations=0`, `f11_accepted=false`, `p8=NO-GO`.
