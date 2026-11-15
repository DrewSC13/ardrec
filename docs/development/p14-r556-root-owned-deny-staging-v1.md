# ARDREC P14 R55.6 — Root-owned deny-only staging, sin timer y sin tráfico

**Base exacta:** `cb23f6a47d3d9f02ce720ec59fbdffc5c7421ece` (PR #128 fusionado). Repositorio público por elección del responsable; recibos host fuera de Git.

## Entrega

- `r556_root_staging.py` comprueba de forma determinista el paquete privado de R55.5 (`r555-prepared-20261115T170340Z-5617`), sus nueve archivos (siete para root, `contract.json` y `SHA256SUMS`), SHA-256, permisos, manifest, XML de ambos bindings, la política R34 deny y el hash fijo del recuperador.
- Produce exactamente nueve llamadas `/usr/bin/install` posibles: dos directorios `root:root 0700` y siete archivos `root:root 0600` a `/var/lib/ardrec/r555-deny-guard`. Nunca ejecuta shell, `nft -f`, `virsh` mutante ni `systemd-run`.
- `ardrec_p14_r556_stage.py --verify-offline` autentica material sin root, sin timer y sin acceso de red.
- `ardrec_p14_r556_stage.py --install-root-bundle`: **operación física distinta y autorizada por el operador**. Requiere `main` limpio con R55.6 integrado, denegación R33/R34 y pareja SSH+runner intacta (readback R55.3), ruta de destino vacía y autorización interactiva exacta `AUTORIZO_R556_INSTALAR_ROOT_SIN_TIMER`. Comprueba nuevamente el material antes del primer `install`.
- Tras las copias, se verifican propietarios/modos y el SHA-256 **desde los bytes root-owned** de todos los archivos antes de ejecutar `root-recover.py --check-root-bundle`. El chequeo privilegiado es exclusivamente read-only. Se repite la auditoría de denegación y se sella recibo 0700/0600.
- Si existe el destino o ocurre un fallo durante las copias, no se reintenta ni se sobreescribe automáticamente. Hay que inspeccionar el host y reconciliar el estado.

## Distinciones de alcance

La instalación de un programa de recuperación **no es** prueba de que recupere nftables/bindings. No se arma timer de sistema y no se instala servicio periódico. Tampoco hay experimentos de interrupción root, SSH guest, FTP, SMB, escaneos, ARP/ICMP positivos ni apertura de firewall. En todos los resultados `P8=NO-GO`.

**Hito siguiente R55.7:** probar en laboratorio idempotencia física de `--restore-deny` bajo autorización nueva, readbacks nft+bindings, y después implementar el temporizador supervisado por `systemd --system` con TTL fijo y prueba real de recuperación ante SIGKILL, antes de cualquier transición de política.

## Pruebas

```
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r556*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r556_stage.py --verify-offline
```

La primera ejecución física solo podrá hacerse **después** del merge y CI, y únicamente con autorización explícita en la terminal. El paquete ZIP no ejecuta ese modo automáticamente.
