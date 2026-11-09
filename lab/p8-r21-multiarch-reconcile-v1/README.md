# P8-R21 — conciliación offline de dependencias ELF (sin despacho)

Este incremento toma como base exacta el merge firmado de P8-R20 (`363f5ca7b34419e5a1da270907f9b89c768e6a08`) y los recibos privados R19 y R20, fijados por SHA-256. R20 recuperó **67/67 relaciones antiguas** como candidatos, pero dejó **8 relaciones adicionales** sobre cinco SONAME:

- `libdcerpc-binding.so.0` (2)
- `libjansson.so.4` (1)
- `libndr-krb5pac.so.0` (3)
- `libsamdb.so.0` (1)
- `libwbclient.so.0` (1)

R21 valida **otra vez** los dos recibos privados sin incorporarlos al repositorio; reconstruye el informe R20 desde las bibliotecas observadas y los estados previos, rechazando desviaciones. Consulta con `guestfish --ro` los seis directorios candidatos de R19 **más** `/usr/lib/x86_64-linux-gnu/samba` de R20. Consolida alias por ruta canónica; si hay dos candidatos realmente diferentes registra *ambigüedad*, nunca elige el primero. Solo lee el ELF de candidatos únicos no vistos previamente y descubre sus `DT_NEEDED` posteriores hasta agotar el frente o alcanzar límites explícitos. Verifica el hash de la QCOW2 antes y después, sin arrancar la VM de ARDREC ni ejecutar las bibliotecas.

Esto **no** reproduce `ld.so`: no inspecciona prioridades reales, `ld.so.cache`, `glibc-hwcaps`, `LD_*`, `preload`, `RPATH/RUNPATH` efectivos, configuración de clientes ni identidad en ejecución. Un grafo candidato completo no es un cierre real del cargador y **no autoriza** perfiles, casos, presupuestos ni despachos.

## Pruebas públicas (sin material privado)

```sh
python3 -B lab/verify_p8_r21_multiarch_reconcile.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s lab/tests -p test_p8_r21_multiarch_reconcile.py -q
```

## Adquisición material privada

Tras validación y comprobación independiente de imagen inactiva, autenticar `sudo -v` y ejecutar desde el worktree R21 el colector **sin root** con `--confirm-image-idle`, en directorio privado `0700` y recibo de creación única `0600`. No repetir si ya existe. Compartir **solo** el resumen de stdout, no el JSON privado.

**Salida permitida:** constatación de rutas y hashes offline candidata, sin promoción de autoridad. P8, AL-06/AL-07 permanecen abiertos; P9 y A1–A10 no iniciados.

**EN:** Read-only R19/R20 receipt provenance, seven-directory canonical DSO candidate reconciliation, ambiguous outcomes denied; no loader, runtime, authorization or dispatch proof.
