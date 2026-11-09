# P8-R20 — Inspección offline de bibliotecas privadas Samba

Incremento de reducción de brechas de R19. R19 tenía 67 relaciones sin resolver a partir de seis directorios genéricos. R20 examina un único directorio adicional, `/usr/lib/x86_64-linux-gnu/samba`, reportado por los listados oficiales de Debian 13/trixie para `samba-libs` (amd64). Este dato externo sirve para **formular una consulta candidata**; solo la lectura autenticada de la QCOW2 del operador puede confirmar la presencia, identidad y hash.

El colector usa un recibo privado R19 fijado por SHA, verifica la imagen R9 antes y después, consulta enlaces/rutas canónicas por `guestfish --ro` y lee ELF por `virt-cat` sin ejecutar los objetos. Profundiza únicamente en bibliotecas nuevas del directorio Samba y coteja sus `DT_NEEDED` contra los candidatos de R19 y R20. Mantiene explícitamente cualquier relación todavía sin candidato y no implementa prioridad de `ld.so`, `ld.so.cache`, variables `LD_*`, preload, `glibc-hwcaps`, `RPATH` ni `RUNPATH` efectivos. La observación no es autorización, cierre runtime ni permiso de despacho.

El recibo es privado, de creación única, modo `0600` en directorio `0700` fuera de Git. La CI pública no accede al disco ni a recibos; solo valida contrato y pruebas sintéticas. Ninguna VM de ARDREC, cliente SSH/FTP/SMB, ni cargador invitado se ejecuta.

## Verificación estática

```sh
python3 -B lab/verify_p8_r20_samba_candidate.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s lab/tests -p test_p8_r20_samba_candidate.py -v
```

**EN:** Bounded Samba-private DSO candidate search, read-only and deny-only. Neither effective loader equivalence nor operational readiness.
