# ARDREC — P8-R20: reducción de brechas ELF privadas de Samba

**Base:** `4d0907a982183a33b18eb2decba20fc02f37b822`, PR #52 (R19) fusionado y CI posterior aprobada.

R19 observó offline 68 bibliotecas candidatas, 292 relaciones, 67 relaciones no resueltas y 0 ambiguas en el dominio de seis directorios genéricos. Entre los SONAME pendientes aparecen bibliotecas `*-private-samba.so.0`. El listado de archivos de `samba-libs` en Debian 13/trixie/amd64 incluye numerosas bibliotecas con estos nombres en `/usr/lib/x86_64-linux-gnu/samba` (fuente documental pública: https://packages.debian.org/trixie/amd64/samba-libs/filelist). El listado documental **no confirma** su presencia en la QCOW2 particular.

R20 introduce un único directorio nuevo de búsqueda **candidate-only**, una lectura offline con comprobación de integridad de la imagen R9 antes/después, detección de enlaces canónicos y metadatos ELF; además, contrasta los nuevos `DT_NEEDED` con los candidatos históricos y marca los restantes. No cambia R19, no ejecuta `ld.so`, servicios, CLI, VM, ni despachos. No infiere orden de búsqueda, `RPATH/RUNPATH`, cache o identidad dinámica real.

**Pendiente:** medición de R20 en la QCOW2, compatibilidad y configuración efectiva por perfil, revisión real de `argv`, límites de tiempo y recursos calibrados, autorización/alcance/revocación de casos, evidencias AL-06/AL-07 y pruebas independientes de limpieza para las cinco variantes de escritura. Los 29 perfiles permanecen bloqueados, 0 casos y 0 despachos. P8 sigue abierto; P9 y A1–A10 no iniciados.

**EN:** Samba-specific offline candidate DSO lookup supplements, but does not replace, real loader attestation or per-case authority.

## Resultado material R20 verificado por el operador

Adquisicion privada offline R20 sobre la imagen QCOW2 fijada por R9: **67/67 relaciones pendientes de R19 recuperadas como candidatas**, **64 bibliotecas nuevas**, **563 relaciones nuevas**, **8 nuevas relaciones sin resolver** y **53 indicadores de rutas de busqueda personalizadas**.

SHA-256 del recibo privado: `0e3d4fb71dc8784d551cf2e028fa441e719d2c443baa14af5aebe7d76951f17d`.

El recibo permanece fuera de Git. La observacion no certifica la semantica efectiva del cargador dinamico, identidad de runtime, configuraciones efectivas ni autorizaciones. Cero perfiles, cero casos y cero despachos.
