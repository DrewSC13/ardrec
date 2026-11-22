# R135 — Núcleo de publicación durable y preflight físico de solo lectura

## Base y finalidad

- Base local firmada: `9b60dc0a884bf3042428d5d3466ea8b5cd9dd12e`.
- Rama única: `feat/ardrec-cierre-operacional-experimental`.
- `main` inicial: `95a6d57b8241101c7a8fa3aedc07fb779b088d9f`.
- Conservar R116-F1/F3, R130, R132, R133 y R134.
- El repositorio ARDREC es **público** por decisión del proyecto; no subir secretos ni evidencia sensible.

## Funcionalidad nueva de R135

`r135_root_transaction.py` construye y verifica el inventario estructural completo B4/B9 V2, publica dos directorios **privados** mediante dos renombrados `renameat2(RENAME_NOREPLACE)` y conserva un diario previo y un recibo durable. Implementa `fsync` para archivos, directorios y su padre. Verifica que un destino publicado contenga los bytes originales con permisos y propiedad esperados y no repara automáticamente la publicación ya observada.

El resultado permite recuperar pruebas de fallo después de preparar archivos, antes de publicar B4, con B4 únicamente publicado, con ambos publicados sin recibo y antes del recibo. Rechaza directorios ajenos, modificación de bytes, archivos faltantes, cambios de permisos, enlaces simbólicos, enlaces físicos, bloqueo simultáneo, journal alterado, recibo truncado y escritura sin espacio.

**No es todavía el instalador root independiente.** El núcleo no expone una CLI de instalación ni conoce las claves root; la devolución de `authorize(phase, plan)` es un contrato de inyección para el agente independiente. En las pruebas dicha función devuelve True y **no constituye una autorización real**. Los documentos JSON no-manifiesto son comprobados sintácticamente y por inventario, pero todavía no mediante sus guardas semánticas operacionales. Las pruebas usan directorios temporales privados, nunca los destinos `/var/lib/ardrec`.

Un instalador real deberá: estar instalado fuera del checkout por una operación independiente, verificar las claves públicas preprovisionadas root, la exclusión de los doce roles operacionales y de instalación, el commit/árbol firmado, la identidad de arranque, la liberación Ed25519 y la revocación fresca antes de cada paso; comprobar los contratos operacionales completos; ejecutar la transacción con `dirfd`, `O_NOFOLLOW`, políticas de recuperación y garantías contra TOCTOU; y realizar readback exacto de los dos destinos absolutos. R135 **no** acredita todo lo anterior.

## Preflight físico de B

`scripts/ardrec_p14_r135_lab_readiness.py --report` realiza exclusivamente consultas `virsh domstate` y `virsh net-info` a `qemu:///system`, sin sudo ni mutaciones. Comprueba si SSH, FTP y runner están encendidos, y SMB apagado, conforme al piloto históricamente definido, y obtiene el estado consultable de las tres redes. No da por demostrados los cinco enlaces presentes en DENY, el sexto ausente, aislamiento físico, guardián autónomo ni restauración medida; conserva `readiness=NOT_ACCREDITED`, `a6=ND` y `p8=NO-GO`.

El reporte puede guardarse únicamente como evidencia **privada** local en `/home/cicada/ardrec-lab`. No agregar al repositorio público direcciones IP, MAC, claves, dumps, capturas ni certificados.

## Pruebas de revisión

- 32 pruebas automáticas del núcleo transaccional en una caja temporal (inyección de fallos; no root operacional).
- 12 pruebas sintéticas del lector físico, sin ejecución `virsh` real.
- En Prometheus repetir las suites R130 (75), R132 (20), R133 (32), R134 (20) y R135 (44): objetivo local 191 pruebas, manteniendo los resultados de las suites por separado.

## Pendientes de aceptación

- Instalar y probar agente root autenticado independiente — **pendiente**.
- Provisionar confianza y aprobación auténticas — **pendiente externo**.
- Probar instalación y recuperación sobre rutas root reales, con readback — **pendiente**.
- Ejecutar preflight físico B en Prometheus y comprobar 5/1 + recuperación DENY — **pendiente**.
- FTP-T01 real y A1–A10 — **pendiente**.
- Calibrar P7 y validar 54 observaciones experimentales — **pendiente**.

No crear PR ni merge hasta el cierre A/B/C/D. Se autorizan commits firmados en la rama única. No ejecutar el código fuente con sudo ni usar el parche de Git como instalador root.
