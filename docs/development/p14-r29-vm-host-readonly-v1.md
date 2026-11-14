# P14-R29 · Verificación read-only de identidad documental y residuos libvirt

**Base exacta:** merge PR #94, `03db4d120a87a04a9487088b1ccc1da1fe165161`.

## Problema y decisión

R28 ofrece una TUI real con A1-A10 de desarrollo, pero no realizó observaciones de VM. El último registro público de desarrollo de servicios en `lab/services-v1/evidence.json` conserva una prueba histórica de 4 VM, 17 comprobaciones y cierre con **dominios apagados y redes transitorias retiradas**. Su archivo de activación de un solo uso NO se puede volver a invocar. R29, por ello, nunca crea/arranca/destruye una VM ni reproduce los checks históricos.

## Identidades del entorno DEV del histórico

- `ardrec-dev-ssh`: `10.203.30.2`, TCP 22, red aislada `ardrec-dev-ssh`.
- `ardrec-dev-ftp`: `10.203.31.2`, TCP 21 (FTPS explícito), red `ardrec-dev-ftp`.
- `ardrec-dev-smb`: `10.203.32.2`, TCP 445, red `ardrec-dev-smb`.
- `ardrec-dev-runner`: 3 interfaces históricas `10.203.30.1`, `10.203.31.1`, `10.203.32.1`.

Estos son **datos históricos**, no una confirmación de que los dominios o las IP estén activos hoy. Se contrastan exclusivamente nombres de libvirt y, si existen dominios, UUID y NIC/MAC de su XML con el patrón registrado. Ni una coincidencia completa acredita identidad del invitado, procedencia de la imagen, TLS, el aislamiento físico o permiso operativo.

## Modo sin efectos secundarios

`--historical-only` lee los registros públicos y el ciclo R28 inmutable. No invoca `virsh` ni toca la red.

`--observe-local-libvirt` usa únicamente `virsh --readonly --connect qemu:///system` con `list --all --name`, `net-list --all --name` y, para los dominios declarados presentes, `domuuid`, `domstate` y `dumpxml --inactive`. No invoca `sudo`, `ssh`, `curl`, `smbclient`, `nmap`, `net-create`, `start`, `resume`, `destroy` ni realiza un socket a la VM. Cada subprocess recibe límites de tiempo/salida, entorno fijo y argumentos constantes. Una falla de libvirt aborta sin conceder PASS. Un dominio presente o un nombre de red `ardrec-*` requiere revisión; se evita interpretar esa presencia como seguridad verificada.

La vista de diez algoritmos de R28 permanece inalterada. R29 añade un panel de laboratorio mediante la tecla `v`, ligado al SHA-256 de `ciclo.json`, sin repetir el intento benigno. Todos los valores resultantes conservan `P8=NO-GO`, riesgo final ND, cero checks de invitado y cero generaciones.

## Límites de aceptación

- Aceptable: lectura de metadatos locales sin mutación y reporte con fuente histórica diferenciada, digest, resultados por los cuatro roles y estado de residuos libvirt.
- No aceptable: alegar hosts activos porque el histórico reportó IP; convertir presencia libvirt en verificación de servicio; reeditar/RUN de activation-r8; superar AL-06/AL-07; liberar perfiles P8; acreditar A7 con hechos de red no observados.
- Si los dominios históricos no están definidos hoy, `ABSENT_FROM_LIBVIRT_LIST` no es un fallo de software: coincide con la limpieza de noviembre, pero **no** certifica restauración, custodia externa ni ausencia de recursos con otros nombres.

## Continuidad R30

La siguiente capacidad real será una verificación de identidad y autorización de **nuevos** recursos de desarrollo restaurados bajo un procedimiento reutilizable distinto del R8 congelado. Solo con esa base independiente y una decisión explícita de seguridad cabe conectar resultados de servicio a A5-A6. No cambiar la clasificación ND ni el riesgo final antes de disponer de esos recibos.
