# ARDREC — P8-R18: observación ELF offline; sin cierre de dependencias

**Base de integración prevista:** `05513b28af3ffa23ef98cef3fd4e2dcf2a71eea8`, PR #50
R17 fusionado, `main` sincronizado, CI previa y posterior aprobadas.

Se agrega un instrumento de medición restringida para tres binarios candidatos ya
registrados por R9: `ssh`, `curl` y `smbclient`. El lector R18 exige antes las
comprobaciones históricas de la QCOW2 inmutable de R9 y extrae solamente el ELF
de cada candidato con `virt-cat`, mediante lectura offline (guestfs puede iniciar su appliance de inspección,
no la VM de ejecución de ARDREC). Compara los tres SHA
observados con R9, analiza su intérprete dinámico y etiquetas `DT_NEEDED`, y
rehace el hash de la imagen después de la adquisición. El informe privado queda
fuera del repositorio, en modo `0600`, sin adjuntar los bytes de los binarios.

En la CI solo se verifica el contrato estructural y el parser sobre bytes sintéticos.
La salida privada del operador requiere verificación adicional y NO será promovida
por una prueba sintética. Resolver completamente rutas, symlinks, ABI de bibliotecas,
resolución de `ld.so`, dependencias transitivas y características de ejecución
es trabajo posterior; también lo son la configuración efectiva de SSH/FTP/SMB,
autorización privada, límites de ejecución y limpieza independiente de escrituras.

**Sin promoción:** 29 perfiles siguen bloqueados, 348 vinculaciones sin resolver;
0 opciones CLI, 0 gramáticas ejecutables, 0 casos, 0 perfiles autorizados,
0 despachos. P8 y AL-06/AL-07 abiertos; P9 y A1–A10 no iniciados.

**EN:** Offline ELF metadata collection, not dependency closure or operational approval.
