# ARDREC — P8-R13: esquemas tipados abstractos sin ejecución (propuesta)

**Base protegida:** `5e8502f1c6f93046fecaab837660e4b8c2caef7a` (PR #45, P8-R12 integrado).

R13 incorpora **29 reglas estructurales** para clasificar intenciones de SSH (8), FTP/FTPS (10) y SMB (11), combinando identidad de la operación, clase de efecto, etiqueta de recurso ficticio, obligación de protección criptográfica y superficie de intérprete. Un validador puro rechaza entradas desconocidas y solo construye etiquetas internas deterministas no ejecutables.

La especificación **no define** sintaxis de `ssh`, `curl`, `sftp`, `smbclient` ni `rpcclient`, ni `argv`, opciones aprobadas, remotos SSH o órdenes SMB. Cinco variantes de escritura siguen sujetas a limpieza independiente y sus propios recibos. Las diferencias entre TLS de control/datos, firma/cifrado SMB y SMBv1 aislado se mantienen sin afirmar capacidad comprobada.

Gates: 0 gramáticas CLI efectivas, 0 flags aprobados, 0 renderizadores `argv`, 0 permisos, 0 casos reales y 0 despachos. 29 perfiles bloqueados. AL-06 y AL-07 pendientes; siete obligaciones abiertas. No VM, red, clientes guest, P9, A1–A10 ni experimento.

**EN:** P8-R13 proposes pure abstract typed-intent compilation and a strict schema for 29 blocked variants. Symbols are not executable arguments or authorizations. The general point 8 remains open until separate runtime, isolation, safety and evidence gates pass.
