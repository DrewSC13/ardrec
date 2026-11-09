# ARDREC — P8-R12: lectura semántica acotada de manuales (propuesta)

**Base protegida exacta:** `82ed763b809f0ae0bc94c8dbfa5bc9fb1fd300f4` (P8-R11 integrado vía PR #44, CI pre/posmerge verificados).

**Alcance:** roadmap punto 8 exclusivamente; propuesta source-only de interpretación anotada de **91 expresiones** encontradas en siete páginas de manual de una imagen QCOW2, con **29 asociaciones por perfil**. El JSON original del operador no se incorpora ni se publica en Git. Su SHA-256 se vincula en el contrato para comparación local opcional. La evidencia se generó por lectura del anfitrión, no ejecución de los binarios del invitado.

**Resultado de interpretación acotada:** 74 fragmentos poseen una definición directa, 15 son menciones o descripciones incompletas, dos tienen colisiones léxicas de opciones cortas en `ssh` (`-o` frente a `-O`, `-l` frente a `-L`). La etiqueta de definición no representa lectura integral del manual ni valida argumentos CLI. `--ssl-reqd` de curl solo aparece mencionado en el fragmento, por lo que no se afirma cobertura completa de TLS de control y datos. El cliente `smbclient -c` y `rpcclient -c` interpretan listas de órdenes: una cadena libre no puede aceptarse como AST tipado. `ssh_config` muestra comandos que pasan por el shell; se excluyen del futuro diseño no acotado. `--ftp-ssl-control` y `--ftp-ssl-ccc` plantean degradación de cifrado documentada. `--max-protocol` no prueba una versión SMB mínima negociada, ni la firma implica cifrado.

**Semántica de política:** `EXCLUDE_FREEFORM_OR_DOWNGRADE` excluye **usos no acotados o degradantes** del diseño preliminar; no es un renderizador ni demuestra que cada herramienta pueda restringirse correctamente. `WRITE_NEEDS_SEPARATE_CLEANUP` identifica riesgos de mutación, nunca autoriza escritura ni borrado. `PRIVATE_MATERIAL_UNRESOLVED` identifica datos que requieren custodia privada. `BOUNDED_FUTURE_CANDIDATE` y `NEEDS_COMPLETE_MANUAL` son clasificaciones de investigación, no allowlists para ejecución.

**Gates intactos:** 0 revisiones completas del manual, 0 opciones/gramáticas aprobadas, 0 capacidades de binarios comprobadas, 0 casos/objetivos autorizados, 0 perfiles vinculados, 0 despachos. Persisten 29 perfiles bloqueados, AL-06 y AL-07, siete obligaciones de desarrollo y la imposibilidad de atestar el runtime vivo. No arrancan máquinas, no se invoca red, no se ejecutan clientes SSH/FTP/SMB y no se avanza a P9 ni A1–A10.

**Validación:** el verificador lee únicamente los archivos versionados, exige el contenido del artefacto por SHA-256 y compara el contrato con R10/R11 y sus 29 operaciones. Opcionalmente, `--probe RUTA_JSON` coteja el informe local íntegro por hash, cada término y su contexto por hash; no muestra los contextos ni publica el informe. CI ejecuta las pruebas de denegación y los verificadores de fuente sin acceder a la imagen ni a datos del operador.

**Estado:** propuesta hasta firma de commit, CI remoto e integración protegida.

**EN:** Bounded source-excerpt review, not complete manpage attestation, argument rendering, credential processing, case approval, trusted execution, experiment, or algorithm implementation. All 29 profiles remain deny-only.
