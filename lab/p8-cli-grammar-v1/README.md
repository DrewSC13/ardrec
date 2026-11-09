# ARDREC P8-R13 — gramática tipada abstracta / non-executable

**Únicamente roadmap P8.** Este incremento agrega un compilador puro de intenciones a etiquetas tipadas para los **29 perfiles bloqueados**. Su entrada acepta exclusivamente seis campos y valores enumerados fijados por la fuente versionada; su salida son etiquetas internas para revisión técnica, **nunca** `argv`, comando remoto, orden `smbclient -c`, credencial, destino, token CLI aprobado ni permiso de ejecución.

Hay **cinco perfiles de escritura** con `VERIFY_THEN_REMOVE_MARKER`. Se prohíbe convertir la eliminación en una instrucción libre; cada escritura seguirá exigiendo limpieza independiente y recibos futuros. Se distinguen expresamente `FTP_CONTROL_TLS_UNVERIFIED` y `FTP_DATA_TLS_UNVERIFIED`; `SMB_SIGNING_UNVERIFIED`, `SMB_ENCRYPTION_UNVERIFIED` y `SMBV1_ISOLATED_FIXTURE_ONLY_UNVERIFIED`. Esas etiquetas son obligaciones **no verificadas**, no afirmaciones de compatibilidad.

El campo `assurance_design` no acredita configuración efectiva; `resource_tag` es un marcador de recurso sintético, no una ruta, URI ni usuario. No existe renderizador de flags ni concatenación de cadenas de órdenes. Se rechazan campos extra, duplicados JSON, valores fuera de enumeración, secretos, destinos, parámetros libres, degradaciones de TLS y cadenas arbitrarias con delimitadores de shell.

## Verificación

`python3 lab/verify_p8_cli_grammar.py` comprueba hashes exactos y correspondencia 29/29 con P8-R12, además de compilar planes simbólicos de prueba sin contactos físicos. `python3 -m unittest discover -s lab/tests -p test_p8_cli_grammar.py -v` ejecuta pruebas adversariales.

No se modifica el catálogo original, las reglas A1–A10, permisos, casos, red, clientes o sistemas virtualizados. No hay atestación de capacidades de CLI, del runtime vivo, de identidad de objetivos, de credenciales ni de límites piloto. Se mantienen AL-06, AL-07 y siete obligaciones abiertas.

**EN:** Closed abstract intent schema, not a verified CLI grammar. Five distinct cleanup-gated writers, protocol-specific unverified assurance requirements, 29 disabled variants. No argv, shell, private authorization, dispatch, experiment, P9, or algorithms.
