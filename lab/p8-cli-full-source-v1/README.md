# ARDREC P8-R14 — anclaje de entradas a siete manuales íntegros

**Roadmap: únicamente P8.** El informe privado `ARDREC_P8_R14_FULL_MANPAGES_20261109.json` (SHA-256: `2968e57fc65554735cef5ad349ec8a159dcc42fae3b0f05a653b2df0b20af365`) conserva las siete fuentes roff completas verificadas frente a la QCOW2. No se incluye el JSON privado ni texto íntegro de los manuales en Git.

`anchors.json` almacena 91 localizaciones **exactas de encabezados de entrada**, un hash SHA-256 de cada línea, su manual y hash de fuente, 25 límites de seguridad derivados para revisión y los 29 enlaces a perfiles del contrato R13. Se distinguen localización documental, evaluación semántica y autorización: encontrar una entrada de manual no atesta la semántica operacional del ejecutable, la configuración efectiva, el tráfico de red o el soporte real de un binario.

Límites documentales propuestos: configuración SSH heredada, instrucciones que invocan intérpretes o comandos externos, verificación de host keys, multiplexación, lotes SFTP mutadores, TLS requerido y degradaciones FTP, proxy/reintentos/protocolos de curl, cadenas de comandos Samba y RPC, firma distinta de cifrado SMB y exclusión de escrituras sin limpieza independiente. Son riesgos de diseño, no allowlists ejecutables. Las 5 variantes de escritura siguen bloqueadas.

**CI (sin manuales privados):**

```sh
python3 lab/verify_p8_cli_full_sources.py
python3 -m unittest discover -s lab/tests -p test_p8_cli_full_sources.py -v
```

**Comprobación local adicional contra informe privado:**

```sh
python3 lab/verify_p8_cli_full_sources.py --private-full /ruta/privada/ARDREC_P8_R14_FULL_MANPAGES_20261109.json
```

El verificador y sus pruebas no ejecutan ningún comando SSH/FTP/SMB, `sudo`, ni acceso de red. No hay archivo de `argv`, árbol de órdenes, destino, credencial, autorización, permiso de ejecución o algoritmo. P8, AL-06, AL-07 y obligaciones de desarrollo siguen abiertos.

**EN:** Seven pinned full sources, 91 exact source-entry anchors and 25 unapproved safety boundaries. Source-only, audit-only; zero completed semantic approvals, zero executable grammars, zero dispatch.
