# ARDREC R166-F3 — Diagnóstico causal desde originales R115 y lectura pasiva R163

## Base real del incremento

Prometheus, 23-11-2026: R166-F2 aplicado e idempotente (4/4), 28/28 R119 y
10/10 R166-F2; captura actual `capture-khhz0lsk`, SHA-256
`52506150bab3cac68187099478ecd6359875045f18837328a52d39cd8614c007`.
La captura tiene 18/18 sondas `RC_1`, todas las VM, bindings, nft/helper/hook
`ND`, `P8=NO-GO` y `0` modificaciones de anfitrión. El proceso de captura
terminó con código `0`; eso no acredita que las sondas hayan sido exitosas.

## Reutilización y nuevo contrato

La CLI existente `python -m ardrec live --capturar --texto --diagnostico`
incorpora los indicadores opcionales `--causas` y `--r163-presencia`.
No hay nuevo capturador, subproceso root, agente, familia de prueba ni TUI.

- `--causas`: R119 llama a `f5.report(capture)` y solo después clasifica el
  `stderr` base64 contenido en la **captura original privada** R115-F5.
  Proyecta códigos de vocabulario cerrado sin mostrar `stderr`, `stdout`,
  direcciones, nombres de máquina, usuarios, dominios ni rutas de ficheros
  derivados de la salida del host. `R166_F3_ORIGINAL_CAPTURE_SHA256` vincula
  la proyección al documento fuente. Las cadenas de error son pistas, **no**
  autenticación de privilegios ni prueba de inexistencia de máquina.
- `--r163-presencia`: lectura `lstat` no privilegiada de las rutas fijas que
  declaran los componentes de bootstrap, agente, manifest, fuentes B4/B9,
  journal/receipt y documentos de confianza R163. `ACCESS_DENIED_UNKNOWN`
  no se interpreta como ausencia; `ROOT_0600_METADATA_ONLY` no acredita hash,
  procedencia, firma, vigencia ni instalación funcional. No se abre ni se lee
  ningún documento de autorización/revocación.
- Se mantienen explícitamente `R166_F3_ROOT_INSTALL_ACTION=NONE`,
  `R166_F3_R163_SOURCE_AUTHENTICITY=NOT_ATTESTED`,
  `R166_F3_R163_SIGNED_AUTHORITY=NOT_ATTESTED`, `R166_F3_P8=NO-GO` y
  `R166_F3_HOST_MUTATIONS=0`.

## Interpretación de causa por sonda

| Código | Qué acredita el `stderr` concreto | Siguiente comprobación permitida |
|---|---|---|
| `SUDO_AUTH_REQUIRED` | `sudo -n` pide autenticación o terminal | Revisar política exacta de lectura bajo custodia del operador; no poner `NOPASSWD: ALL` |
| `SUDO_POLICY_DENIED` | Política de privilegios prohíbe el comando | Revisar la lista cerrada R115-F5 `READS` y la delegación estricta por ruta y argumentos; no cambiar privilegios automáticamente |
| `SUDO_TTY_POLICY` | Política exige TTY | Corregir configuración de acceso según la política institucional, previa autorización |
| `LIBVIRT_CONNECT_FAILED` | Error de conexión a libvirt | Revisar servicio/socket del host y permisos; no arrancar VM |
| `LIBVIRT_OBJECT_NOT_FOUND` | Domain o binding ausente según virsh | Reconciliar definiciones/inventario sin crearlas desde la CLI |
| `NFT_TABLE_NOT_FOUND` | La consulta de nft no halla el recurso | Verificar origen firmado del filtro R34 antes de cualquier instalación |
| `SOURCE_FILE_NOT_FOUND` | Falta un fichero consultado por SHA-256 | Contrastar staging R163 y los originales firmados |
| `UNCLASSIFIED_NONZERO` | La salida no se ajusta a patrones conocidos | Examinar solo el recibo privado en Prometheus, no publicarlo |
| `NONZERO_WITHOUT_STDERR` | Falla sin diagnóstico en stderr | Conservar recibo y cotejar situación local |
| `COMMAND_UNAVAILABLE`, `TIMEOUT`, `OUTPUT_TRUNCATED` | Captura no concluyente | Corregir la causa antes de repetir |

El estado `P8=NO-GO` tiene precedencia sobre cualquier diagnóstico
favorable. No ejecutar `--stage` ni `--apply` desde el checkout mutable; no
levantar máquinas ni cambiar filtros hasta verificar los contratos físicos.

## Reconciliación R163 anterior a cualquier intervención root

1. Comparar commit y árbol de la fuente R163 F8/F9/F10 con el staging y
   recibo privado del **host**, no con la copia del repositorio.
2. Revisar integridad de `/opt/ardrec/r163-bootstrap-v1/bootstrap.py` y
   `/opt/ardrec/r163-installer-v1/installer.py` contra sus originales firmados.
3. Contrastar los hash SHA-256 reales de B4/B9 y el manifiesto root con
   journal y recibo root. La metadata no sustituye esta prueba.
4. Confirmar quién custodia las claves y qué autoridad independiente exigen
   los contratos; un operador con varias claves sigue siendo una persona.
5. Revisar autorización vigente y revocación efectiva mediante el agente
   instalado externo y la política del host; si no hay recibo admisible,
   conservar bloqueo.
6. Solo después planificar por separado cualquier reparación de acceso
   estrictamente READONLY a `sudo -n` y la instalación física firmada.
7. Repetir captura actual y relectura desde originales. Conservar fecha,
   `R119_CAPTURE_ROOT`, `R119_CAPTURE_SHA256`, causas clasificadas y estados.

## Pruebas y límites

`test_p14_r166_f3_causal_root_readback.py`: 16 tests de sanitización,
identidad de originales, clasificación, metadata y ausencia de subprocesos.
Se conservan R119 (28), R166-F2 (10), R166-F1 (13), R165-F3 (20) y R163
(12+12) como regresión, sin sustituir la aceptación física.

**No está permitido afirmar:** B4/B9 instalado, guardian independiente,
restauración medida, FTP-T01 real, recalibración final, A6 admitida, A9
publicada ni 54 unidades experimentales. Todo ello permanece pendiente de
sus originales y pruebas en Prometheus.
