# R114-F4 — Primera lectura real A5-adjunta FTP-T01 (sin evidencia A6 automática)

## Alcance autorizado

Se reutilizan el recibo **R114-F3** `anchors-79002bed` y toda su ascendencia autenticada F2, F1, R113-F2/QGA, P7 y F10R. Se selecciona exclusivamente el activo FTP `ardrec-r33-dev-ftp` (`52:54:00:ad:31:02`, `10.203.31.2/28`) y su candidato **FTP-T01**, manteniendo el antecedente de control TCP 21 de F10R como evidencia anterior **sin convertirlo en ejecución A5**.

La nueva acción física, separadamente autorizada, es **un solo** `guest-exec` en FTP de `/usr/bin/cat /etc/vsftpd.conf` mediante QGA. Se guarda un marcador `.once` **antes** de pedir la ejecución; se capturan las respuestas QGA y los bytes de configuración **antes** de interpretarlos. Se verifica `qemu-guest-agent guest-info`, identidad MAC de la VM, y el `DENY` F6 **antes y después**.

No hay `systemctl start`, tráfico de red, root-shell, modificación de servicios, cambio de filtros ni apertura de R34. No hay nuevas ejecuciones de SSH o SMB.

## Alcance epistemológico

Leer `/etc/vsftpd.conf` permite acreditar **el contenido real de un archivo de configuración**, no la configuración efectiva completa del demonio (incluyendo opciones por defecto, overrides o entorno). El método nominal `FTP_EFFECTIVE_CONFIG_READONLY` de A5 puede enlazarse como **intención formal de caso**, pero este recibo no acredita el procedimiento completo. La identidad de caso `FTP-T01-S01-01` es una propuesta operacional localizada en un activo físico; la existencia de este registro no prueba un intento A5 formal completo. La salida F10R previa tampoco se reclasifica como un intento autorizado retroactivo.

El recibo exige mantener `a5_case_start_independently_accredited=false`, `a5_family_execution_completed=false`, `a6_classification=ND`, cero soportes A6 admitidos, `a7_rf=null`, cero transiciones y `P8=NO-GO`.

## Entradas, persistencia y replay

- Fuente F3: manifiesto `9a216b641f01fdeba5c5e559bb4819393212ecc6c5bbc6f7d90e79f8663f2acf`, informe `4f2132be53f2c700199ce6fe2d12f1d95008781f3283f6fd5db19e26200a9a9c`.
- Directorio privado: `/home/cicada/ardrec-lab/r114-f4-ftp-configuration-read-v1/capture-<hex>`; directorios `0700`, archivos `0600`, creación exclusiva, sin sobrescribir incidentes.
- Replay: verifica cada hash y alcance de archivos, fuente F3 original, XML de identidad capturado, marcador `.once`, secuencia QGA, respuesta original byte por byte, contenido del archivo, estado F6 antes/después, intención R59D y el informe recomputado. **No ejecuta QGA ni consulta el host**.

## Secuencia operacional

1. Validar rama, HEAD firmado y árbol Git limpio; verificar ZIP y hash de cada archivo.
2. Instalar cuatro archivos fuente, ejecutar **783** pruebas (743 previas y 40 nuevas) y crear commit firmado.
3. Solicitar `AUTORIZO_UNA_LECTURA_LOCAL_VSFTPD_CONF_QGA_R114_F4_DENY`.
4. Reabrir/verificar F3 y F6, verificar MAC e interfaz, verificar comandos QGA admitidos, escribir marcador y ejecutar **un** proceso local.
5. Guardar respuesta y bytes antes de interpretar. Acreditar F6 posterior, emitir informe y replay.
6. En caso de error, detenerse, conservar la sesión y **no repetir** `guest-exec`.

Próximo incremento: diseñar la ejecución completa y acotada FTP-T01 con identidad de caso y enlace formal de resultado, seguida de evaluación A6 si los soportes exigidos se observan y acreditan. Las rutas SSH-T01 y SMB-T01 requieren negociación independiente; `P8` no se activa prematuramente.
