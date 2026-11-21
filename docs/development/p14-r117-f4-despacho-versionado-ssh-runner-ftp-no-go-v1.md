# R117-F4 — Despachador versionado SSH → runner → FTP (código; NO-GO físico)

## Objetivo

Liberar dos controladores R117 **versionados** para las etapas SSH y runner/FTP,
reutilizando sin modificaciones el motor verificado R116-F12. El histórico
R116-F13 continúa criptográficamente cerrado. F4 es una entrega **source-only**:
instalar, verificar, probar y firmar el código no inicia una VM, no altera nftables,
no arma systemd y no emite autorizaciones.

## Transformación controlada

- `r117_f4_controlled_boot.py`: derivación literal del F7 R116 con sustituciones
  exhaustivas de esquema, rama, ancestro del merge R116, directorios privados,
  dominios criptográficos, rutas de fuentes y mensajes CLI.
- `r117_f4_runner_ftp_boot.py`: derivación literal del F8 R116, vinculada al
  nuevo F7 R117 sin monkeypatches ni carga de código de R116 a modo ejecutor.
- La familia `r116_*`, sus 33 fuentes fijadas y el manifiesto raíz F12 siguen
  intactos. CI incluye una prueba de correspondencia exacta de bytes de ambas
  derivaciones respecto del original (sólo sustituciones permitidas).

## Fronteras operacionales

1. R117-F3 exige HEAD Git firmado `G`, rama exacta, `main` R116 fusionado
   como ancestro y árbol limpio antes de cualquier operación de arranque.
2. Cada boot exige contrato FTP-T01 con revisión Ed25519 independiente,
   autorización vigente y revocación separada, y permiso por rol igualmente
   firmado, revocable y ligado al HEAD/plan. No se crean llaves, permisos ni
   expedientes falsos.
3. Secuencia única SSH → runner → FTP; un inicio por rol como máximo.
   Se conservan intentos fallidos y posibles incidentes, sin reintentos
   automáticos ni limpieza destructiva.
4. F5/R34 se valida antes y después de cada etapa; P8 no es habilitado.
   SMB permanece apagada. No se autoriza tráfico ni piloto FTP por el boot.
5. Los permisos R117-F4 se leen sólo desde las nuevas rutas raíz:
   `/etc/ardrec/r117-f4-boot-trust-v1.json` y
   `/etc/ardrec/r117-f4-boot-revocation-v1.json`. Los dominios de firma usan
   `ARDREC-R117-F4-...`, incompatibles con firmantes documentales previos.
6. Los nuevos recibos privados se guardarán bajo
   `/home/cicada/ardrec-lab/r117-f4-one-boot-deny-v1` y
   `/home/cicada/ardrec-lab/r117-f4-runner-ftp-deny-v1`.
7. La integración con el controlador root del piloto FTP-T01 requiere
   versión y staging aparte: **el controlador root R116-F3 vigente no admite
   recibos F4**. No ejecutar arranques físicos hasta que la versión raíz
   candidata y sus fuentes sean verificadas junto con la autoridad externa.

## Validación reproducible

- `PYTHONPATH=src:scripts python3 -B scripts/ardrec_p14_r117_f4_dispatch_audit.py --offline`:
  sólo verifica hashes y 33 fuentes fijadas.
- `--source`: verifica además firma Git vigente R117 y vínculos de módulos.
- `--root`: audita únicamente la instalación F12 anterior (no migra).
- Todas las funciones de arranque están sujetas a permisos independientes.
- Regresión R112–R117, sin permisos root ni tráfico; CI exacta.

## Estado de aceptación

`P7=DRAFT`; `A5 nuevo=NOT_ATTESTED`; `A6=ND`; `P8=NO-GO`.
R117-F2 sigue como prueba previa válida de reaplicación DENY 45 s en 0/6,
**no** como recuperación física desde ALLOW o 5/1.
