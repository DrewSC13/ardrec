# R71 — Demostración positiva acotada A3/A4/A5 con R38 original

**Base obligatoria:** merge R70 (`74e7501618bde4c51839fb5e8b88fdc4c6967da8`).
No sustituye R69/R69.1/R70, ni modifica sus objetos generacionales.

## Alcance implementado

1. Antes de iniciar un proceso, reabre el almacén R70, verifica GEN0, GEN1, la instantánea analítica, el HEAD y las fuentes de A1. Exige GEN1 estructural y `P8=NO-GO`.
2. A3/A4 usan la **proyección sintética independiente** de R27. El selector real de la generación R70 permanece vacío; el selector hipotético obtiene SSH_DEV / CASE_REFERENCE (prioridad 1/4; precedencia 10), con guardas verdaderas *únicamente* en la proyección.
3. A5 ejecuta **exclusivamente** el fixture local predefinido `ok` del `BenignPipeline` existente. No admite comandos proporcionados por el usuario, no abre sockets contra las VM y registra un solo inicio verificable con artefactos SHA-256 y recuperación idempotente.
4. A6 clasifica ND porque un recibo de un proceso benigno local **no demuestra la condición de SSH**, ni FTP/SMB, ni satisface procedencia operacional. El proceso local NO deriva de una reserva A5 de la máquina de estados ARDREC.
5. A7 usa `r58d_interval_kernel.build_intervals()` sobre un dato **sintético fijo** E=1/2. Para este ejemplo da valor hipotético 5/12. El Rf **confirmado permanece ND**. No se presenta ese valor como observación ni resultado del proceso benigno A5.
6. A8 conserva el `DETENER` de R70 sin desbloquear ni reabrir servicios; A9 conserva GEN1 y NO crea GEN2. A10 renderiza la información en el **mismo** `dashboard_tui.py` R38, con paneles, teclas y políticas anteriores.
7. La salida R71 es determinista para un diario de proceso confirmado, anclada al recibo GEN1 de R70 y sus hashes. Se recalcula a partir de la persistencia existente y los recibos de `BenignPipeline`; no crea otro almacén A9.

## Entrada de demostración

Solo terminal Zsh, usuario no-root; tras crear GEN1 mediante R70:

```text
PYTHONPATH=src python3 -B -m ardrec --durable-dev-root /home/cicada/ardrec-lab/r70-safe-tutor-001 --shadow-cycle --shadow-journal-root /home/cicada/ardrec-lab/r71-benign-tutor-001 --tui
```

`--json` en lugar de `--tui` produce un documento verificable con hash. Repetir la invocación reutiliza el único inicio confirmado; un inicio ambiguo o un artefacto alterado bloquea la operación en vez de repetirla.

## Exclusiones importantes

- **No** autoriza P8 o despacho físico, no ejecuta pentesting, no abre conexiones SSH/FTP/SMB y no acredita evidencias A6 de servicio.
- **No** recalcula Rf confirmado a partir de la evidencia sintética de demostración.
- **No** crea generación A9 posterior. Es una integración verificable de selección/sombra/ejecución benigna, previa al recorrido técnico autorizado.
- La existencia de R70 GEN1 no hace elegibles sus observaciones: permanecen DETENIDO.

## Aceptación

La suite R71 prueba integridad, selección hipotética, primer inicio benigno local, idempotencia, no alteración GEN1, riesgo hipotético, corrupción y el proceso curses real. Las pruebas preexistentes R70, R69.1, R69, R38, R28, R67, R68, R42.5 y archivo analítico se deben repetir en Prometheus y CI. No declarar completitud técnica A3–A7 ni del experimento hasta pruebas físicas autorizadas.
