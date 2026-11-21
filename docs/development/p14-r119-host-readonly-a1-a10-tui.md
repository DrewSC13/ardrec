# ARDREC R119 — Integración de captura real de laboratorio y TUI de solo lectura

**Base:** merge PR #202, `main` `32edad13a45b43c365ef91a729be9e52896df054`. Fecha: 21-11-2026.

## Propósito implementado

Se incorporó el subcomando `python -m ardrec live` a la entrada normal. Reutiliza R115-F5 para capturar por comandos `sudo -n` predefinidos el estado REAL de libvirt, nftables, F11, helper de recuperación, definiciones de las VM runner/SSH/FTP/SMB y sus bindings. La TUI R38 original ahora distingue explícitamente `R119_REAL_HOST_CAPTURE_READONLY_NOT_RUNTIME_AUTHORITY` de las vistas DEV sintéticas. No aparece una segunda TUI independiente.

Permite enlace opcional `--caso-a5` a un diario privado F13 ya existente, validado por F14, sin crear socket ni gastar nuevo intento. Muestra la clasificación de A1–A10 (progreso de admisión/etapas, no ejecución de diez algoritmos), estado actual de cuatro VMs y bloqueos. Todos los estados son solo lectura: `P8=NO-GO`, `A6=ND`, `Rf=ND`, `A8` sin mutación y `A9` sin nueva generación.

## Uso en Prometheus desde Zsh dentro del repositorio

```
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m ardrec live --capturar --texto
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m ardrec live --capturar --tui
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m ardrec live --reproducir /home/cicada/ardrec-lab/r115-f5-lifecycle-deny-v1/capture-IDENTIFICADOR --tui
```

La primera opción genera un recibo nuevo R115-F5 privado. El capturador invoca **solo** la allowlist de comandos READONLY mediante `sudo -n`, `shell=False`; requiere los privilegios ya existentes. Si faltan, presenta estados ND en lugar de solicitar cambios en sudoers. La opción `--reproducir` valida un recibo ya almacenado (permisos, owner, hashes, bytes canónicos y replay íntegro) y lo etiqueta `REPLAY`, **nunca como lectura actual**. La vista TUI conserva `q` para volver a Zsh y no se conecta a la red al navegar. No canalizarla a `more`, porque necesita TTY. Los datos brutos del host permanecen privados y no se imprimen en stdout.

La fuente cerrada F5B V3 se verifica por huella y semántica versionada; **no** prueba vigencia del binario instalado ni firma/revocación actual. Una captura real no concede por sí misma autorización para conexiones, arranques ni aceptación A6. SSH/FTP/SMB pueden estar apagados: esto es un resultado, no un fallo de implementación R119.

## Cobertura y bloqueos específicos

A1 y A2 solo presentan ausencia de autoridad para reglas operativas y el vínculo de cierre SOURCE_ONLY; A3 muestra las guardas del reporte vivo F5 y los estados de DENY; A4 permanece sin selección; A5 refleja, si se adjunta, el estado de un diario F13/F14 candidato; A6 y A7 quedan ND; A8 no altera el estado; A9 no publica ninguna generación; A10 reproduce una vista de lectura del anfitrión, claramente rotulada, en la TUI ya existente. El contador de progreso técnico no aumenta por abrir la vista.

Los bloqueos previstos incluyen P7 sin congelamiento, ausencia de acreditación independiente P8/revocación, integridad insuficiente de fuentes físicas para admitir A6, falta de nueva generación A9 y, según la captura, drift F11/R34, VM no conforme, SSH/FTP/SMB apagado o lectura antigua. R119 no permite evadirlos.

## Verificación

- `lab/tests/test_p14_r119_live_readonly.py`: 28 pruebas de contrato con fixtures sintéticas **explícitamente identificadas**; no se alegan pruebas en el host real ni un nuevo intento FTP.
- Regresiones R38, R69, R71, R118 y R117: se ejecutan sobre la copia antes de enviar el parche; registrar resultados exactos.
- CI Python de `.github/workflows/ci.yml`: descubrimiento explícito y ejecución R119.

La primera captura viva de Prometheus se comparará con la configuración efectiva de la máquina y determinará el próximo cambio operacional concreto. La fase siguiente conectará autoridad vigente, resultado físico independiente y admisión A6 al ciclo A7–A10 y a la persistencia A9; no se debe inferir de este incremento que ya existe una generación técnica confirmada.
