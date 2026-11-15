# ARDREC P14-R43 — A1–A10 local reproducible en TUI R38 (NO-GO)

## Objetivo

Ejecutar de verdad el **fixture local benigno** previsto por R27/P9–P12 y enlazar su
registro A5, clasificación documental A6=ND, oráculo A7, parada prudente A8,
recibo durable A9 y vista A10 en el monitor R38/R42.5. No crear otro TUI.
El reporte refleja **tres categorías distintas**: (1) A1–A4 sintéticos;
(2) A5 local ejecutado y reconciliado, NO SSH/FTP/SMB;
(3) evidencia física SSH histórica R42.2/R42.3 de solo lectura.

## Condiciones técnicas

- Base exacta de `main`: `2169c2bd24f87efe03357d90a41843a2d900e619`.
- R42.4 mantiene esquema anterior para preview; R43 etiqueta explícitamente
  `SYNTHETIC_AND_LOCAL_BENIGN_A1_A10_DEVELOPMENT_ONLY`.
- Ruta del diario: directorio de nombre `r43-local-cycle-YYYYMMDDTHHMMSSZ-PID`
  ubicado **solo** bajo el padre privado 0700 de los recibos SSH. Sin symlinks,
  sin chmod automático y sin guardar recibos en Git.
- Ejecución requiere `--run-local-benign`, `--journal-root` y
  `--i-authorize-r43-local-benign`; omitir cualquiera bloquea el intento.
- La única instrucción ejecutable procede del fixture `ok` de BenignPipeline:
  Python aislado, salida acotada y deadline 1000 ms. No comandos arbitrarios.
- Se comprueban evento SHA, `start_count=1`, artefactos, enlace del recibo R28
  y SHA del reporte antes de mostrar el dashboard.
- Reabrir el MISMO directorio es idempotente: no debe ejecutar el fixture dos veces.
- Rf operativo queda ND, clasificación técnica A6 ND, ninguna publicación A9,
  VM sin pruebas técnicas nuevas y **P8=NO-GO**.

## Ejecución en Prometheus

```sh
cd /home/cicada/Development/GitHub/ardrec
BASE=/ruta/privada/autorizada
REC="$BASE/r43-local-cycle-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 -B scripts/ardrec_p14_r424_evidence_tui.py \
  --r422-result "$BASE/r422-pcap-recibo-validado" \
  --r423-result "$BASE/r423-guest-path-recibo-validado" \
  --run-local-benign --journal-root "$REC" \
  --i-authorize-r43-local-benign --texto
```

Repetir con el mismo `REC` y `--tui` reabre el desarrollo sin repetir A5;
si el usuario no consiente la ejecución local no se suministran flags de
escritura y se usa simplemente `--tui` o `--texto` (preview R42.5 anterior).

## Criterio de aceptación

Preflight pin exacto y sin cambio en base; suite local R43 y regresión P14 PASS;
trazabilidad PASS; recibo R28 íntegro, A5 `RECORDED_LIMITED` con inicio 1;
A6 `ND`, A9 `published_generation=None`, monitor R38 de tres paneles;
CI obligatorio protegido. Ningún estado representa pentesting real ni
acreditación experimental de tesis. Hallazgos AL-06/AL-07 permanecen abiertos.
