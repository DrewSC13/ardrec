# P14-R37 · Entrada documental A6 y vista A6 de la TUI (sin acreditación técnica)

Base: `main` del PR #107 `1af422609ca58232cef597e55c386c8aacfd0a05`.
Fuente académica: tesis entregada `Tesis ARDREC(20261114-203754).pdf`, §3.6.1, algoritmo 6, figuras 3.17–3.20 (páginas impresas 118–121; PDF 133–136).

## Límite del incremento

Incorpora un recibo SSH DEV y soporte externo **por lectura local únicamente**. Contrasta sesión, servicio y caso fijos (`DEV_TUTOR_001` / `SSH_DEV` / `CASE_REFERENCE`), método permitido, bytes SHA-256, fecha de captura vs. fecha `as-of` explícita (máximo 24 h), formato y tamaño acotado. La captura y el `as-of` son **declarados por el operador**, no certificados por el importador. Un documento con firmas o claves desconocidas tampoco adquiere autoridad por su hash.

El valor `observed_claim` se expone como *afirmación no verificada*. `ACCEPTED_FOR_DOCUMENTARY_REVIEW` **no** significa `VALIDADO` ni `VERDADERO` en A6. La clasificación sigue `ND`, `confirmed_rf` y `final_risk` siguen nulos; el estado real, A7, A8, A9 y P8 no se modifican. Los casos de duplicidad y conflicto son guardas de lote ensayadas como función auxiliar, no parte del CLI de recibo único.

El soporte y el recibo del laboratorio deben mantenerse **fuera de Git**, en directorio privado del operador. Las muestras en `lab/p14-r37-a6-defensive-import-v1/` son **completamente sintéticas** y no contienen observación física.

## Demostración sobre el fixture sintético

```bash
cd /home/cicada/Development/GitHub/ardrec
(umask 022; PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r37*.py' -v)
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --preview \
  --import-defensive-receipt lab/p14-r37-a6-defensive-import-v1/synthetic-receipt.json \
  --import-defensive-support lab/p14-r37-a6-defensive-import-v1/synthetic-support.txt \
  --as-of-utc 2026-11-14T20:00:00Z --texto
```

Cambia `--texto` por `--tui` en TTY real; izquierda/derecha (o h/l) hasta A6, q para salir. El mismo recibo/soporte y `as-of` producen el mismo digest de salida. Para una fuente real, mantener los bytes originales, la identidad de VM y configuración, así como las evidencias separadas de autorización y captura; el importador sólo documenta la recepción para revisión. No se ejecutan comandos sobre la VM.

## Pruebas a conservar

Oráculo independiente de bytes SHA-256; entradas válidas e inválidas; claves duplicadas; soporte ausente, modificado o enlazado; identidad ajena; método no permitido; captura futura/antigua; duplicados y contradicción de lote; informe alterado. Ejecutar después el conjunto P14 y verificador de trazabilidad sobre el worktree real. Este paso no acredita conformidad integral de A6, ni completitud de P19/P25/P26.
