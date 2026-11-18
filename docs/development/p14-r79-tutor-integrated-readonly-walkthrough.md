# ARDREC R79 — Recorrido académico único A1–A10 y 25 familias

**Estado:** software DEV sintético de solo lectura, no ensayo experimental ni autorización P8.

## Finalidad

R79 facilita la exposición ante el tutor mediante una vista trazable de las diez etapas A1–A10, cruzando tres fuentes existentes y previamente autenticadas: (i) R75 GEN1, recuperación y monitor R38; (ii) R76 recepción sintética de 25 intenciones tipadas A5 y tres declaraciones sin validar; y (iii) R78 intervalos A7 exactos y escenarios E=0, E=1/2, E=1 para 25 familias.

**Separación de poblaciones:** las 54 unidades A2 son un escenario sintético distinto de las 25 familias A5–A7 y de la sesión durable de tres servicios. Nunca se presentan como observaciones experimentales.

## Contrato de ejecución

`scripts/ardrec_p14_r79_tutor_walkthrough.py` ofrece `--json`, `--texto` y `--verify-json`, siempre con `--receipt-dir`, `--r76-report` y `--r78-report`. Opera como usuario no root desde el repositorio canónico, verifica los recibos con los verificadores R75, R76 y R78 y conserva sus hashes y vínculos originales. Los archivos de entrada JSON deben ser canónicos, privados y sin enlaces inseguros, siguiendo el lector R77.

No despacha comandos ni genera nuevas ejecuciones A5, evidencias, generaciones A9 o transiciones A8. `--verify-json` reconstruye y compara el documento íntegro a partir de las fuentes, no solo de su SHA local; no crea archivos ni invoca subprocesos. El modo `--texto` muestra diez etapas y las 25 familias en la terminal, con fracciones exactas y etiquetas explícitas de hipótesis.

La recepción documental con firmas Ed25519 de R77 permanece como capacidad de atribución y validación de procedencia de documentos **sin pin externo acreditado** en esta demostración. Firmas y hashes no acreditan el comportamiento real de los servicios.

## Límites para el tribunal y tutor

- **A1–A2:** estado DEV, tres servicios y 54 unidades *sintéticas*; GEN1 estructural.
- **A3–A5:** selección hipotética y un único proceso benigno local; cero inicios físicos acreditados.
- **A6:** `ND` en 25 familias; sin validación de soportes observacionales independientes.
- **A7:** 25 intervalos matemáticos; E=0/1/2/1 son escenarios contrafactuales, no mediciones; `Rf` confirmado nulo.
- **A8:** sin transiciones aplicadas en el puente de familias.
- **A9:** sin generación adicional; R75 conserva GEN1 estructural.
- **A10:** monitor R38 original, diez etapas, tres paneles, solo lectura.
- **P8:** `NO-GO`. F11 y ensayos con VM siguen sin autorización física; aceptación funcional del sistema `PENDING`, validación experimental `NOT_RUN`.

## Uso desde Prometheus

```shell
cd /home/cicada/Development/GitHub/ardrec
PYTHONPATH=src python3 -B scripts/ardrec_p14_r79_tutor_walkthrough.py --receipt-dir /home/cicada/ardrec-lab/r75-demo-20261118T035215Z-241956 --r76-report /home/cicada/ardrec-lab/r76-demo-20261118T115635Z-6283/report.json --r78-report /home/cicada/ardrec-lab/r78-demo-eTecV3I2/report.json --texto | more
```

Una salida en texto o JSON es un instrumento de presentación reproducible; no un certificado independiente. El manifiesto SHA-256 detecta cambios locales sin establecer una cadena de custodia externa.
