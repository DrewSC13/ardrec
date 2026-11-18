# ARDREC R78 — Sensibilidad matemática contrafactual de A7, 25 familias

**Base:** merge R77 `11c26f882164515ee78305eed5adbfe2768c1252`. **Alcance:** exclusivamente analítico, sintético, offline y no operacional. La fuente R75/R76 se verifica íntegra antes de cada operación.

## Problema y propósito

R75 acredita reproducibilidad de software, R76 ofrece 25 intenciones A5 y sus intervalos completos A7 sin admisión técnica, y R77 atribuye documentos a firmas Ed25519 solamente cuando existe registro externo fijado. Aún no se han aportado el pin independiente ni un historial independiente, ni se ha autorizado la observación física F11/P8. Por tanto, las 25 clasificaciones A6 siguen siendo ND y ningún `Rf` confirmado existe.

R78 responde a una cuestión matemática independiente: **¿cómo cambiaría el intervalo A7 de cada familia si, únicamente como hipótesis, la evidencia diferenciable tuviera magnitud exacta 0, 1/2 o 1?** Se ejecuta el núcleo R58-D de fracciones exactas, no una fórmula paralela. En ningún momento se infiere la magnitud a partir del contenido `OBSERVADO_POSITIVO`, `OBSERVADO_NEGATIVO` o `INCONCLUSO` de R76, pues no existe calibración de esa correspondencia. Las tres magnitudes son escenarios **hipotéticos externos a A6**, y los extremos 0 y 1 deben coincidir con el intervalo previamente conservado por R76/R58-E.

## Interfaces y controles

Entrada: `scripts/ardrec_p14_r78_a7_whatif_sensitivity.py`. Recibe el directorio privado y auténtico R75 y el reporte R76 en JSON canónico, propietario actual, permisos 0600 y directorio padre 0700. R77 provee el lector privado `read_canonical`; R76 verifica R75 sin modificarlo; R58-D efectúa el cálculo y su verificación. El resultado está acotado a 25 familias (SSH 8, FTP 8, SMB 9) y tres niveles matemáticos. Cada familia registra intervalo sin resolver, tres escenarios `whatif_E_*_rf`, `A6=ND`, `a7_confirmed_rf=null`, A8 sin transición, A9 sin publicación y P8 NO-GO. El SHA-256 del reporte identifica su contenido, **no autentica observación física**.

```shell
cd /home/cicada/Development/GitHub/ardrec
PYTHONPATH=src python3 -B scripts/ardrec_p14_r78_a7_whatif_sensitivity.py \
  --receipt-dir /home/cicada/ardrec-lab/r75-demo-20261118T035215Z-241956 \
  --r76-report /home/cicada/ardrec-lab/r76-demo-20261118T115635Z-6283/report.json \
  --texto | more
```

Para recibo JSON: `--json > /RUTA_PRIVADA/r78.json` con `umask 077`. Para validación estricta posterior: `--verify-json /RUTA_PRIVADA/r78.json`. **Verificar nunca reinvoca A5 ni inicia procesos de guest**, simplemente recalcula matemáticamente a partir de las entradas inmutables. No hay entrada arbitraria para configurar credenciales, herramientas de red, VM ni comandos de host.

## Pruebas y criterios

`lab/tests/test_p14_r78_a7_whatif_sensitivity.py`: diecisiete casos que comprueban identidad de las 25 familias, monotonía y fronteras exactas, repetición determinista, CLI real, ausencia de ejecución, rechazos de reportes rehasheados con `GO` o `Rf` falso, modificación de GEN1/R75, alteración de R76 y permisos inseguros. Se conserva CI histórica.

## Interpretación académica

R78 es demostración de **sensibilidad de la función matemática A7**, no validación experimental. La coincidencia de extremos confirma autoconsistencia del cálculo y del modelo de incertidumbre; **no** demuestra que los valores 0, 1/2 o 1 se observaron en SSH/FTP/SMB. Está prohibido comunicar `whatif_E_half_rf` como `Rf` confirmado, estado físico o mejora experimental. Para avanzar a la acreditación real hacen falta campaña autorizada, contención F11, testigos independientes, resultados con soporte, calibración de reglas del catálogo P7 y protocolo de transición. P8 permanece NO-GO.
