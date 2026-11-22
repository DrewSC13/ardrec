# ARDREC R148 — Registro privado de 54 posiciones y análisis emparejado no autoritativo

## Propósito y relación con la tesis

La tesis establece una **comparación emparejada sobre 54 servicios–escenario**, distribuidos en 18 SSH, 18 FTP y 18 SMB/Samba. La estimación estática debe quedar congelada **antes** de las pruebas y de conocer las salidas ARDREC; la referencia debe provenir de una **rúbrica técnica independiente y preferiblemente ciega**. El piloto y las repeticiones técnicas no se cuentan como observaciones independientes. Se conservan las exclusiones documentadas sin reemplazarlas, así como las diferencias cero.

R148 materializa el instrumento digital previo a esas observaciones. Reutiliza `r125_integrated_acceptance.coverage` y exige el catálogo original P7 con SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`. Construye las **54 posiciones vacías**, no identidades de escenarios, resultados, intentos, evidencias ni autorizaciones. P7 continúa `DRAFT_NOT_FROZEN`, P8 `NO-GO`, A6 `ND`, A9 `NOT_PUBLISHED`.

La entrega no cambia la formulación del capítulo III ni introduce hipótesis nuevas. Instrumenta el análisis definido en el capítulo I: error absoluto respecto del criterio independiente y contraste unilateral con Wilcoxon de rangos con signo para pares.

## Capacidades efectivas

- Registro canónico privado `protocol.json` y `observations.json`, con sellos SHA-256, archivos `0600`, carpeta `0700`, lectura con `O_NOFOLLOW`, rechazo de hardlinks, permisos no privados, esquemas inconsistentes y deriva del catálogo.
- Identidades de posiciones `SSH-01..18`, `FTP-01..18`, `SMB-01..18` sin inventar `case_id`, `scenario_id` ni `family_id`.
- Verificación estructural de unicidad de casos y escenarios, pertenencia de cada familia al protocolo, campos y referencias de evidencia y exclusiones justificadas. Ningún hash aportado por un usuario se trata como firma.
- Cálculo con `Decimal` y rangos medios para empates; distribución exacta por *sign-flip* condicional a las magnitudes no nulas, sin aproximación normal para tamaños pequeños. Dirección: `error absoluto estático > error absoluto ARDREC`. Los pares con diferencia 0 permanecen en los recuentos pero no reciben rango Wilcoxon; esta convención se registra **antes** de ver datos definitivos.
- Resumen descriptivo de los tres protocolos. No interpreta grupos como contrastes inferenciales adicionales.
- Etiquetado obligatorio de cualquier análisis de datos proporcionados como `EXPLORATORY_UNVERIFIED_NOT_THESIS_RESULT`. **No existe ruta de promoción a A6, A9, P7 o P8.**

## Estado y límites de evidencia

`RECORDED_UNVERIFIED` es un dato **declarado**, no una observación física acreditada. Requiere referencias SHA-256 estructurales (congelamiento estático, recibo físico, A9, evidencia común y rúbrica independiente), pero la comprobación criptográfica de autores, procedencia física, vigencia y secuencia temporal debe realizarse fuera de este módulo por las autoridades y verificadores correspondientes. `EXCLUDED_UNVERIFIED` requiere motivo y referencia de decisión; no elimina la posición de la muestra.

El registro inicia con `common_scale=null`, sin inventar rango numérico. La escala y la rúbrica deben decidirse y congelarse **antes** de ingresar resultados. El cálculo acepta solo valores decimales expresados como cadenas para evitar redondeos binarios silenciosos. Los metadatos editados manualmente no constituyen registro inmutable ni verificación temporal; el sellado SHA-256 solo detecta cambios accidentales/no concordantes, no autentica a un autor. Para el conjunto definitivo se exigirá cadena de custodia, respaldo y firmas externas comprobadas antes de considerar una medición admitida.

## Uso en Zsh desde el repositorio principal

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B \
  scripts/ardrec_p14_r148_experiment_register.py --prepare \
  --folder /home/cicada/ardrec-lab/r148-paired-study-v1 | more

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B \
  scripts/ardrec_p14_r148_experiment_register.py --audit \
  --folder /home/cicada/ardrec-lab/r148-paired-study-v1 | more

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B \
  scripts/ardrec_p14_r148_experiment_register.py --analysis \
  --folder /home/cicada/ardrec-lab/r148-paired-study-v1 | more
```

`--prepare` exige una carpeta nueva, no sobreescribe; `--audit` comprueba estructura privada; `--analysis` es puramente analítico y **no acredita evidencia experimental**. Todos los comandos retornan al prompt. No usan `sudo`, redes, arranques, edición de nft, publicación ni permisos de root.

## Siguiente hito práctico

1. Autorización y bootstrap independiente del ejecutor B4/B9 R146, aún pendiente.
2. Piloto FTP-T01 autorizado, restauración DENY física y A6/A9 con recibos; luego calibrar/congelar P7 y la rúbrica I4 (sin usar el piloto como parte de las 54 unidades).
3. Selección y congelamiento de los 54 servicios–escenario técnicamente distinguibles y estimaciones estáticas antes de cualquier evidencia técnica de cada unidad.
4. Aplicar los verificadores independientes y registrar resultados dentro del mismo protocolo, sin afirmar observaciones reales por simples SHA-256.
5. Analizar exclusivamente los pares válidos, informar faltantes, exclusiones, empates, ceros, magnitud de efecto y límites de inferencia. El reporte R148 sirve como herramienta computacional exploratoria, no como sustituto del contraste confirmatorio auditado.

CI prueba el núcleo y el instrumento con 60 casos. La regresión acumulada exigida por el aplicador es 596 pruebas (536 previamente acreditadas + 60 nuevas). La creación del registro privado ocurre **después** del commit firmado y es una operación opcional de un solo intento; no es una condición para aprobar el código.
