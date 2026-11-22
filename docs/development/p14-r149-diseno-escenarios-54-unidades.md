# ARDREC R149 — Diseño reproducible de 54 servicios–escenario (borrador, sin ejecución)

## Alcance

R149 transforma las 54 **posiciones** privadas ya preparadas por R148 en un **instrumento de selección**, todavía sin identidades reales, sin resultados y sin autorizar pruebas. Los 54 registros son 18 SSH, 18 FTP y 18 SMB. El catálogo de 25 familias mantiene su SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`, sus precondiciones, soportes y operaciones acotadas, incluidos los controles contra enumeraciones ilimitadas, fuerza bruta y acciones destructivas.

La columna `candidate_family` es **una sugerencia de distribución para cubrir las 25 familias**. No es una selección real, ni una exigencia de representación estadística, ni una afirmación de que los 54 escenarios técnicamente distinguibles existen. Los casos definitivos han de seleccionarse conforme a la factibilidad, el alcance firmado, el piloto y P7. R149 jamás agrega escenarios falsos al registro R148.

## Cuatro artefactos de una carpeta privada

* `plan.json`: plan estructural canónico con SHA-256 del catálogo, protocolo y registro R148, proporción 18/18/18 y estado P7 borrador.
* `family-checklist.json`: extracto exacto de las 25 familias, incluyendo condición, acción mínima, precondiciones, soportes, parámetros y limpieza.
* `family-proposal.csv`: propuesta original de familias, inmutable por contrato de R149; no atribuye identidad a ninguna unidad.
* `selection-working.csv`: copia **editable** por un operador autorizado. Los 54 campos `chosen_family`, `case_id`, `scenario_id`, `service_instance_id`, `variation_reason`, referencias SHA-256 y estimación estática comienzan vacíos.

La selección solo será estructuralmente completa cuando las 54 posiciones tengan identificador único de caso, escenario único, servicio/instancia, familia compatible, condición diferenciadora, autorización de alcance referida, decisión de preregistro referida, estimación estática y respaldo referido. Los valores de referencia aún **no están autenticados**. Las dos identidades (`case_id`, `scenario_id`) deben ser únicas en toda la selección; una instancia de servicio puede repetirse si las condiciones de escenario son genuinamente distintas.

Las familias de cada protocolo se proponen de manera cíclica sobre las 18 posiciones: 8 SSH, 8 FTP, 9 SMB. Esto produce una distribución inicial de cobertura (todas las 25 familias), **no casos ni resultados**. El investigador puede cambiar `chosen_family` sin modificar `candidate_family`, siempre respetando el protocolo y justificando el escenario.

## Controles y reproducibilidad

La carpeta debe ser `0700`, los cuatro archivos `0600` del mismo propietario, con rechazo de enlaces simbólicos y archivos con varios hardlinks. La creación exige destino inexistente; la auditoría no escribe nada. La propuesta original y los dos archivos JSON se verifican contra la reconstrucción a partir del catálogo fijado y los documentos R148; únicamente el CSV de trabajo puede editarse. La validación detecta identificadores duplicados, campos inesperados, CSV truncado, cruces entre protocolos, fórmulas de hoja de cálculo, referencias SHA-256 malformadas y estimaciones no decimales.

La salida `CANDIDATE_COMPLETE_UNVERIFIED` quiere decir **completitud estructural declarada**; no implica consentimiento, autenticidad de soportes, P7 congelado, piloto, A6, A9 o aprobación P8. Mantener A6=`ND`, A9=`NOT_PUBLISHED`, P8=`NO-GO`, P7=`DRAFT_NOT_FROZEN`, observaciones físicas confirmadas=`0`.

## Uso desde el repositorio, Zsh

Después de integrar R149 en una rama limpia y firmada:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B \
  scripts/ardrec_p14_r149_scenario_design.py --prepare \
  --folder /home/cicada/ardrec-lab/r149-scenario-design-v1 | more

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B \
  scripts/ardrec_p14_r149_scenario_design.py --audit \
  --folder /home/cicada/ardrec-lab/r149-scenario-design-v1 | more
```

`--prepare` no se debe ejecutar dos veces: si la carpeta ya existe, usar `--audit`. Los archivos editados deben conservar modo `0600`; por ejemplo, ajustar manualmente los permisos del CSV de trabajo si la herramienta de edición cambia el modo, antes de volver a auditar.

## Secuencia operacional y científica

1. Revisar la sugerencia de familias y la checklist contra los servicios reales disponibles. No confundir propuesta con muestra congelada.
2. Tras el piloto físico autorizado y calibración P7, registrar únicamente casos realmente distinguibles y alcanzables en `selection-working.csv` antes de pruebas definitivas.
3. Obtener la rúbrica independiente y congelamiento estático verificable **antes** de observar resultados ARDREC, sin retroajustar estimaciones.
4. Después de arrancar con permisos externos válidos y restauración DENY verificable, asociar recibos reales y resultados a las 54 posiciones R148, preservando exclusiones y errores.
5. Ejecutar la comparación emparejada R148 únicamente con pares acreditados por la cadena de custodia. R149 no tiene una ruta para elevar un dato a observación física confirmada.

Este componente no instala root, no arranca máquinas, no provoca tráfico y no altera `main`.
