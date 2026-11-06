# Punto 6 — Separación de escenarios / Step 6 — Scenario separation

## Español

**Alcance:** diseño y comprobaciones *documentales* de separación de los conjuntos
`dev`, `pilot` y `exp`; no crea redes, VM, muestras experimentales, credenciales
ni directorios privados. La fuente de la tesis es el PDF con SHA-256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
secciones 1.9.3, 1.9.4, 3.2.1 y 3.3.1, entre otras.

El concepto de **unidad experimental** es el servicio–escenario con estado inicial,
versión, configuración, exposición, autenticación, controles y contexto documentados.
La **instancia de servicio** es la instalación/ejecución concreta del servicio Linux.
Un **escenario** registra una caracterización evaluable de esa instancia.
Una **familia operacional** pertenece al catálogo de 25 clases de comprobación de
la tesis: SSH-T01…T08, FTP-T01…T08 y SMB-T01…T09; no es una unidad experimental.
Un **caso derivado** vincula familia y escenario; una **ejecución** pertenece a un
escenario; un **intento** se vincula a una ejecución y caso; un **artefacto** (salida,
soporte o registro) debe conservar etapa, ejecución, intento cuando corresponda,
procedencia y contenido. Solo una unidad de `exp` elegible y posteriormente congelada
podrá integrar el conjunto inferencial, sin que los intentos aumenten `n`.

**Reglas de custodia lógica:** identidades con espacio de nombres `dev-*`, `pilot-*`
y `exp-*`; manifiestos distintos; referencias internas a la etapa; rutas privadas
separadas para configuraciones, inventarios, referencias de credenciales, recursos
mutables, logs, evidencia y resultados. No se almacenan credenciales en Git.
Los registros arrastran `prior_use` y `origin_scenario_ids`; un uso anterior no se
borra cambiando la etiqueta. La huella técnica del escenario es SHA-256 del JSON
canónico `{'protocol': p, 'profile': perfil}` (UTF-8, claves ordenadas, sin espacios,
`ensure_ascii=False`). Si una huella experimental coincide con la de desarrollo o
piloto, se rechaza como posible duplicación de la misma condición técnica. También
se rechaza contenido idéntico de logs/evidencia/resultados entre esos conjuntos.
Estas barreras son **conservadoras**; una coincidencia legítima exige análisis y
trazabilidad, nunca una excepción automática en el validador.

La reutilización de una base genérica de SO/herramientas es admisible **solo** con
huella, procedencia y acreditación de que no incluye observaciones anteriores.
No equivale a reutilizar snapshots con depuración, instrumentación activa, datos de
pilotaje, claves, bitácoras o resultados. Sus manifestaciones concretas deberán
verificarse fuera de Git antes de activación y no se han creado aquí.

La topología reserva 9 segmentos `/28` — desarrollo: `10.203.30/31/32.0/28`;
piloto: `10.203.40/41/42.0/28`; experimento: `10.203.50/51/52.0/28` —
con **un solo conjunto activo** por presupuesto. La reserva no acredita despliegue,
conectividad, aislamiento o autorización. El registro público de servicios y el
registro de restauración del punto 5 corresponden únicamente a `dev` y permanecen
históricamente inalterados.

### Criterios de cierre del incremento documental

1. Las tres etapas están registradas con propósito, espacio de nombres y recursos
   privados distintos, referidos a las nueve reservas reales de topología.
2. No se confunden escenario, instancia, familia, caso, ejecución, intento,
   soporte/artefacto ni unidad experimental.
3. El validador rechaza identidades y referencias de otra etapa, rutas transversales,
   uso anterior incompatible, repetición como unidad, mezcla de intentos y copias de
   resultados entre piloto/desarrollo y experimento.
4. Las pruebas incluyen al menos mutaciones adversariales de los casos anteriores.
5. Los registros históricos conservan sus límites; AL-06, AL-07 y siete obligaciones
   residuales no se cierran por documentación.
6. Los verificadores y pruebas se ejecutan localmente y se integran a CI **solo tras
   aplicar el incremento**; el punto no se declara integrado antes del PR/CI de main.

Comprobación documental: `python3 lab/verify_scenario_separation.py`.
Pruebas: `python3 -m unittest discover -s lab/tests -p test_scenario_separation.py -v`.

**Pendiente:** despliegue, comprobación física independiente de aislamiento,
identificación de escenarios reales, catálogo operacional (punto 7), pilotaje,
selección/congelamiento de 54 unidades, instrumentos, aceptación funcional y
validación de hipótesis. No publicar artefactos o evidencias privadas.

## English

P6 provides **document-only** separation of development, pilot and experiment
namespaces, manifest references, technical identities and data-custody categories.
It does not deploy VMs or networks, grant authorization, freeze the 54 experimental
service–scenario units or validate the research hypothesis. Cross-stage references,
prior-use laundering and attempted reuse of experimental evidence are rejected.
Only documented generic OS/tool bases without prior observations may be shared.
All historical evidence remains at its original scope; real isolation and the
operational executor are pending separately.
