# R70 — Primera generación analítica DEV segura (17–18 noviembre de 2026)

## Objetivo operacional acotado

Conservar la semántica de la sesión R69 y el monitor R38/R69.1, añadir una generación
analítica estructural verdadera `1` que sea publicable por `DurableStore.publish_analytical`,
recuperable por replay y visible por `python -m ardrec --tui`. **No** autoriza
pentesting, prueba de laboratorio, operación del ejecutor ni cálculo de riesgo final.

## Recorrido reproducible

- **A1**: reproduce el R68 de los tres servicios **desde la misma configuración**
  y el estado confirmado original (GEN0); no reevalúa con contexto GEN1.
- **A2**: preserva la configuración congelada y la generación 0.
- **A3**: no hay autorización de despacho para este escenario DEV; la guarda
  física permanece bloqueada. No se declara una verificación del laboratorio.
- **A4**: conjunto elegible de la ruta de despacho vacío, selección `None`.
- **A5**: ninguna reserva, aceptación, ejecución ni inicio; 0 intentos.
- **A6**: no se adquiere soporte técnico; clasificación ND.
- **A7**: análisis ND para las magnitudes derivadas (motivo `NO_EVIDENCE`),
  prioridad ND por `NO_ELIGIBLE`, R0 y criticidad congeladas.
- **A8**: transición operacional **real** `DETENER` (`T10`) **solo del contexto DEV**,
  bajo guarda de control sintético explícita (`cause_verified`/`effect_processable`
  locales). No implica fallo real o ausencia de autorización de una VM.
- **A9**: materializa `AnalyticalArchive` con tres proyecciones y los 21 objetos
  referenciados; publica atomicamente HEAD por `publish_analytical`, con validación
  **estructural** (`structural_only`, sin `execution_counters_v1`).
- **A10**: vuelve a abrir `DurableStore`, recupera la instantánea anclada y
  presenta su contenido mediante el **mismo** monitor `dashboard_tui.py` R38.

## Entrada

`PYTHONPATH=src python3 -B -m ardrec --durable-dev-root <privado> --safe-cycle --tui`

El ejecutor Prometheus usa un root DEV dedicado `r70-safe-tutor-001`. **No
modifica ni termina** la sesión histórica `r69-dev-tutor-001`; así se preserva
su generación 0 para el siguiente recorrido positivo del laboratorio.

- `--safe-cycle` es el único modo que permite **crear** la generación 1 y solo
  después de verificar el recibo R69. No realiza tráfico, subprocesos, ni VM.
- `--durable-dev-root <privado> --tui` vuelve a abrir GEN0 o GEN1 sin publicar.
- `--json` permite comparar hashes y resultados con las pruebas.
- Dos invocaciones `--safe-cycle` sobre el mismo estado dejan exactamente
  el mismo HEAD, diario, archivo y documento.

## Restricciones y aceptación

- `P8=NO-GO`, `physical_observation_attested=false`, `A5=0`, `Rf=ND`.
- Conservar el recibo `a1-generation-0.json` byte a byte.
- Ni `--tui` ni `--json` ni la recuperación ejecutan acciones técnicas.
- Rechazar alteración de origen, configuración, estado, archivo, HEAD original, hash anclado,
  generaciones no soportadas o parada distinta a la política DEV.
- El contrato **no** cierra el ciclo físico A3–A7, las 25 familias, F11,
  ni el experimento de 54 observaciones. La ruta positiva controlada
  requiere otra entrega y evidencias del anfitrión.

## Trazabilidad

Origen `R69` (PR #164, SHA `08415a83`), TUI `R69.1` (PR #165,
SHA `31206b7cef258d17e4e0042736de5e9499ad4c75`). Los hashes de
snapshot y HEAD son resultado de cada sesión; no son identificadores de
confianza externa. CI y Prometheus deben repetir las pruebas y confirmar
hashes antes de llamar integrado a R70.
