# Vista vigente / Current view

Español: la [revisión del punto 1](../traceability/point-1-closure-v1.md) y la [cobertura v2](current-coverage-v2.json) registran el estado vigente de los componentes. El contenido siguiente conserva la matriz histórica; sus estados no son resultados actuales del sistema.

English: the [point 1 review](../traceability/point-1-closure-v1.md) and [v2 coverage](current-coverage-v2.json) record current component status. The following content preserves the historical matrix; its statuses are not current system results.

# Criterios de aceptación del sistema

Fuente: TESIS ARDREC. Las referencias usan secciones y la huella del documento
consultado; no dependen de su nombre de archivo ni de una paginación anterior.
Esta matriz deriva criterios verificables de la especificación. AC, INV y TF/TE
son identificadores de ingeniería del repositorio, no numeraciones de la tesis.
INV-01 a INV-07 corresponden a los grupos de la tabla 3.13; los demás desarrollan
restricciones transversales. Los escenarios son pruebas propuestas, no ejecutadas.

## Tres evaluaciones independientes

| Evaluación | Condición de aceptación | Evidencia exigida |
| --- | --- | --- |
| Implementación | Contratos y comportamiento completos dentro del alcance declarado. | Archivos, revisión y commit identificados; compilar no basta. |
| Verificación funcional | Los resultados cumplen requisitos e invariantes, incluidos rechazos, límites y fallos. | Pruebas ejecutables, oráculos independientes, resultados y entorno vinculados al commit. |
| Validación experimental | Se aplica el protocolo congelado a observaciones reales y evaluables. | Datos, referencia externa, exclusiones, análisis y conclusiones reproducibles. |

IMPLEMENTED no implica VERIFIED. VERIFIED no implica VALIDATED. La validación
experimental completada no exige que la hipótesis resulte favorable. Una simulación
puede verificar código, pero no sustituye observaciones del laboratorio.

## Estados y reglas de cierre

- Implementación: NOT_IMPLEMENTED, PARTIAL, IMPLEMENTED.
- Verificación funcional: NOT_RUN, PARTIAL, PASS, FAIL.
- Validación experimental: NOT_APPLICABLE, NOT_RUN, COMPLETE, INCOMPLETE.
- Aceptación de cada criterio: PENDING o ACCEPTED. COMPLETE describe cumplimiento
  del protocolo, no superioridad del modelo. NOT_APPLICABLE debe justificarse.
- Todo avance requiere evidencia con commit, comando o procedimiento, entorno,
  resultado observado, resultado esperado, artefactos y huellas. Los fallos y las
  exclusiones se conservan; no se convierten en casos aprobados.
- Las condiciones funcionales se aceptan con implementación completa y pruebas
  pertinentes aprobadas. Las experimentales requieren además protocolo ejecutado,
  datos elegibles y análisis revisado. No se exigen resultados estadísticos favorables.
- La cobertura de filas y enlaces verifica esta matriz, no el funcionamiento del sistema.
  Cada escenario se desglosará en casos ejecutables y casos de referencia independientes
  antes de aceptar su criterio. No se usan porcentajes sin un denominador definido.

## Punto de partida y alcance

El estado inicial se fija en el commit indicado en system-v1.json. Los reportes
previos registran 34 pruebas Python y 7 pruebas Rust, además del intercambio Unix.
Las comprobaciones existentes se citan solo como soporte parcial: no prueban todavía
validación Rust de todos los mensajes, deduplicación durable, algoritmos A1-A10,
recuperación integral ni resultados experimentales. Esta etapa no vuelve a ejecutar
esas pruebas ni cambia sus resultados históricos.

Los límites actuales de contratos y transporte son decisiones de implementación;
su suficiencia para perfiles completos deberá verificarse. Los módulos asociados
incluyen destinos futuros: una carpeta existente no prueba implementación.
En criterios experimentales, A10 identifica la procedencia de las salidas evaluadas,
no un algoritmo de análisis estadístico.

Antes de experimentar se concretarán y congelarán elegibilidad, exclusiones,
tratamiento de datos faltantes y empates, referencia externa, pilotaje y sensibilidad.
El diseño prevé 54 unidades, 18 por protocolo; las pérdidas se informan sin completar
artificialmente la muestra. Rref no entra en selección, clasificación ni recalibración.
La formalización matemática se conserva; discrepancias de fuente, ejemplos u oráculos
deben resolverse explícitamente antes de implementar el criterio afectado.

La finalización técnica exige cerrar los criterios funcionales aplicables y repetir
la instalación y reproducción desde un entorno limpio. La finalización académica
añade los criterios experimentales y el informe de resultados, incluso si son negativos.
Se mantienen commits y documentación bilingües, español primero; comentarios de código
breves solo en español. Se avisará antes de iniciar A1 y antes del flujo operativo.

## Invariantes

- **INV-01**: Origen coherente: evento, decisión, contexto y generación corresponden.
- **INV-02**: Configuración y caracterización congeladas durante la observación.
- **INV-03**: No se amplía el conjunto de unidades, casos ni acciones autorizadas.
- **INV-04**: Historia, evidencia y revisiones previas se conservan.
- **INV-05**: Solo transiciones permitidas; estados terminales no se reabren.
- **INV-06**: Prioridades y candidatos corresponden al mismo estado.
- **INV-07**: Identidades, referencias, procedencia e integridad se conservan.
- **INV-08**: Racionales exactos y dominios válidos; ND nunca se convierte en cero.
- **INV-09**: Presupuesto acotado; cada inicio acreditado se contabiliza una vez.
- **INV-10**: Una acción sin conciliar bloquea nuevos despachos.
- **INV-11**: Decisiones deterministas; Rref queda fuera de la selección y recalibración.
- **INV-12**: La convergencia usa historia computable y respeta reinicios.
- **INV-13**: Solo una generación íntegra y duraderamente publicada tiene autoridad.
- **INV-14**: La invocación progresa con recursos acotados o finaliza explícitamente.
- **INV-15**: Simulación, verificación funcional y observaciones experimentales se separan.

## Criterios

### AC-01

Python decide; Rust ejecuta; el transporte no admite evidencia ni confirma estados. Los permisos impiden escrituras ajenas.

- TESIS ARDREC: 3.9.1.
- Módulos: `src/ardrec/coordination`, `crates/ardrec-executor`, `src/ardrec/persistence`.
- Algoritmos: A10.
- Invariantes: INV-01, INV-07.
- TF-01 (planificada): Intentar ejecutar desde la capa analítica y publicar desde el ejecutor; ambos accesos se rechazan.
- Estados: implementation=PARTIAL; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-02

Racionales reducidos, denominador positivo, tipos exactos y ND explícito conservan su significado entre Python y Rust.

- TESIS ARDREC: 3.2.9, 3.9.4.
- Módulos: `src/ardrec/contracts`, `src/ardrec/messages.py`.
- Algoritmos: A1, A2, A7.
- Invariantes: INV-08.
- TF-02 (planificada): Probar cero canónico, límites, booleanos, decimales, fracciones no reducidas y equivalencia entre lenguajes.
- Estados: implementation=PARTIAL; functional_verification=PARTIAL; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: tests/unit/test_contracts.py.

### AC-03

Las tramas Unix respetan longitud, UTF-8, límites, lecturas parciales y permisos; un canal defectuoso no provoca otro despacho.

- TESIS ARDREC: 3.9.3, 3.9.4.
- Módulos: `src/ardrec/transport.py`, `crates/ardrec-executor`.
- Algoritmos: A5.
- Invariantes: INV-07, INV-10.
- TF-03 (planificada): Fragmentar cabeceras y cuerpos, truncar, exceder límites, denegar acceso al socket y perder la conexión.
- Estados: implementation=PARTIAL; functional_verification=PARTIAL; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: tests/unit/test_transport.py, crates/ardrec-executor/src/transport.rs, scripts/verificar_transporte.py.

### AC-04

Todos los mensajes declarados tienen perfiles de éxito, rechazo e incertidumbre aplicables; identidades, versiones y referencias se verifican también semánticamente.

- TESIS ARDREC: 3.9.3, 3.9.5, 3.9.6, 3.9.7, 3.9.8, 3.9.9, 3.9.10, 3.9.11.
- Módulos: `src/ardrec/messages.py`, `crates/ardrec-executor`.
- Algoritmos: A5, A6, A9, A10.
- Invariantes: INV-01, INV-07.
- TF-04 (planificada): Cubrir descubrimiento, ejecución, consulta/respuesta, supervisión, rechazo, estado persistido y cierre; alterar identidad, versión, referencia y productor.
- Estados: implementation=PARTIAL; functional_verification=PARTIAL; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: tests/unit/test_messages.py.

### AC-05

Un mensaje idéntico recupera su respuesta durable; un duplicado distinto produce conflicto; cambiar message_id no permite reutilizar attempt_id.

- TESIS ARDREC: 3.9.3, 3.10.2.
- Módulos: `src/ardrec/messages.py`, `src/ardrec/attempts`, `src/ardrec/persistence`.
- Algoritmos: A5, A9.
- Invariantes: INV-01, INV-07, INV-09.
- TF-05 (planificada): Repetir mensajes antes y después de reiniciar; cambiar contenido o contexto; comprobar cero ejecuciones adicionales.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-06

La evaluación tipada es determinista; solo VERDADERO habilita acciones; ND no equivale a FALSO ni a cero.

- TESIS ARDREC: 3.3.2, 3.6.
- Módulos: `src/ardrec/rules`.
- Algoritmos: A1.
- Invariantes: INV-08, INV-11.
- TF-06 (planificada): Tablas completas de operadores y decisiones, campos ausentes, tipos inválidos, reglas ambiguas y orden de entrada permutado.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-07

La configuración válida se congela; identidades son únicas; se verifican referencias, pesos, dependencias y límites. Et inicia en cero, Rf en R0, Q en PREPARADO e historia de transiciones vacía.

- TESIS ARDREC: 3.2.1, 3.2.2, 3.2.3, 3.6.
- Módulos: `src/ardrec/initialization`.
- Algoritmos: A2.
- Invariantes: INV-02, INV-03, INV-08.
- TF-07 (planificada): Configuración válida y variantes con duplicados, ciclos no permitidos, pesos inválidos, referencias ausentes y cambio posterior de configuración.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-08

Los controles respetan origen, autorización, precedencia y consumo único. Los planes potenciales son finitos y operan sobre copias sin crear evidencia real.

- TESIS ARDREC: 3.3.3, 3.4.1, 3.6, 3.9.9.
- Módulos: `src/ardrec/controls`.
- Algoritmos: A3.
- Invariantes: INV-02, INV-03, INV-09, INV-11.
- TF-08 (planificada): Guardas VERDADERO/FALSO/ND, dependencias, control consumido, planes cíclicos y comprobación de que la simulación no altera el estado original.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-09

Solo se seleccionan candidatos autorizados del servicio PENDIENTE y con presupuesto; se minimiza la clave (-PA, precedencia, id_servicio, id_caso).

- TESIS ARDREC: 3.4.1, 3.4.2, 3.4.3, 3.6.
- Módulos: `src/ardrec/selection`.
- Algoritmos: A4.
- Invariantes: INV-03, INV-06, INV-11.
- TF-09 (planificada): Enumerar candidatos como oráculo independiente; probar empates, entrada permutada, prioridad alta no autorizada y conjunto vacío.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-10

La intención y la decisión son durables; aceptación no acredita inicio. El contador aumenta una vez al incorporar inicio verificado; no inicio verificable no consume ejecución.

- TESIS ARDREC: 3.4.4, 3.6, 3.9.2.
- Módulos: `src/ardrec/attempts`, `src/ardrec/persistence`, `crates/ardrec-executor`.
- Algoritmos: A5.
- Invariantes: INV-07, INV-09, INV-10.
- TF-10 (planificada): Aceptar sin iniciar, acreditar inicio, repetir el evento y restaurar sesiones; comprobar reserva, contador y límite de una o dos ejecuciones autorizadas.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-11

Solo existe una acción técnica pendiente de conciliación; inicio, terminación o limpieza inciertos bloquean nuevos despachos y no causan reejecución automática.

- TESIS ARDREC: 3.5.5, 3.9.2, 3.9.3.
- Módulos: `src/ardrec/attempts`, `crates/ardrec-executor`, `src/ardrec/coordination`.
- Algoritmos: A5, A10.
- Invariantes: INV-09, INV-10.
- TF-11 (planificada): Perder respuesta antes/después del inicio, exceder esperas y fallar limpieza; consultar la identidad original y agotar conciliación sin fabricar confirmación.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-12

El ejecutor aplica perfiles congelados, argumentos separados sin shell, alcance y límites. Conserva soportes y limpia únicamente artefactos previstos; código cero no acredita evidencia.

- TESIS ARDREC: 3.7, 3.9.2.
- Módulos: `crates/ardrec-executor`, `lab`.
- Algoritmos: A3, A5.
- Invariantes: INV-03, INV-07, INV-10.
- TF-12 (planificada): Destinos/argumentos no autorizados, timeout, salida truncada, hijos activos y limpieza fallida; verificar conservación de archivos ajenos y referencias protegidas.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-13

Cada condición se clasifica por soportes, procedencia, parámetros y reglas; se distinguen POSITIVO_VALIDO, NEGATIVO_VALIDO, INCONCLUSO, INCIDENCIA, INVALIDO y NO_ADMITIDO.

- TESIS ARDREC: 3.3.4, 3.6, 3.9.8.
- Módulos: `src/ardrec/evidence`.
- Algoritmos: A6.
- Invariantes: INV-04, INV-07, INV-08.
- TF-13 (planificada): Casos de cada clasificación, soportes alterados o faltantes, salida cero sin prueba y varias condiciones en un intento.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-14

Una condición conserva clave, revisiones y soportes; duplicados no inflan evidencia. Las contradicciones bloquean conclusiones dependientes y solo resoluciones verificadas cambian vigencia.

- TESIS ARDREC: 3.2.5, 3.3.4, 3.6, 3.9.9.
- Módulos: `src/ardrec/evidence`, `src/ardrec/persistence`.
- Algoritmos: A6.
- Invariantes: INV-04, INV-07.
- TF-14 (planificada): Duplicar soportes, contradecir perfiles y retirar el máximo; probar resolución autorizada, no autorizada e indicadores de aceptación sin respaldo.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-15

Normalizaciones, criticidad y contribuciones reproducen las ecuaciones; Et es el máximo vigente, no una suma. Sustituciones negativas autorizadas no alteran R0 ni anulan positivos vigentes.

- TESIS ARDREC: 3.2.2, 3.2.3, 3.2.4, 3.2.5, 3.2.7.
- Módulos: `src/ardrec/analytics`, `src/ardrec/contracts`.
- Algoritmos: A2, A7.
- Invariantes: INV-02, INV-04, INV-08.
- TF-15 (planificada): Oráculos racionales independientes, extremos ordinales, evidencia vacía/negativa/positiva, retiro de vigencia y sustituciones incompatibles.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-16

Prioridad y riesgo se calculan con sus fórmulas respectivas; ajustes simultáneos cumplen R0- <= D <= Rf <= U <= 1. No hay redondeo interno ni uso de Rref.

- TESIS ARDREC: 3.2.6, 3.2.8, 3.2.9, 3.6.
- Módulos: `src/ardrec/analytics`.
- Algoritmos: A7.
- Invariantes: INV-06, INV-08, INV-11.
- TF-16 (planificada): Comparar resultados exactos con cálculo independiente; extremos, ajustes simultáneos, ND, pesos principales y variantes operacionales válidas.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-17

La ventana contiene solo actualizaciones computables; retransmisiones no cuentan. Reinicios conservan historia y prevalecen según configuración; estabilidad numérica sola no permite cierre.

- TESIS ARDREC: 3.2.9, 3.5.7, 3.6.
- Módulos: `src/ardrec/analytics`, `src/ardrec/stopping`.
- Algoritmos: A7, A8.
- Invariantes: INV-04, INV-08, INV-12.
- TF-17 (planificada): Tres variaciones admisibles, ventana incompleta, duplicados, contradicción, reanudación y reinicio coincidente con actualización.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-18

Se verifican ES, SA, CV y LE completos; se registran todos los criterios verdaderos y prevalece ES > SA > CV > LE. Seguridad y controles conservan su precedencia; estados terminales no se reabren.

- TESIS ARDREC: 3.5.2, 3.5.3, 3.5.5, 3.5.6, 3.6.
- Módulos: `src/ardrec/stopping`, `src/ardrec/coordination`.
- Algoritmos: A8, A10.
- Invariantes: INV-05, INV-10, INV-12.
- TF-18 (planificada): Cada criterio, coincidencias, contraejemplos, incertidumbre y pausa externa conciliada; intentar reabrir CERRADO/DETENIDO.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-19

La transición comprueba origen, configuración, espacio, historia, estado, derivados e integridad sobre una copia; el rechazo conserva íntegramente la generación anterior.

- TESIS ARDREC: 3.5.4, 3.6, 3.8.1.
- Módulos: `src/ardrec/transitions`, `src/ardrec/persistence`.
- Algoritmos: A9.
- Invariantes: INV-01, INV-02, INV-03, INV-04, INV-05, INV-06, INV-07, INV-08.
- TF-19 (planificada): Alterar por separado cada grupo de invariantes; comprobar rechazo, ausencia de mutación y confirmación íntegra del candidato válido.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-20

Exclusión de escritura, generaciones inmutables, manifiestos y sincronización aseguran publicación íntegra; la autoridad se obtiene del puntero verificado, no de marcas aisladas.

- TESIS ARDREC: 3.6, 3.10.1, 3.10.2.
- Módulos: `src/ardrec/persistence`, `src/ardrec/transitions`.
- Algoritmos: A9.
- Invariantes: INV-01, INV-04, INV-07, INV-13.
- TF-20 (planificada): Inyectar fallos de escritura, sincronización y reemplazo; intentar dos escritores y corromper manifiesto/puntero; conservar una generación verificable o detener recuperación.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-21

La recuperación distingue decisión, intención, resultado durable, generación escrita y puntero publicado; reprocesar el resultado no repite la herramienta ni duplica efectos.

- TESIS ARDREC: 3.6, 3.10.2.
- Módulos: `src/ardrec/persistence`, `src/ardrec/attempts`, `src/ardrec/transitions`.
- Algoritmos: A5, A9, A10.
- Invariantes: INV-01, INV-09, INV-10, INV-13.
- TF-21 (planificada): Interrumpir en cada frontera y reiniciar repetidamente; comparar identidad, contador, efectos y autoridad con una ejecución sin interrupción.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-22

El coordinador integra A1-A9; la supervisión registra intervenciones autorizadas. FINALIZADA/PAUSADA/DETENIDA son salidas distintas de los estados del servicio y refieren una generación confirmada.

- TESIS ARDREC: 3.5.2, 3.6, 3.9.9, 3.9.11.
- Módulos: `src/ardrec/coordination`, `crates/ardrec-executor`.
- Algoritmos: A10.
- Invariantes: INV-05, INV-07, INV-10, INV-14.
- TF-22 (planificada): Recorridos completos, pausa/reanudación, parada de seguridad, intervención inválida y salida de emergencia; verificar motivos, referencias y asuntos sin conciliar.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-23

Mismo estado, configuración y eventos producen mismas decisiones y resultados. El avance consume recursos finitos o termina; con M combinaciones, ejecuciones <= 2M y esperas externas acotadas.

- TESIS ARDREC: 3.8.2, 3.8.3, 3.8.4.
- Módulos: `src/ardrec/coordination`, `src/ardrec/selection`, `src/ardrec/transitions`.
- Algoritmos: A1, A2, A3, A4, A5, A6, A7, A8, A9, A10.
- Invariantes: INV-09, INV-11, INV-14.
- TF-23 (planificada): Reordenar entradas, reproducir eventos, buscar ciclos sin progreso y escalar casos/evidencias; medir costes frente al análisis sin inventar un umbral de rendimiento.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-24

El laboratorio SSH/FTP/SMB está autorizado y aislado; límites y perfiles se congelan tras pilotaje. Simulaciones no modifican contadores reales, evidencia experimental ni I7.

- TESIS ARDREC: 3.7.5, 3.9.1, 3.9.2.
- Módulos: `lab`, `crates/ardrec-executor`, `experiments`.
- Algoritmos: A3, A5, A10.
- Invariantes: INV-03, INV-10, INV-15.
- TF-24 (planificada): Verificar aislamiento y restauración; pérdida de alcance, cambio material y limpieza insegura detienen acciones; comprobar separación de simulación y experimentación.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-25

El diseño prevé 54 unidades servicio-escenario, 18 por protocolo; referencia externa y elegibilidad se definen antes de medir. Intentos no aumentan n y exclusiones quedan justificadas.

- TESIS ARDREC: Resumen, 3.1, 3.2.1, 3.8.2, 3.9.11.
- Módulos: `experiments`.
- Algoritmos: A10.
- Invariantes: INV-03, INV-11, INV-15.
- TE-25 (planificada): Auditar manifiesto, referencia congelada, separación de Rref y pares comparables; revisar ausencias, unidades no evaluables y posibles dependencias entre observaciones.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_RUN; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-26

Se comparan errores absolutos de R0 y Rf frente a Rref mediante el plan emparejado: MAE, Wilcoxon, alfa 0,05, tamaño del efecto y sensibilidad. El resultado puede no apoyar la hipótesis.

- TESIS ARDREC: Resumen, 3.8.2.
- Módulos: `experiments`.
- Algoritmos: A10.
- Invariantes: INV-11, INV-15.
- TE-26 (planificada): Fijar previamente hipótesis, tratamiento de ceros/empates/ausencias y sensibilidad; verificar cálculos con datos sintéticos separados y ejecutar después sobre datos reales trazables.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_RUN; acceptance=PENDING.
- Soporte previo parcial: ninguno.

### AC-27

Un tercero puede reconstruir resultados desde versión, configuración, eventos y soportes conservados; el informe distingue cierre operativo, corrección funcional y resultado experimental.

- TESIS ARDREC: 3.8.2, 3.9.11, 3.10.
- Módulos: `src/ardrec/coordination`, `src/ardrec/persistence`, `experiments`.
- Algoritmos: A9, A10.
- Invariantes: INV-04, INV-07, INV-13, INV-15.
- TF-27 (planificada): Instalar desde entorno limpio, reproducir el análisis y comparar resultados; comprobar huellas, referencias y discrepancias documentadas.
- Estados: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_RUN; acceptance=PENDING.
- Soporte previo parcial: ninguno.


---

# System acceptance criteria

Source: TESIS ARDREC. References use sections and the consulted document hash,
independent of its filename or previous pagination. This matrix derives verifiable
criteria from the specification. AC, INV and TF/TE are repository engineering IDs,
not thesis numbering. INV-01 through INV-07 map to table 3.13 groups; the remaining
invariants express cross-cutting constraints. Scenarios are proposed, not executed.

## Three independent assessments

| Assessment | Acceptance condition | Required evidence |
| --- | --- | --- |
| Implementation | Complete contracts and behavior within declared scope. | Identified files, review and commit; compilation is insufficient. |
| Functional verification | Requirements and invariants hold, including rejection, boundaries and faults. | Executable tests, independent oracles, results and environment tied to the commit. |
| Experimental validation | The frozen protocol is applied to real, evaluable observations. | Data, external reference, exclusions, analysis and reproducible conclusions. |

IMPLEMENTED does not imply VERIFIED. VERIFIED does not imply VALIDATED. Completed
experimental validation does not require a favorable hypothesis outcome. Simulation
may verify code but cannot replace laboratory observations.

## Status and closure rules

- Implementation: NOT_IMPLEMENTED, PARTIAL, IMPLEMENTED.
- Functional verification: NOT_RUN, PARTIAL, PASS, FAIL.
- Experimental validation: NOT_APPLICABLE, NOT_RUN, COMPLETE, INCOMPLETE.
- Criterion acceptance: PENDING or ACCEPTED. COMPLETE means protocol completion,
  not model superiority. NOT_APPLICABLE requires justification.
- Every status advance requires commit, command or procedure, environment, observed
  and expected results, artifacts and hashes. Failures and exclusions are retained.
- Functional acceptance requires complete implementation and passing relevant tests.
  Experimental acceptance additionally requires protocol execution, eligible data
  and reviewed analysis; favorable statistical findings are not required.
- Row and link coverage checks this matrix, not system behavior. Each scenario must
  become executable cases and independent reference cases before criterion acceptance.
  Percentages require an explicitly defined denominator.

## Baseline and scope

The initial assessment is tied to the commit in system-v1.json. Previous reports
record 34 Python tests, 7 Rust tests and the Unix exchange. Existing checks provide
partial support only: full Rust message validation, durable deduplication, A1-A10,
end-to-end recovery and experimental results remain unverified. This stage neither
reruns those tests nor changes historical results.

Current contract and transport limits are implementation choices whose adequacy for
complete profiles remains to be checked. Associated modules include future targets;
an existing directory does not demonstrate implementation. For experimental criteria,
A10 identifies the origin of evaluated outputs, not a statistical analysis algorithm.

Eligibility, exclusions, missing data, ties, external reference, piloting and
sensitivity procedures must be specified and frozen before experimentation. The design
targets 54 units, 18 per protocol; losses are reported without fabricating observations.
Rref stays outside selection, classification and recalibration. Mathematical definitions
are preserved; source, example or oracle discrepancies must be explicitly resolved
before implementing the affected criterion.

Technical completion requires all applicable functional criteria and clean-environment
installation and reproduction. Academic completion additionally requires experimental
criteria and the results report, including negative findings. Documentation and commits
remain bilingual, Spanish first; brief code comments remain Spanish only. Notice will
be given before A1 implementation and before the operational flow begins.

## Invariants

- **INV-01**: Consistent origin: event, decision, context and generation match.
- **INV-02**: Configuration and characterization remain frozen during observation.
- **INV-03**: Authorized units, cases and actions are not expanded.
- **INV-04**: History, evidence and previous revisions are preserved.
- **INV-05**: Only allowed transitions; terminal states never reopen.
- **INV-06**: Priorities and candidates correspond to the same state.
- **INV-07**: Identities, references, provenance and integrity are preserved.
- **INV-08**: Exact rationals and valid domains; ND is never converted to zero.
- **INV-09**: Bounded budget; each proven start is counted once.
- **INV-10**: An unreconciled action blocks new dispatch.
- **INV-11**: Deterministic decisions; Rref stays outside selection and recalibration.
- **INV-12**: Convergence uses computable history and respects resets.
- **INV-13**: Only a complete, durably published generation has authority.
- **INV-14**: Invocation progresses with bounded resources or explicitly terminates.
- **INV-15**: Simulation, functional verification and experimental observations remain separate.

## Criteria

### AC-01

Python decides; Rust executes; transport neither admits evidence nor confirms state. Permissions prevent unauthorized writes.

- TESIS ARDREC: 3.9.1.
- Modules: `src/ardrec/coordination`, `crates/ardrec-executor`, `src/ardrec/persistence`.
- Algorithms: A10.
- Invariants: INV-01, INV-07.
- TF-01 (planned): Attempt execution from the analytical layer and publication from the executor; both accesses are rejected.
- Status: implementation=PARTIAL; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-02

Reduced rationals, positive denominators, exact types and explicit ND preserve their meaning across Python and Rust.

- TESIS ARDREC: 3.2.9, 3.9.4.
- Modules: `src/ardrec/contracts`, `src/ardrec/messages.py`.
- Algorithms: A1, A2, A7.
- Invariants: INV-08.
- TF-02 (planned): Test canonical zero, boundaries, booleans, decimals, unreduced fractions and cross-language equivalence.
- Status: implementation=PARTIAL; functional_verification=PARTIAL; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: tests/unit/test_contracts.py.

### AC-03

Unix frames enforce length, UTF-8, limits, partial reads and permissions; a faulty channel causes no new dispatch.

- TESIS ARDREC: 3.9.3, 3.9.4.
- Modules: `src/ardrec/transport.py`, `crates/ardrec-executor`.
- Algorithms: A5.
- Invariants: INV-07, INV-10.
- TF-03 (planned): Fragment headers and bodies, truncate, exceed limits, deny socket access and disconnect.
- Status: implementation=PARTIAL; functional_verification=PARTIAL; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: tests/unit/test_transport.py, crates/ardrec-executor/src/transport.rs, scripts/verificar_transporte.py.

### AC-04

All declared messages have applicable success, rejection and uncertainty profiles; identities, versions and references are also checked semantically.

- TESIS ARDREC: 3.9.3, 3.9.5, 3.9.6, 3.9.7, 3.9.8, 3.9.9, 3.9.10, 3.9.11.
- Modules: `src/ardrec/messages.py`, `crates/ardrec-executor`.
- Algorithms: A5, A6, A9, A10.
- Invariants: INV-01, INV-07.
- TF-04 (planned): Cover discovery, execution, query/response, supervision, rejection, persisted state and closure; alter identity, version, reference and producer.
- Status: implementation=PARTIAL; functional_verification=PARTIAL; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: tests/unit/test_messages.py.

### AC-05

An identical message retrieves its durable response; a changed duplicate conflicts; changing message_id cannot reuse attempt_id.

- TESIS ARDREC: 3.9.3, 3.10.2.
- Modules: `src/ardrec/messages.py`, `src/ardrec/attempts`, `src/ardrec/persistence`.
- Algorithms: A5, A9.
- Invariants: INV-01, INV-07, INV-09.
- TF-05 (planned): Repeat messages before and after restart; change content or context; verify zero additional executions.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-06

Typed evaluation is deterministic; only TRUE enables actions; ND is neither FALSE nor zero.

- TESIS ARDREC: 3.3.2, 3.6.
- Modules: `src/ardrec/rules`.
- Algorithms: A1.
- Invariants: INV-08, INV-11.
- TF-06 (planned): Complete operator and decision tables, missing fields, invalid types, ambiguous rules and permuted input order.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-07

Valid configuration is frozen; identities are unique; references, weights, dependencies and limits are checked. Et starts at zero, Rf at R0, Q at PREPARADO and transition history empty.

- TESIS ARDREC: 3.2.1, 3.2.2, 3.2.3, 3.6.
- Modules: `src/ardrec/initialization`.
- Algorithms: A2.
- Invariants: INV-02, INV-03, INV-08.
- TF-07 (planned): Valid configuration and variants with duplicates, forbidden cycles, invalid weights, missing references and later configuration changes.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-08

Controls preserve origin, authorization, precedence and single consumption. Potential plans are finite and operate on copies without creating real evidence.

- TESIS ARDREC: 3.3.3, 3.4.1, 3.6, 3.9.9.
- Modules: `src/ardrec/controls`.
- Algorithms: A3.
- Invariants: INV-02, INV-03, INV-09, INV-11.
- TF-08 (planned): TRUE/FALSE/ND guards, dependencies, consumed controls, cyclic plans and verification that simulation leaves original state unchanged.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-09

Only authorized candidates from PENDIENTE services with remaining budget are selected; minimize (-PA, precedence, service_id, case_id).

- TESIS ARDREC: 3.4.1, 3.4.2, 3.4.3, 3.6.
- Modules: `src/ardrec/selection`.
- Algorithms: A4.
- Invariants: INV-03, INV-06, INV-11.
- TF-09 (planned): Enumerate candidates as an independent oracle; test ties, permuted input, unauthorized high priority and an empty set.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-10

Intent and decision are durable; acceptance does not prove start. The counter increases once when verified start is incorporated; verified non-start consumes no execution.

- TESIS ARDREC: 3.4.4, 3.6, 3.9.2.
- Modules: `src/ardrec/attempts`, `src/ardrec/persistence`, `crates/ardrec-executor`.
- Algorithms: A5.
- Invariants: INV-07, INV-09, INV-10.
- TF-10 (planned): Accept without starting, prove start, repeat the event and restore sessions; check reservation, counter and the one-or-two authorized execution limit.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-11

Only one technical action awaits reconciliation; uncertain start, termination or cleanup blocks new dispatch and never causes automatic re-execution.

- TESIS ARDREC: 3.5.5, 3.9.2, 3.9.3.
- Modules: `src/ardrec/attempts`, `crates/ardrec-executor`, `src/ardrec/coordination`.
- Algorithms: A5, A10.
- Invariants: INV-09, INV-10.
- TF-11 (planned): Lose responses before/after start, exceed waits and fail cleanup; query the original identity and exhaust reconciliation without fabricating confirmation.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-12

The executor enforces frozen profiles, separate arguments without a shell, scope and limits. It preserves supporting artifacts and cleans only intended artifacts; zero exit code does not prove evidence.

- TESIS ARDREC: 3.7, 3.9.2.
- Modules: `crates/ardrec-executor`, `lab`.
- Algorithms: A3, A5.
- Invariants: INV-03, INV-07, INV-10.
- TF-12 (planned): Unauthorized targets/arguments, timeout, truncated output, live children and failed cleanup; verify unrelated files remain intact and references are protected.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-13

Each condition is classified using supporting artifacts, provenance, parameters and rules; distinguish POSITIVO_VALIDO, NEGATIVO_VALIDO, INCONCLUSO, INCIDENCIA, INVALIDO and NO_ADMITIDO.

- TESIS ARDREC: 3.3.4, 3.6, 3.9.8.
- Modules: `src/ardrec/evidence`.
- Algorithms: A6.
- Invariants: INV-04, INV-07, INV-08.
- TF-13 (planned): Cases for every classification, altered or missing artifacts, zero exit without proof and multiple conditions in one attempt.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-14

A condition preserves its key, revisions and artifacts; duplicates do not inflate evidence. Contradictions block dependent conclusions and only verified resolutions change validity.

- TESIS ARDREC: 3.2.5, 3.3.4, 3.6, 3.9.9.
- Modules: `src/ardrec/evidence`, `src/ardrec/persistence`.
- Algorithms: A6.
- Invariants: INV-04, INV-07.
- TF-14 (planned): Duplicate artifacts, contradict profiles and withdraw the maximum; test authorized/unauthorized resolutions and unsupported acceptance flags.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-15

Normalizations, criticality and contributions reproduce the equations; Et is the current maximum, not a sum. Authorized negative substitutions neither alter R0 nor cancel valid positives.

- TESIS ARDREC: 3.2.2, 3.2.3, 3.2.4, 3.2.5, 3.2.7.
- Modules: `src/ardrec/analytics`, `src/ardrec/contracts`.
- Algorithms: A2, A7.
- Invariants: INV-02, INV-04, INV-08.
- TF-15 (planned): Independent rational oracles, ordinal extremes, empty/negative/positive evidence, withdrawal and incompatible substitutions.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-16

Priority and risk use their respective formulas; simultaneous adjustments satisfy R0- <= D <= Rf <= U <= 1. No internal rounding or use of Rref occurs.

- TESIS ARDREC: 3.2.6, 3.2.8, 3.2.9, 3.6.
- Modules: `src/ardrec/analytics`.
- Algorithms: A7.
- Invariants: INV-06, INV-08, INV-11.
- TF-16 (planned): Compare exact results against independent calculations; extremes, simultaneous adjustments, ND, main weights and valid operational alternatives.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-17

The window contains only computable updates; retransmissions do not count. Resets preserve history and follow configuration precedence; numeric stability alone cannot close a service.

- TESIS ARDREC: 3.2.9, 3.5.7, 3.6.
- Modules: `src/ardrec/analytics`, `src/ardrec/stopping`.
- Algorithms: A7, A8.
- Invariants: INV-04, INV-08, INV-12.
- TF-17 (planned): Three admissible variations, incomplete window, duplicates, contradiction, resumption and reset coinciding with an update.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-18

Full ES, SA, CV and LE predicates are checked; all true criteria are recorded with ES > SA > CV > LE. Safety and controls preserve their precedence; terminal states never reopen.

- TESIS ARDREC: 3.5.2, 3.5.3, 3.5.5, 3.5.6, 3.6.
- Modules: `src/ardrec/stopping`, `src/ardrec/coordination`.
- Algorithms: A8, A10.
- Invariants: INV-05, INV-10, INV-12.
- TF-18 (planned): Each criterion, simultaneous criteria, counterexamples, uncertainty and reconciled external pause; attempt reopening CERRADO/DETENIDO.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-19

Transition checks origin, configuration, scope, history, state, derived values and integrity on a copy; rejection preserves the entire previous generation.

- TESIS ARDREC: 3.5.4, 3.6, 3.8.1.
- Modules: `src/ardrec/transitions`, `src/ardrec/persistence`.
- Algorithms: A9.
- Invariants: INV-01, INV-02, INV-03, INV-04, INV-05, INV-06, INV-07, INV-08.
- TF-19 (planned): Alter each invariant group separately; verify rejection, no mutation and complete confirmation of a valid candidate.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-20

Writer exclusion, immutable generations, manifests and synchronization ensure complete publication; authority comes from the verified pointer, not isolated markers.

- TESIS ARDREC: 3.6, 3.10.1, 3.10.2.
- Modules: `src/ardrec/persistence`, `src/ardrec/transitions`.
- Algorithms: A9.
- Invariants: INV-01, INV-04, INV-07, INV-13.
- TF-20 (planned): Inject write, synchronization and replacement failures; attempt two writers and corrupt manifest/pointer; preserve a verifiable generation or stop recovery.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-21

Recovery distinguishes decision, intent, durable result, written generation and published pointer; replaying a result neither reruns the tool nor duplicates effects.

- TESIS ARDREC: 3.6, 3.10.2.
- Modules: `src/ardrec/persistence`, `src/ardrec/attempts`, `src/ardrec/transitions`.
- Algorithms: A5, A9, A10.
- Invariants: INV-01, INV-09, INV-10, INV-13.
- TF-21 (planned): Interrupt at every boundary and restart repeatedly; compare identity, counter, effects and authority against an uninterrupted run.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-22

The coordinator integrates A1-A9; supervision records authorized interventions. FINALIZADA/PAUSADA/DETENIDA differ from service states and refer to a confirmed generation.

- TESIS ARDREC: 3.5.2, 3.6, 3.9.9, 3.9.11.
- Modules: `src/ardrec/coordination`, `crates/ardrec-executor`.
- Algorithms: A10.
- Invariants: INV-05, INV-07, INV-10, INV-14.
- TF-22 (planned): Complete flows, pause/resume, safety stop, invalid intervention and emergency exit; verify reasons, references and unreconciled matters.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-23

The same state, configuration and events produce the same decisions and results. Progress consumes finite resources or terminates; with M combinations, executions <= 2M and external waits are bounded.

- TESIS ARDREC: 3.8.2, 3.8.3, 3.8.4.
- Modules: `src/ardrec/coordination`, `src/ardrec/selection`, `src/ardrec/transitions`.
- Algorithms: A1, A2, A3, A4, A5, A6, A7, A8, A9, A10.
- Invariants: INV-09, INV-11, INV-14.
- TF-23 (planned): Reorder inputs, replay events, seek non-progress cycles and scale cases/evidence; measure costs against the analysis without inventing a performance threshold.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-24

The SSH/FTP/SMB laboratory is authorized and isolated; limits and profiles are frozen after piloting. Simulations never modify real counters, experimental evidence or I7.

- TESIS ARDREC: 3.7.5, 3.9.1, 3.9.2.
- Modules: `lab`, `crates/ardrec-executor`, `experiments`.
- Algorithms: A3, A5, A10.
- Invariants: INV-03, INV-10, INV-15.
- TF-24 (planned): Verify isolation and restoration; scope loss, material change and unsafe cleanup stop actions; check simulation/experiment separation.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_APPLICABLE; acceptance=PENDING.
- Previous partial support: none.

### AC-25

The design targets 54 service-scenario units, 18 per protocol; external reference and eligibility are defined before measurement. Attempts do not increase n and exclusions are justified.

- TESIS ARDREC: Resumen, 3.1, 3.2.1, 3.8.2, 3.9.11.
- Modules: `experiments`.
- Algorithms: A10.
- Invariants: INV-03, INV-11, INV-15.
- TE-25 (planned): Audit manifest, frozen reference, Rref separation and comparable pairs; review missing data, non-evaluable units and possible dependencies between observations.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_RUN; acceptance=PENDING.
- Previous partial support: none.

### AC-26

Compare R0 and Rf absolute errors against Rref using the paired plan: MAE, Wilcoxon, alpha 0.05, effect size and sensitivity. Results may not support the hypothesis.

- TESIS ARDREC: Resumen, 3.8.2.
- Modules: `experiments`.
- Algorithms: A10.
- Invariants: INV-11, INV-15.
- TE-26 (planned): Predefine hypotheses, zero/tie/missing-data handling and sensitivity; verify calculations on separate synthetic data, then run them on traceable real data.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_RUN; acceptance=PENDING.
- Previous partial support: none.

### AC-27

A third party can reconstruct results from preserved version, configuration, events and artifacts; the report distinguishes operational closure, functional correctness and experimental outcome.

- TESIS ARDREC: 3.8.2, 3.9.11, 3.10.
- Modules: `src/ardrec/coordination`, `src/ardrec/persistence`, `experiments`.
- Algorithms: A9, A10.
- Invariants: INV-04, INV-07, INV-13, INV-15.
- TF-27 (planned): Install in a clean environment, replay the analysis and compare results; check hashes, references and documented discrepancies.
- Status: implementation=NOT_IMPLEMENTED; functional_verification=NOT_RUN; experimental_validation=NOT_RUN; acceptance=PENDING.
- Previous partial support: none.

## Revisión posterior de la especificación / Subsequent specification review

Español: esta matriz conserva el punto de partida histórico identificado en system-v1.json.
La revisión de TESIS ARDREC y los pendientes de cobertura se registran en
[el informe de alineación](../traceability/specification-review-20261023.md).
La implementación posterior de componentes no modifica automáticamente los estados
de aceptación ni sustituye las pruebas completas de cada requisito.

English: this matrix preserves the historical baseline identified in system-v1.json.
The TESIS ARDREC review and coverage gaps are recorded in
[the alignment report](../traceability/specification-review-20261023.md).
Later component implementation does not automatically change acceptance statuses
or replace complete verification of each requirement.
