# ARDREC — P8-R29: comprobación consolidada de declaraciones tipadas

**Estado:** propuesta source-only sobre `45203db865f407fef5b57594a4b9ce740783c32d`; no significa commit, PR, integración o cierre P8 hasta completarse sus controles independientes.

## Progreso técnico

Se implementa una función pura para cruzar exactamente **29 operaciones semánticas** de R1/R10/R13/R15 (SSH 8, FTP 10, SMB 11), sus referencias materiales nombradas, controles específicos de protocolo, precondiciones, soportes de aceptación y planes de limpieza. En vez de recopilar únicamente contadores, se valida que las declaraciones de cada variante sean compatibles, con rechazo de declaraciones que pretendan fijar `argv`, credenciales, cliente, rutas o autorización sin pruebas.

Un diseño simbólico válido no implica capacidad. El verificador devuelve `DENY` para todos los perfiles; las cinco variantes con escritura siguen exigiendo limpieza independiente. `R27` acredita fuentes SSH vinculadas y grafo **candidato**, sin configuración efectiva; la revisión privada `R28` no altera la autoridad operativa.

## Métricas de trazabilidad que deben permanecer distintas

- **29 perfiles**, de **25 familias**; SSH 8, FTP 10, SMB 11.
- **348** campos materiales sin vincular (29 × 12).
- **261** obligaciones de suficiencia probatoria runtime sin verificar (29 × 9).
- **271** vínculos de controles documentales de R17/R15 (no equivalen a las 261 pruebas).
- **238** vínculos de riesgos documentados; **cinco** perfiles de escritura sin limpieza independiente acreditada.
- **Cero** perfiles aprobados, casos autorizados, renderizadores `argv` o despachos.

## Criterio de continuación

El siguiente bloque sustantivo deberá establecer por variante las capacidades materiales requeridas y cómo probar las nueve clases de evidencia sin atribuir pruebas no realizadas. La realización de `argv`, ejecución de binarios, casos reales, configuración efectiva, presupuestos y restauración son **obligaciones pendientes** que requieren las fases y autorizaciones correspondientes; no se deducen del validador. Mantener AL-06/AL-07 y P8 abiertos y P9/A1–A10 sin iniciar.

**EN:** Source-anchored, deterministic typed symbolic operation design validator. No execution rights or runtime proof are conferred.
