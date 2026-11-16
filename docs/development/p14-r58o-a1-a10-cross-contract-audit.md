# P14 — R58-O: auditoría transversal sintética A1–A10

## Propósito

Correlacionar los contratos de desarrollo previamente integrados, **sin construir un segundo motor de ejecución** ni atribuir al programa capacidades operacionales que todavía no existen.

- **A1–A3 (R26):** tres servicios sintéticos, nueve eventos verificables, guardas que impiden el despacho. Verificación del ciclo de desarrollo R28.
- **A4 (R58-L):** selección voraz exacta de casos del catálogo, únicamente sobre la proyección `PENDIENTE` simulada. La selección confirmada de R26 permanece vacía porque sus unidades están `PREPARADO`.
- **A5 (R58-M/N):** lectura del diario durable y comprobación de un recibo declarado inmutable, sin ejecución ni verificación independiente de la identidad física.
- **A6–A8 (R58-K/L):** 25 familias disponibles, 29 casos en la demostración, clasificación real `ND`, intervalos A7 matemáticos no resueltos y recomendación A8 de pausa.
- **A9:** existencia y verificación de un recibo local declarado R58-N; **no** se publica una generación técnica.
- **A10:** reporte reproducible y cadena SHA-256 de diez entradas, cada una con su fuente, orden, estado y predecesor.

## Brecha de integración explícita

R26 contiene tres referencias de servicio/controles y R58-L/N contiene hasta 54 ventanas de casos del catálogo. **Compartir `session_id` no demuestra que exista un enlace operacional firmado de cada control A3 a una variante concreta A4–A6.** El informe exige:

`a1_a3_to_family_case_binding_attested=false`, `independent_physical_case_binding_attested=false`, `a1_a10_implementation_complete=false`, `experimental_hypothesis_validated=false`.

R58-O registra y detecta brechas, no las resuelve silenciosamente.

## Seguridad e invariantes

No toca VM, servicios, redes, imágenes, credenciales ni diarios existentes. El módulo principal es exclusivamente de lectura. La demostración crea un diario de fixture `ok` **temporal** y registra `RESERVED`/`ACCEPTED`, pero nunca llama a `execute` ni `recover`; elimina el directorio temporal al terminar. Sin clasificación acreditada A6, ni Rf confirmado, ni transición A9, ni despacho P8. R34 DENY / F11 sin activación física / P8 NO-GO.

Comando desde la raíz del repositorio:

`PYTHONPATH=src python3 -B scripts/ardrec_p14_r58o_a1_a10_trace_demo.py --synthetic-offline`

El código de verificación recomputa el documento entero desde los contratos originales y el recibo durable; un SHA-256 recalculado sobre una modificación falsa no basta para superar la prueba. **Esta prueba de integración no equivale a la validación experimental de las 54 unidades.**
