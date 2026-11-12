# ARDREC — P8-R32: cola de revisión semántica con origen verificado

**Base exacta:** merge firmado R31 `3a236a74da1b88f1e9485e3a6de82064592a04fa` (PR #62, CI posmerge confirmada). Este documento describe una propuesta R32; su publicación e integración requieren una nueva PR, firma y CI.

**Dato material antecedente:** recibo privado R31 `8f26fb577e2f744b2f7a67d0aaf8970f427a9f749fdd530996f26cea44d99542`, obtenido una sola vez por el operador y almacenado fuera de Git. Registra 39 ventanas roff de tres manuales originales, vinculadas a 21 perfiles FTP/SMB, sin certificación semántica.

**Alcance nuevo:** verificador contra sustitución/corrupción de recibo, campos, identidad de la fuente, offsets, SHA-256 de ventana y correspondencia con anclas R14. Generación opcional, privada, de 39 fichas con ocho preguntas técnicas por entrada (312 sin resolver): semántica y ámbito, gramática y precedencia, importación de configuración, secretos, cifrado y degradación, ejecución/red, lecturas/escrituras/limpieza, límites/fallos/prueba adicional. Las detecciones léxicas se identifican expresamente como **indicios** y no reemplazan la revisión de la cláusula completa ni del binario real. El informe de R32 evita copiar los bytes originales y solo se crea de modo exclusivo, fuera de Git, 0600 dentro de 0700.

**No se declara:** 39 revisiones semánticas concluidas, completitud de cláusulas, opciones aprobadas, gramática de `argv`, compatibilidad de cliente o servidor, capacidades runtime, perfil ni caso autorizado, presupuesto, aislamiento, restauración ni despacho. El objetivo próximo, sujeto a una fase de revisión humana específica, será responder las 312 preguntas con evidencias y registrar explícitamente incertidumbres y exclusiones.

**Estado:** P8 abierto; 29 perfiles bloqueados, 348 vinculaciones materiales, 261 barreras probatorias y cinco variantes de escritura sin limpieza independiente; AL-06/AL-07 abiertos. P9 y A1–A10 no iniciados. CI usa solo fuentes públicas y bytes sintéticos; no lee recibos privados ni QCOW2.

**EN:** Private, exact-source-bound semantic review queue with unanswered questions. Source integrity is not semantic approval or execution authority.
