# P8-R34 — Navegación documental privada de solo lectura (DENY ALL)

Este incremento permite consultar **el estado de las 39 entradas y sus 312 preguntas originalmente pendientes**. Los datos proceden del recibo privado R32 y del libro/eventos privados R33 previamente autenticados; no se extraen ni descargan fuentes nuevas. La CI usa exclusivamente fuentes públicas y objetos sintéticos. Un evento R33 de *disposición documental* solo cambia el estado `UNTRIAGED` a `DOCUMENTARY_DISPOSITION_RECORDED_NOT_APPROVAL`; jamás declara respuesta semántica suficiente, opción CLI válida, capacidad de cliente, perfil permitido ni despacho.

La interfaz local admite `summary` (solo conteos), `list` (página de hasta 10 identificadores autenticados y pendientes) y `focus --term <identificador_exacto>` (ocho preguntas y referencias de una entrada). Los resultados no incluyen el contenido roff, notas humanas ni las disposiciones concretas. Nunca escribir ni publicar esta salida en Git. No hay modo de registro, cambio de estado, ejecución, contacto de red, acceso a QCOW2 o uso de clientes.

Tras integrar R34 y verificar la CI posmerge, el operador podrá ejecutar **desde la rama `main` limpia**:

```bash
python3 -B lab/p8_r34_private_review_navigation.py summary
python3 -B lab/p8_r34_private_review_navigation.py list --offset 0 --limit 5
# Seleccione manualmente un term_id auténtico de la lista previa:
python3 -B lab/p8_r34_private_review_navigation.py focus --term 'TERM_ID_AUTENTICADO'
```

El último ejemplo contiene un marcador deliberado, no una opción de cliente ni un identificador válido. El modo `focus` rechaza entradas inexistentes. **Una ventana roff de hasta 24 líneas NO certifica una cláusula completa.** Para evaluar cada pregunta será necesaria una revisión documental sustantiva, humana y separada; R34 no atribuye respuestas ni reclama disponer de todas las cláusulas.

Se mantienen 29 perfiles bloqueados, 348 vinculaciones materiales no satisfechas, 261 barreras probatorias sin comprobar, cinco variantes de escritura sin prueba independiente de limpieza y cero casos/despachos autorizados. P8, AL-06 y AL-07 continúan abiertos; P9 y A1–A10 no iniciados.

**EN:** Read-only source-bound, private human-review navigation, never semantic certification or operational authorization.
