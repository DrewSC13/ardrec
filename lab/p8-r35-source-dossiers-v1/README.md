# P8-R35 — Expedientes documentales anclados, sin certificación semántica

Incremento **source-only, deny-all**. Tras R34 se mantienen 39 términos documentales y ocho preguntas por término, total 312. R35 añade una **matriz preliminar de desarrollador** de esas 312 verificaciones, explícitamente identificada como observaciones de documentación pública que **no** equivalen a una revisión concluyente de las versiones privadas capturadas. El archivo `developer_matrix.json` no contiene credenciales, comandos ejecutados, recibos privados, roff ni aprobaciones.

El operador R35 vuelve a autenticar **la captura R14 ya existente**, sin tocar QCOW2, ejecutar clientes o importar manuales nuevos. Concilia en memoria los 39 contextos originales R31, la cola R32 y el libro/eventos privados R33. Para cada término identifica el ancla y un **rango candidato acotado** por la siguiente ancla conocida (si existe), un máximo de 120 líneas y 20.000 bytes. Una ancla siguiente puede omitir encabezados intermedios; este rango **no garantiza capturar una cláusula completa**. No extraer decisiones sobre sintaxis, valores por defecto, TLS o capacidades de un mero límite físico.

El informe privado R35, si el operador lo crea de manera explícita y exclusiva, contiene exclusivamente **metadatos** (IDs, SHA-256, números de línea, estado conservador, clase de revisión y los IDs de ocho preguntas). No contiene texto de manual, fragmentos, notas humanas, credenciales o descripciones de opciones. Las fuentes originales siguen en R14. `inspect` es solo lectura; `create` crea un único fichero privado con permisos `0600`, carpeta `0700`, `O_EXCL` y `fsync`. Ningún modo escribe en R33. No repetir `create` si ya existe el informe.

**Después de integrar R35 y comprobar la CI posmerge y el avance rápido de `main`**, las operaciones permitidas son:

```bash
python3 -B lab/p8_r35_private_source_dossiers.py inspect
python3 -B lab/p8_r35_private_source_dossiers.py create
```

No ejecutarlas desde un worktree de propuesta, ni en CI. El operador debe ejecutar `inspect` antes de decidir crear el informe, revisando su salida. En CI solo se ejecutan el verificador público y pruebas sintéticas, sin acceso a R14/R31/R32/R33.

**El cierre real de P8 exige adicionalmente** cláusulas completas revisadas, capacidades efectivas de clientes, 348 vinculaciones materiales, 261 acreditaciones runtime, cinco limpiezas independientes, autorización y aislamiento experimental. Registrar un candidato o clasificar ocho preguntas no prueba ni satisface esas obligaciones. Se mantienen 29 perfiles denegados; cero renderizadores argv, opciones aprobadas, casos autorizados y despachos. P8 y AL-06/AL-07 abiertos, P9/A1–A10 no iniciados.

**EN:** Pinned original-source, bounded candidate locations and public preliminary review hypotheses; no semantic certification, operational authorization or client activity.
