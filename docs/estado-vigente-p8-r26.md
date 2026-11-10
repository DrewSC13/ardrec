# ARDREC — Estado propuesto P8-R26: grafo sintético de Include SSH

**Base exacta:** `d4dfb21ba81143e27870586b9ebf442326287eb7` (PR #58 integrado y CI posmerge aprobada). Esta página forma parte de una **entrega source-only en staging**, no acredita nuevo commit/PR/integración hasta que el operador lo realice y aporte sus controles.

## Evidencia y alcance

- Evidencia aportada por el operador: verificador del recibo privado R25 `P8_R26_INPUT=PASS`, 2 fuentes medidas, 2.426 bytes, una directiva `Include` pendiente. Esa operación **no releyó la imagen** ni resolvió el contenido de `Include`.
- Verificación del asistente: PR #58 en `main`, CI posmerge Python y Rust `completed/success`, y sincronización fast-forward de `main` informada por Prometheus.
- Aporte R26: analizador puro para corpus sintéticos, con grafo candidato ordenado, detección de ciclos, límites finitos, referencias fuera de ámbito denegadas y marca explícita de `Host`/`Match` sin evaluar.
- La CI de este candidato no leerá QCOW2, recibos, secretos o archivos de configuración del usuario. Alias exacto material de R25 se trata únicamente como declaración sintética permitida, no como seguimiento real de symlink.

## Pendientes finitos, separados por pruebas y autoridad

| Dependencia P8 | Fuente necesaria | Producto/verificación de salida | Estado de R26 |
|---|---|---|---|
| Árbol Include SSH observado | Fuente de configuración material, con revalidación de QCOW2 y límites | Grafo privado verificable, sin revelar contenidos | **PENDIENTE** |
| Contextos `Host`/`Match` | Contexto de destino, usuario, orden y semántica exacta de versión | Regla revisada para candidatos; ejecución solo en etapa autorizada | **PENDIENTE** |
| Configuración de usuario | Identidad del proceso y HOME específicos, sin suponer un usuario | Cadena de fuentes autenticada y política de precedencia | **PENDIENTE** |
| Parser de OpenSSH vs. modelo | Versión/documentación y contraste aislado autorizado | Verificación semántica independiente; `ssh -G` no autorizado aquí | **PENDIENTE** |
| FTP y SMB: variantes | Manuales y contexto fuente ya anclados en R14/R15 | Reglas por 21 posiciones FTP/SMB | **PENDIENTE** |
| Contrato tipado `argv`/auxiliares | Revisión de gramática por variante y capacidad material | Contratos de solo datos; ninguna cadena shell libre | **PENDIENTE** |
| Caso, autoridad, caducidad, limpieza | Evidencia de confianza real y guardas por caso | Frontera P8/P9–P12 documentada; despacho no implementado en P8 | **PENDIENTE** |
| Pruebas de aceptación y cierre P8 | Cobertura específica y reconciliación de obligaciones | Dictamen de cierre acotado, no promoción por contador | **PENDIENTE** |

**Alcance que no cambia:** 25 familias (SSH 8, FTP 8, SMB 9); 29 perfiles (SSH 8, FTP 10, SMB 11); matrices históricas de 348 campos no vinculados y 261 barreras pendientes; cinco escrituras sin limpieza independiente; cero casos autorizados, cero opciones CLI aprobadas y cero despacho. AL-06 y AL-07 abiertos, P9 y A1–A10 sin empezar.

La existencia de un grafo sintético no es evidencia de que los archivos reales hayan sido resueltos, ni verifica configuración efectiva. La lectura física adicional requerirá alcance y autorización separados. No abrir un PR ni integrar a `main` como efecto de la prueba de staging.

**EN:** Candidate source-only, deterministic synthetic graph with explicit unresolved effective semantics and no operational authority.

## Revisión R26-FIX1 sin integración

Tras 33 pruebas del staging inicial se detectó pérdida de marca condicional en aristas descendientes de `Host`/`Match`. El paquete FIX1 conserva la incertidumbre heredada por ruta, rechaza `Match !exec` y añade regresiones: 17 casos y 37 pruebas sintéticas. Este paquete no acredita que el árbol de inclusión de la imagen sea el mismo, ni aplica un parche sobre `main`.
