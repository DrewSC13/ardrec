# ARDREC — P8-R23: obligaciones materiales y de capacidad por perfil

**Base protegida:** merge R22 `f9fc5c42141bfe1e66672ecb71b4ab6fef9debcc` (PR #55), con CI posterior `42730066285` aprobada. R23 no reescribe R18–R22 ni reabre la imagen QCOW2.

El incremento construye una **matriz verificable de obligaciones** a partir de las fuentes públicas ya fijadas: catálogo P7 (25 familias), perfiles P8 (29 variantes) e inventario/compatibilidad R9 (15 binarios observados, tres principales SSH/FTP/SMB). Contrasta para cada variante los doce campos de vinculación aún nulos, precondiciones, parámetros materiales, soportes de aceptación, política de cliente sin shell y la correspondencia con el binario candidato y su SHA-256 *observado en imagen*. De este modo, enumera exactamente **348 vinculaciones pendientes** (29 × 12) y separa las **cinco variantes con escritura** que requieren limpieza independiente. Cada obligación es una *ausencia por resolver*, no una prueba de capacidad.

El colector privado R23 puede autenticar por SHA-256 el recibo R22 y verificar sus agregados (138 nodos, 906 relaciones y 66 observaciones RUNPATH) sin publicar sus bytes ni acceder a la QCOW2. Solo el SHA-256 de un nuevo recibo R23, sus conteos y límites se incorporarán al historial público cuando exista una adquisición validada del operador. CI nunca lee recibos privados.

**No se acredita:** identidad del ejecutable en runtime, cierre de búsqueda efectiva `ld.so`, soporte real de opciones SSH/FTP/SMB, política/capacidad del servidor, aislamiento físico de los casos, autorización, presupuesto congelado, captura forense, argv tipado aprobado, restauración independiente, ni capacidad de despacho. No construir argumentos ni ejecutar clientes. Las rutas con escritura se mantienen bloqueadas por separado; un resultado positivo de escritura no equivale a su limpieza.

**Estado:** P8, AL-06 y AL-07 abiertos. Los 29 perfiles permanecen `BLOCKED_UNBOUND_NO_EXECUTION` en la fuente; cero casos autorizados, cero despachos. P9 y A1–A10 sin iniciar.

**EN:** Pinned, fail-closed per-profile material obligation ledger. Static image binary candidates are not operational capability proofs or authorizations.

## Resultado material R23 autenticado

El operador adquirió el recibo privado R23, cuya integridad se ha comprobado por SHA-256, sin transferir sus bytes al repositorio. **29 perfiles** (SSH 8, FTP 10, SMB 11), **25 familias**, **348 campos de vinculación sin materializar** (12 por perfil), **cinco variantes de escritura con limpieza independiente pendiente** y **nueve clases de comprobación runtime no verificadas por perfil**. Se verificó la procedencia del recibo R22 por SHA-256: **138 nodos**, **906 relaciones ELF** y **66 objetos RUNPATH** siguen siendo candidatos estáticos.

SHA-256 del recibo privado R23: `42b7ff79f73d589be96a8d76e1bcb812a5374112679c277a23f598eeb851f1c3`. SHA-256 del libro determinista de obligaciones: `8557bd27144ac390d72dec2337ac4d246fdb388571242de49a31f21441607330`. Los recibos R22/R23 se conservan en almacenamiento privado fuera de Git.

No se verificaron identidad binaria de runtime, semántica de carga efectiva, capacidades CLI, autorización de casos, configuración efectiva, argv aprobado, presupuesto, capturas ni restauración independiente. **Cero perfiles/casos autorizados y cero despachos.** P8, AL-06 y AL-07 siguen abiertos; P9 y A1–A10 no iniciados.
