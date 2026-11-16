# P14 / R58-W — Declaración sintética de intención A5 y resolución sin inicio

**ES.** La capa R58-W consume exclusivamente el informe R58-V verificado y conserva el rechazo durable de R58-S. Sólo acepta identidades A7 de casos cuya **fase simulada** es `PENDIENTE`. Una intención de modelo `DECLARE_INTENT` nunca representa envío, reserva, aceptación, inicio ni autorización de intento A5. `RESOLVE_NO_START` cierra documentalmente la intención como **sin inicio**, sin evidencia técnica admitida.

**EN.** R58-W implements a source-pinned, private, offline SQLite event ledger for simulated declarations and no-start resolutions. Neither event is an executable attempt or evidence. R58-S denial remains authoritative.

- Entradas: recibo R58-V y sus ocho fuentes, comprobadas nuevamente; seis directorios independientes, propiedad del usuario y permisos restringidos.
- Reglas: `DECLARE_INTENT` sólo para un caso `PENDIENTE` del modelo; `RESOLVE_NO_START` sólo después de declarar; repetición idéntica = idempotente; cambios = conflicto; eventos inmutables y hash encadenado.
- Persistencia: transacción SQLite `BEGIN IMMEDIATE`, `synchronous=FULL`, `journal_mode=DELETE`, integridad y reconstrucción del estado materializado por replay.
- Seguridad: no `subprocess`, `socket`, red, P8, VM, executor o mutación de R58-S/T/U/V. Cero reservas e inicios A5 reales, evidencia A6 acreditada cero, clasificación A6 `ND`, riesgo final `None`, publicación A9 `None`, R34 DENY, F11 no activado y `P8=NO-GO`.
- Límite: un hash sin una firma externa no es prueba de autenticidad frente al propietario de la base; R58-W demuestra detección interna de alteraciones accidentales y coherencia lógica, no integridad antifraude total.
- No demuestra ni confirma la hipótesis experimental de la tesis. No representa las 54 unidades completas; la muestra fija de demo tiene 29 casos de 25 familias.


## Corrección de rendimiento R58-W-R1 (sesión de verificación)

La CLI integrada emplea `verified_model_source_batch` exclusivamente durante
la secuencia de operaciones del libro SQLite sintético. Al entrar reconstruye y
verifica íntegramente el informe R58-V; antes de cada operación y al salir
recalcula huellas SHA-256 de todos los archivos en cinco directorios fuente,
además de los cuatro documentos fuente. No se reutiliza entre procesos,
no permite sesiones anidadas y rechaza cambios de contenido, permisos,
inventario o identidad. Fuera del contexto, cada operación mantiene la
verificación original completa. No cambia el formato del libro, ni la
semántica de guardas, A6=ND, F11 inactivo o P8=NO-GO.
