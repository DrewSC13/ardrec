# ARDREC — R58-M: auditoría A5 del diario benigno durable (solo lectura)

## Alcance y autoridad

La implementación consulta una base **preexistente** del `BenignPipeline` P9–P12 sin instanciarlo en el módulo auditor, sin ejecutar `submit`, `accept`, `execute` ni `recover`. Usa SQLite `mode=ro&immutable=1`; rechaza bases con `-wal`, `-shm` o `-journal` pendientes para no ignorar confirmaciones. No es un lector concurrente: se exige un diario cerrado/estabilizado. La demo crea un diario **efímero** mediante el API original únicamente para `submit` y `accept`; no inicia procesos. No modifica VM, red ni host de laboratorio.

Verifica: huella de solicitud derivada de la especificación P9, cadena SHA-256 de eventos, orden de `RESERVED` → `ACCEPTED` → `START_INTENT` y estados de recuperación/resultado, contador de reserva irreversible, coincidencia del resultado y archivos stdout/stderr cuando existen, y límites de lectura. Los SHA no constituyen autenticación criptográfica contra un autor capaz de reescribir toda la base; **integridad local consistente** no equivale a procedencia independiente.

## Limitación de identidad y relación con A4

El diario P9–P12 guarda `request_id` pero no `service_id`, `session_id`, `derived_case_id` ni `assessment_index`. Por ello R58-M compara la identificación declarada con el intento proyectado en R58-L y conserva **`case_identity_binding_accredited=false`**. No puede demostrar que una ejecución benigna corresponda a una condición SSH/FTP/SMB. No transforma la selección A4 en autorización, no da por agotado o liberado un presupuesto de intentos técnicos ni genera evidencia A6. Cualquier diario válido bloquea una propuesta de reintento automático basada exclusivamente en esta auditoría.

## Integración prevista

- `audit_benign_journal(root, request_id)` inspecciona una base cerrada y rechaza casos ambiguos.
- `build_durable_a5_link(review, root, request_id)` vuelve a verificar R58-L y produce un enlace **documental** con el identificador seleccionado.
- `verify_durable_a5_link(...)` recalcula íntegramente la salida y detecta modificaciones incluso si se recalcula su SHA.
- La demo usa `--synthetic-offline`, 29 casos/25 familias, y un diario temporal `ACCEPTED` con **cero inicios**; se elimina al terminar.

## Exclusiones

Sin ejecución física A5, sin aceptación técnica A6, sin cambio de Rf, sin transición A8 o publicación A9, sin VM, sin P8 (NO-GO), sin activación F11 ni modificación de R34 (DENY). No se auditan fixtures `r12_systemd`/`r14_systemd_stop`: tienen rutas de custodia distintas y se rechazan expresamente. El paso siguiente debe diseñar un contrato durable de unión de identidad A4–A5 antes de permitir cualquier acreditación técnica.
