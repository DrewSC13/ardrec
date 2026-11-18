# P14-R88 — Ejecución DEV con los módulos originales (sin despacho)

## Objetivo y alcance

El incremento introduce una sola ruta terminal reutilizando **R69 → R70 → R71 → R38** y una puerta de diagnóstico **P8-R7 Rust deny-only**, sin motor de estados paralelo, sin TUI adicional y sin nueva base de datos. La prueba local ejecuta, como máximo, un fixture benigno `ok` mediante `BenignPipeline` de Python. **No es un intento SSH, ni ejecuta el componente de despacho Rust.**

El coordinador exige igualdad de la identidad `DEV_TUTOR_001` de R69/R70/R71, integridad de la configuración congelada y HEAD del almacén durable, un único inicio total del fixture local, A6=ND, Rf confirmado nulo, GEN1 estructural sin publicación técnica y visualización del tablero R38 original. El diagnóstico Rust usa una propuesta P8-R7 sintética aparte: su perfil de prueba **no se vincula** a la identidad A2, no otorga autoridad y siempre deniega.

## Flujo ejecutable

1. Antes de escribir, comparar un binario Rust con el SHA-256 local declarado; ejecutar el probe de entrada sintética y exigir coincidencia con la evaluación Python **deny-only**.
2. Crear o recuperar la sesión R69 en `DurableStore`, congelando A2 y ejecutando las decisiones A1 originales.
3. Invocar R70 `open_or_publish_safe(..., publish=True)` para parada segura DEV y publicación GEN1 **analítica estructural** en `AnalyticalArchive`; ninguna prueba física.
4. Invocar R71 para seleccionar SSH **solo en sombra** y ejecutar un solo fixture `BenignPipeline('ok')` local; mantener A6=ND y A7=5/12 **hipotético**.
5. Construir la vista con `build_shadow_dashboard` original; verificar el contrato de diez etapas y fijar únicamente los enlaces mínimos de la ejecución en un archivo dentro del diario benigno ya existente. No crear otro almacén.
6. `--verify-only` lee `DurableStore`, el archivo R88 y el diario A5; compara HEAD, evidencia local y vista R38 **sin** invocar submit/accept/execute ni publicar nueva generación.

Las transiciones `DETENER` pertenecen exclusivamente a la ruta GEN1 estructural R70. Las 25 familias y los 54 casos sintéticos no son identidades operacionales de la sesión R88.

## Criterios de aceptación DEV

- Caso único SSH_DEV/CASE_REFERENCE en la sesión R26, rutas independientes privadas; sin red/VM y sin privilegios.
- Probe Rust real P8-R7: JSON idéntico al oráculo Python, denegación obligatoria, SHA-256 local comprobado. CI ejecuta el binario Rust compilado. La prueba aislada Python usa doble de prueba y **no demuestra Rust real**.
- Un solo inicio local total y recuperación sin otro inicio. Corruptelas en diario, HEAD, fixture y binario producen cierre conservador.
- R69, R70, R71 y R38 verifican el mismo registro; A6 ND, Rf=sin confirmar y generación técnica no publicada.
- Regresión Python, Rust y SSH R36.5 requerida por CI antes de merge.

## Límites y ruta crítica

R88 **NO** implementa el despacho de A5 Rust ni acredita F11, autoridad independiente, testigos de red, evidencias técnicas admisibles o publicación de generación posterior a una observación real. Por eso los estados permanecen: sistema `PENDING`, validación `NOT_RUN`, P8 `NO-GO`.

El siguiente bloqueo, para R89, es revisar físicamente F11 **en modo de solo lectura**; las remediaciones y operaciones privilegiadas requieren orden y aprobación independientes. Solo con la autorización y barreras acreditadas se planificará la primera observación SSH R90.
