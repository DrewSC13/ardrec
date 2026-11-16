# P14 / R58-X — Resolución A5 «sin inicio» y cotas exactas A6–A7

**Modo exclusivamente sintético y de lectura.** R58-X consume el recibo R58-V y
la base SQLite R58-W verificada, sin reservar ni iniciar intentos reales. La
resolución `RESOLVE_NO_START` significa únicamente que el intento simulado no
comenzó: no demuestra ni la presencia ni la ausencia de la vulnerabilidad.

## Contratos

- Entrada: los 29 casos/25 familias del catálogo P7 fijado, R58-S (denegación),
  el historial T1/U, el handoff R58-V y el diario R58-W.
- Se verifica íntegramente la cadena de eventos y su materialización antes de
  leer en modo SQLite `ro`; la huella de los bytes se compara antes y después.
- Todas las admisiones A6 permanecen ausentes; no hay soporte ni procedencia
  acreditada. **A6=ND** para los 29 casos.
- La cota A7 se calcula mediante **el núcleo existente R58-E/R58-D**, con
  magnitudes racionales fijadas por la sesión R26, sin atribuir al no-inicio
  un valor de evidencia igual a cero. El conjunto no resuelto es `[0,1]`.
- Para la sesión sintética R26, R0=1/4, criticidad=1/2, riesgo de reemplazo=1/4,
  pesos `(1/3,1/3,1/3)`, las cotas resultan **[1/4,7/12]**. No son una
  estimación empírica ni una medida confirmada del riesgo final.
- La salida SHA-256 identifica un informe matemático reproducible; no confiere
  autenticación externa ni autorización.
- No hay A5 operacional, A6 acreditado, actualización confirmada Rf, cambio
  de estado real, A9 publicada ni despacho P8.

## Pruebas y límites

La suite R58-X comprueba identidades, asociación caso-sesión, integridad del
SQLite, rechazos de reescrituras y manipulación de las conclusiones, cotas A7
exactas e idempotencia de lectura. La CLI requiere `--synthetic-offline` y se
lanza exclusivamente desde la raíz del checkout. El job Python dispone de 30
minutos por la suma de las demostraciones integradas preexistentes; no se
relajan las comprobaciones funcionales ni las barreras del laboratorio.

**No constituye evidencia experimental ni confirmación de la hipótesis.**
R34 DENY, F11 inactivo y P8 NO-GO.
