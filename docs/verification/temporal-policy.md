# Verificación temporal / Temporal verification

## Español

El contraste `python3 scripts/verificar_tiempos.py` comprueba 19 casos con
expectativas explícitas en ambos lenguajes: 38 comparaciones. Incluye inversión
respecto de solicitud, retroceso/avance UTC, microsegundos, medianoche, identidad,
consulta posterior al resultado y duración entera grande. La paridad por sí sola
no constituye el oráculo: ambos resultados se comparan con la expectativa congelada.

`test_temporal.py` añade 12 pruebas Python: rechazo antes de escribir, reserva y
consulta conservadas, reapertura actual, lectura histórica sin cambios de bytes,
bloqueo de promoción, redondeo exacto, independencia UTC, desbordamiento, regresión,
prohibición de serialización y fork real. El diario antiguo Python se construye
simulando la admisión anterior, sin desactivar la verificación durante reapertura.

Rust añade seis pruebas: los mismos 19 oráculos, rechazo durable sin escritura,
lectura/bloqueo de un diario histórico reconstruido con el formato original y tres
pruebas de temporizador. La comprobación Rust de cambio de PID es inyectada; el fork
real se prueba en Python. No se simula un reinicio físico del host ni corte eléctrico.

La suite resultante contiene 254 métodos Python y 69 pruebas Rust. Se conservan
3052 comparaciones de protocolo y 520 casos de magnitudes como conjuntos distintos.
Se repiten empaquetado, formato/clippy, transporte, diario y conciliación por socket.
La CI incorpora un paso temporal obligatorio. Estos resultados son de componentes;
no equivalen a aceptación integral o validación experimental.

## English

The temporal script checks 19 frozen oracles independently in both languages (38
comparisons). Twelve added Python tests cover admission, unchanged historical replay,
blocked advancement, query retention, exact rounding, overflow, clock regression,
UTC independence, non-persistible origins and a real fork. Six added Rust tests cover
the same oracle corpus, durable rejection, historical replay and local timers. Rust
PID changes are injected; only Python exercises a real fork. No physical host restart
or power failure is claimed. Final suites: 254 Python methods and 69 Rust tests.
Operational differential checks (3052) and magnitude cases (520) remain separate.
Remote CI, scoped finding disposition and complete system acceptance are distinct gates.
