# Verificación de publicación analítica / Analytical publication verification

## Español

Ejecutar con Python 3.14.7 desde la raíz:

```bash
PYTHONPATH=src python -B -m unittest discover -s tests/unit -p 'test_analytical_publication.py' -v
PYTHONPATH=src python -B -m unittest discover -s tests/unit -v
```

Esperado: 25 pruebas nuevas y 374 totales, sin omisiones. La CI ya descubre el
archivo nuevo en su paso de pruebas Python; no se introduce una ruta alternativa.
La aceptación local del instalador exige además empaquetado limpio, 73 pruebas
Rust y los siete verificadores existentes, incluidos identidad del par y sus
siete escenarios Python–Rust. Los resultados remotos se registran después de
publicar y verificar la revisión exacta; este documento no los presupone.

Las pruebas nuevas cubren inicialización, adopción histórica, publicación,
recuperación, contexto/fase/conjunto de servicios, congelación, hash inválido,
archivos ausentes/corruptos, rechazo de degradación y conservación de bytes
históricos. Comprueban que recibo de incorporación y anclaje confirman juntos.
Una prueba recorre 20 fronteras con SIGKILL: seis en generación, seis en diario
y ocho en HEAD/acuse. Antes de sustituir HEAD se recupera el par anterior;
después se recupera el par nuevo completo. Nunca se promueve una instantánea
por estar almacenada. La prueba de fsync fallido tras reemplazar HEAD requiere
reapertura y verifica el estado efectivamente visible.

Los objetos del fixture son deliberadamente sintéticos y opacos. Su aceptación
prueba el enlace estructural, no la interpretación analítica. Una prueba muestra
el límite de frescura: un HEAD antiguo íntegro solo se rechaza si se aporta un
checkpoint externo esperado. No se afirma protección autónoma antirrollback.
No se ejecutan herramientas externas, experimentos ni cortes eléctricos.

## English

Run the two commands above with Python 3.14.7. Expect 25 new tests and 374 total,
without skips. Existing CI discovery executes the new file. Local acceptance
also requires clean packaging, 73 Rust tests and all existing verification
scripts. Remote evidence must match the eventual reviewed commit.

Tests cover exact joint publication, legacy preservation, full anchored history
recovery, context and frozen-value rejection, missing/corrupt bytes, and 20
SIGKILL boundaries. They verify atomic receipt incorporation and loss of the
final acknowledgment. Payloads remain intentionally opaque. An external
expected-head test demonstrates both rollback detection with a trusted
checkpoint and its absence without one. No physical power-loss claim is made.
