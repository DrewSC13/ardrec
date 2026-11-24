# R187 - Sensibilidad parametrica

## Alcance

Evaluacion matematica hipotetica basada en las expresiones
de la tesis para beta, lambda y w. Se reutiliza el oraculo
exacto A7 existente sin modificar sus formulas.

## Diseno

Tres perfiles hipoteticos y 17 configuraciones.
Se modifica un solo grupo de pesos por vez.

Los dos pares beta se mantienen independientes.
Lambda y w conservan pesos positivos y suma unitaria.

Se registra la variacion exacta de evidencia, prioridad y
riesgo candidato, ademas de cambios de relaciones de orden.
Las relaciones de orden no equivalen a seleccion operacional.

## Analisis complementarios

Se propone un comparador contextual (R0 + C normalizada)/2.
Se calculan contrafactuales sin contribuciones positivas,
sin sustituciones negativas y sin ambos componentes.

Estas propuestas requieren revision y congelamiento previo.
No sustituyen el contraste principal de la investigacion.

No se utilizan valores Rref para seleccionar pesos.
No se generan resultados experimentales ni autorizaciones.

## Reproduccion

Desde la raiz del repositorio:

    uv run --no-sync python -B -m ardrec.experiments.parameter_sensitivity --texto

    uv run --no-sync python -B -m ardrec.experiments.parameter_sensitivity --json

A6=ND; Rf confirmado=ND; P7 pendiente; P8=NO-GO.
