# Cierre acotado de AL-05 y AL-09 / Scoped AL-05 and AL-09 closure

## Español

Sobre main `0efec398fa72403aeda4cb98fe8783db22fcf57d`, se revisaron los criterios
originales de AL-05 y AL-09 frente al componente integrado en el PR #16.
Ambos hallazgos se cierran dentro de su alcance original: formato y persistencia
de magnitudes individuales, y contrato delimitado de intercambio Python/Rust.
El punto 1 permanece EN CURSO. AL-04, AL-06 y AL-07 siguen abiertos.

El [registro por criterio](alignment-resolution-v1.json) enlaza pruebas concretas,
huellas y ejecuciones CI. La [revisión original](alignment-current-v1.json) y
las matrices históricas conservan su contenido; sus estados corresponden al momento
de su elaboración. Esta resolución registra la disposición posterior de dos hallazgos.

| Hallazgo | Evidencia | Límite |
| --- | --- | --- |
| AL-05 | Formato versionado, racionales/ND exactos, integridad, reapertura, exclusión y seis puntos SIGKILL | No confirma generaciones analíticas completas |
| AL-09 | 520 casos contra oráculos: 420 aceptados y 100 rechazados; igualdad de bytes canónicos | No demuestra aritmética del modelo ni ecuaciones de A7 |

La compatibilidad se conserva mediante formatos separados: no se amplían enteros
operacionales ni se reinterpretan sus registros. No existe una migración de objetos
analíticos previos que ejecutar; una conversión futura requiere versión explícita,
comparación exacta y preservación del original. Versiones desconocidas se rechazan.

La CI del PR #16 es [40431825584](https://github.com/DrewSC13/ardrec/actions/runs/40431825584)
y la de main es [40432151051](https://github.com/DrewSC13/ardrec/actions/runs/40432151051).
El aplicador vuelve a consultar identidad, intento, trabajos y pasos obligatorios
antes de registrar el cierre. Esta evidencia es del flujo y de sus pasos; no se
presenta como informes individuales archivados por método. Las 242 pruebas Python,
los 520 casos numéricos y las 3052 comparaciones operacionales son conjuntos distintos;
no se suman para declarar aceptación del sistema.

AL-06 conserva la obligación de representar el estado analítico completo, integrar
magnitudes en generaciones y verificar invariantes y guardas con sus fuentes.
AL-07 conserva autoridad, pertenencia e integridad de referencias y autenticación.
AL-04 conserva causalidad, UTC, duración y reinicio. Capacidad y retención globales
requieren la integración del estado. AC-02 y AC-20 siguen parcialmente cubiertos.
A1–A10 y el prototipo no se han iniciado; la validación experimental no se ha ejecutado.

Las garantías se limitan al Linux local y propietario confiable del ADR 0009.
SIGKILL representa caída del proceso, no corte físico de energía; el corpus finito
no es demostración exhaustiva. El cierre documental requiere publicación e integración.

## English

At main `0efec398fa72403aeda4cb98fe8783db22fcf57d`, original AL-05/AL-09 gates were
reviewed against PR #16. Both findings close within their original scope: exact
individual-magnitude persistence and delimited Python/Rust numerical interchange.
Point 1 remains IN PROGRESS; AL-04, AL-06 and AL-07 remain open.
The JSON record links each gate to concrete checks, hashes and CI runs. Historical
reviews retain their original contents; this record supplies subsequent disposition.

AL-05 covers versioned exact rational/ND records, integrity, reopen, writer exclusion
and six SIGKILL boundaries. Compatibility uses separate formats with unchanged
operational integer limits/readers. No nonexistent prior analytical migration is
claimed; future conversions need explicit versions and preserved originals.
AL-09 covers canonical bytes and independent expectations for 520 cases (420 accepted,
100 rejected), not model arithmetic. The installer rereads the CI runs linked above,
checking exact identity, attempt, jobs and mandatory steps. This is workflow/step
evidence, not archived individual-method reports. The 242 Python tests, 520 numerical
cases and 3052 operational comparisons are distinct sets, not additive system acceptance.

AL-06 retains full analytical state, generation integration and source-backed guard
and invariant checks. AL-07 retains reference authority and authentication; AL-04
retains temporal semantics. Capacity and retention need full-state integration.
AC-02/AC-20 remain partial. A1–A10 and the prototype are not started; experiments have
not run. Local Linux/trusted-owner limitations apply; SIGKILL is not physical power
loss and finite tests are not exhaustive. This documentation still requires integration.

## Asociación de CI posterior al merge / Post-merge CI association

Español: la consulta recibida devuelve `pull_requests: []` en la ejecución del PR16.
La ausencia de esa asociación no se toma como fallo de CI ni como prueba suficiente.
Se exigen el ID exacto de ejecución, workflow 388831308, evento, rama y commit; se
verifican por separado identidad, cabecera, base y merge del PR16, firmas y padres.
Si la lista contiene una asociación, debe coincidir exactamente con PR16 y sus
commits. Una contradicción o una lista malformada detiene la revisión.

English: the observed PR16 run returns `pull_requests: []`. That absence is neither
CI failure nor sufficient evidence. Verification requires the exact run ID, workflow
388831308, event, branch and commit, plus independently verified PR16 identity,
head/base/merge and signed commit parents. Present associations must match PR16
and its commits exactly; contradictions or malformed lists stop the review.
