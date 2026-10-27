# Verificación de magnitudes / Magnitude verification

## Español

Este incremento atiende AL-05 y AL-09 desde la base
`00f4d8e40e11b90a615e8b3fc603aba0dc6c194d`.
El [ADR 0009](../adr/0009-magnitudes-analiticas.md) define formato, límites y recuperación.
La [ampliación de trazabilidad](../traceability/exact-magnitudes-v1.json) conserva vínculos
con AC-02, AC-20 y sus algoritmos futuros, sin marcar estos algoritmos implementados.

| Verificación | Evidencia reproducible | Alcance |
| --- | --- | --- |
| Persistencia | 22 métodos en `test_magnitude_persistence.py` | Racionales/ND, límites, reapertura, corrupción, exclusión y fallos |
| Caída del proceso | 6 puntos SIGKILL dentro de un método | Temporal, escritura, fsync del archivo, antes/después de renombrar y fsync del directorio |
| Paridad numérica | `python scripts/verificar_magnitudes.py` | 520 casos: 420 aceptados, 100 rechazados; igualdad de bytes con oráculos |
| Regresión Python | `PYTHONPATH=src python -m unittest discover -s tests/unit -v` | 242 métodos previstos: 220 previos y 22 nuevos |
| Regresión operacional | `python scripts/verificar_protocolo.py` | 3052 comparaciones previas; dominio operacional conservado |
| Calidad Rust | Formato, compilación y Clippy con warnings prohibidos | Incluye la nueva característica serde_json y la sonda |

El corpus tiene semilla 20261026 y huella SHA256
`68848ada4e6948c849cb05eaf4ffe389a2495c8f33247aa4817e8ac2dc641c32`.
Contiene valores frontera, denominadores superiores a 64 bits, fracciones negativas,
ND, 192 fracciones generadas de forma determinista y variantes malformadas. Los resultados
válidos se construyen con enteros y Fraction independientes de ambos lectores; los
rechazos son expectativas explícitas. Comparar solo Python contra Rust no sería suficiente.
La aceptación de todos los casos no es una demostración exhaustiva de todos los documentos.

Los fallos de publicación verifican que un objeto previamente confirmado permanece
intacto y que una escritura interrumpida produce ausencia u objeto íntegro. Un objeto
renombrado antes del fallo se recupera mediante validación y sincronización. Se comprueban
fallos reales simulados de `os.write` y `os.fsync`, escrituras cortas, reintentos explícitos,
sesiones invalidadas y bloqueo entre procesos independientes. La referencia puede calcularse
antes de publicar: conocerla no constituye evidencia de durabilidad.

El instalador comprueba los bytes de partida, ejecuta pruebas y guarda registros fuera
del repositorio en `ardrec-patches`. Solo crea el commit firmado tras superar las pruebas.
El empaquetado y la comprobación Rust de base se ejecutan sobre el commit limpio; ante
un fallo posterior se conserva ese commit sin publicarlo. La CI añadida ejecutará el
contraste numérico sobre cada PR y sobre main. Su resultado remoto se confirma después.

Estados separados: componente implementado; verificación local exigida; integración
remota pendiente; aceptación funcional del sistema PENDING; validación experimental NOT_RUN.
A1–A10, protocolo experimental y prototipo operativo no se ejecutan en estas pruebas.
El estado analítico integral, su incorporación a generaciones, la autoridad de referencias
y los hallazgos AL-04/AL-06/AL-07 requieren incrementos posteriores.

## English

This increment addresses AL-05 and AL-09 from baseline
`00f4d8e40e11b90a615e8b3fc603aba0dc6c194d`. ADR 0009 defines format, limits and recovery;
the traceability supplement links AC-02/AC-20 without claiming their future algorithms.

Verification comprises 22 new Python methods, six SIGKILL boundaries, 520 numerical
cases (420 accepted, 100 rejected), the expected 242-method Python suite, 3052 existing
operational protocol comparisons, and Rust formatting/build/Clippy checks. The deterministic
corpus seed is 20261026; its SHA256 is
`68848ada4e6948c849cb05eaf4ffe389a2495c8f33247aa4817e8ac2dc641c32`.
It includes exact boundaries, wide denominators, negative fractions, ND, 192 generated
fractions, malformed input and size limits. Integer/Fraction oracles are independent of
the readers, and rejection expectations are explicit. Case parity is not an exhaustive proof.

Crash tests preserve earlier confirmed objects and require absent-or-complete publication.
An object renamed before a crash is recovered through validation and synchronization.
Injected write/fsync errors, short writes, explicit retries, poisoned sessions and separate
writer processes are exercised. A computable reference alone does not establish durability.

The installer checks baseline hashes, runs tests and preserves logs in ardrec-patches,
then creates a signed commit. Packaging and Rust baseline checks run on the clean commit;
a subsequent failure preserves that commit without publication. Added CI checks numerical
parity on PRs and main; remote outcomes must be confirmed separately.

Implementation, local verification, remote integration, system acceptance and experiments
retain separate states. Global functional acceptance is PENDING; experimental validation
is NOT_RUN. A1–A10 and the operational prototype are not started. Full analytical state,
generation incorporation, reference authority and AL-04/AL-06/AL-07 need later increments.
