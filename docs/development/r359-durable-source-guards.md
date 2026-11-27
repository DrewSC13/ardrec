# Guardas desde estado durable / Durable-state source guards

## Espa??ol

R359 recupera el estado nativo con DurableStore y una huella
HEAD proporcionada por el llamador. No acepta un estado
global arbitrario como sustituto de la recuperaci??n.

Distingue estado confirmado, candidato, intentos pendientes,
contadores incorporados, revisi??n temporal y conciliaci??n.

Las guardas se vinculan con el HEAD, el estado recuperado
y la fuente espec??fica. A1 deriva la disponibilidad l??gica
del diario. A8 conserva indeterminados los criterios cuya
procedencia t??cnica no est?? acreditada.

El archivo anal??tico opcional exige una huella independiente
y conserva el alcance efectivo de validaci??n existente.

La apertura usa los bloqueos y sincronizaciones del almac??n
nativo; no modifica el contenido l??gico del diario ni publica
generaciones. Los recibos de pruebas son sint??ticos.

La custodia externa, frescura y autoridad f??sica permanecen
pendientes. No se habilita despacho ni se confirma Rf.

CLI:
python -m ardrec.coordination.durable_source_guards --help

## English

R359 recovers native state through DurableStore and a
caller-supplied HEAD pin, instead of accepting an arbitrary
global state as a substitute for recovery.

It distinguishes confirmed and candidate states, pending
attempts, incorporated counters, temporal review and recovery.

Guard facts are bound to HEAD, recovered state and their
specific source. A1 derives journal quiescence. A8 preserves
unknown criteria whose technical origin is not established.

The optional analytical archive requires its own supplied
pin and preserves the existing validation scope.

Opening uses native storage locks and synchronization,
without modifying logical journal content or publishing
generations. Test receipts are synthetic.

External custody, freshness and physical authority remain
pending. No dispatch or confirmed Rf is enabled.
