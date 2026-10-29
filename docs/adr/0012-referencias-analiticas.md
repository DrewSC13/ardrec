# ADR 0012 — Referencias analíticas / Analytical references

## Español

Estado: componente implementado, pendiente de aplicación local e integración.
Base: PR #20, `79d58794ed75e9ec422d5178a93e1d60de393b02`.
Fuente revisada: tesis SHA256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
secciones 3.2.1, 3.3.1–3.3.4 y 3.9.10.

La proyección del PR #20 almacena referencias. El nuevo módulo resuelve las siete
referencias de cada servicio contra un manifiesto fijado por una huella externa.
Primero verifica el manifiesto y su correspondencia exacta con todas las proyecciones;
después solicita los objetos por SHA256 y comprueba bytes canónicos, identidad,
función, servicio, registro, invocación, configuración y generación de origen.
Solo devuelve el conjunto completo como bytes inmutables; no repara ni sustituye
objetos faltantes. Una generación de origen anterior puede reutilizarse explícitamente
en generaciones posteriores de la misma invocación. Objetos futuros se rechazan.

Los formatos son `ardrec-analytical-object-1` y `ardrec-analytical-references-1`.
El manifiesto contiene `format`, `context` y `bindings`; cada vinculación contiene
`service_scenario_id`, `role`, `reference`, `sha256`. El contexto contiene registro,
invocación, configuración y generación. Cada objeto contiene `format`, `context`,
`service_scenario_id`, `role`, `reference` y `payload`.
Las funciones son characterization, evidence_repository, execution_counters,
objective_status, history, convergence_window y pending_controls.

Decisiones de implementación versionadas: máximo 896 objetos / 128 servicios,
256 KiB por objeto o manifiesto, 8 MiB para el conjunto, profundidad JSON 32,
enteros entre −(2^63−1) y 2^63−1. Generaciones no negativas y no booleanas.
El límite de bytes puede alcanzarse antes que el límite de objetos. JSON canónico
ASCII con claves ordenadas, sin flotantes ni duplicados. Racionales grandes pueden
representarse mediante cadenas decimales; este módulo no valida su significado.
Las vinculaciones están ordenadas por servicio y función, y sus identidades son
únicas dentro del manifiesto. Son restricciones de esta versión, no cifras de la tesis.

`load_object(sha256)` entrega bytes o `FileNotFoundError`. La disponibilidad demostrada
es la entrega de esos bytes, no su durabilidad en disco. El anclaje del manifiesto en
`DurableStore` y el adaptador de almacenamiento aún no están conectados. Calcular la
huella de un manifiesto no lo convierte en autoridad: la huella esperada debe provenir
de una fuente confiable que esta API no establece ni autentica.

Las cargas son objetos JSON opacos: no se validan todavía esquemas de evidencia,
revisiones, contadores, objetivos, historial, ventanas, controles ni caracterización.
Un campo `authorized: true` no habilita guardas. `check_operational_alignment` compara
las proyecciones con fases y contexto de la parte confirmada del modelo operacional,
sin convertir autoridad ND en VERDADERO ni confirmar una candidatura. La simulación
se rechaza en esa función. La resolución y esta comprobación son operaciones separadas.

Se añaden 27 pruebas; total esperado 302 en Python 3.14.7. La CI existente las descubre.
Los resultados del PR #20 son antecedentes aportados por el usuario, no pruebas de este
incremento. Persistencia existente, Rust y matrices históricas permanecen sin cambios.
AL-06 y AL-07 siguen abiertos: faltan semántica, estado global completo, guardas desde
fuentes verificadas, publicación integral y recuperación, perfiles/autorizaciones/soportes
externos y autenticación del par. AL04-R01/R02/R03 siguen bloqueando el ejecutor real.
El punto 1, la aceptación funcional y la validación experimental no se declaran completos.

## English

This component resolves all seven references per service against an externally pinned
manifest. It verifies canonical bytes, SHA256, role, identity, context and origin
generation, returning an immutable complete set. Older objects can be explicitly reused
within one invocation; future, missing or inconsistent objects are rejected.

Limits are versioned implementation choices: 896 objects, 128 services, 256 KiB per
object/manifest, 8 MiB per set, depth 32 and signed integer magnitudes up to 2^63−1.
Large rationals can use decimal strings, whose semantics are not validated here.
The provider supplies bytes; storage durability and a trusted manifest anchor remain
unconnected. Payload claims do not become authorization or effective guards.
Operational alignment checks confirmed context and phases without promoting authority.

Twenty-seven tests are added; the expected total is 302 under Python 3.14.7. Existing
persistence and Rust remain unchanged. AL-06/AL-07 remain open for domain semantics,
complete global state, sourced guards, durable publication/recovery, external references
and peer authentication. Point 1, system acceptance and experimentation remain pending.
