# R379 — Vinculación de instantáneas DEV / DEV snapshot binding

## Español

R379 añade una entrada de recuperación explícitamente vinculada
a una huella de instantánea, registro, ejecución, configuración,
generación e inventario de caracterizaciones esperadas.

Reutiliza AnalyticalArchive y la resolución nativa de referencias.
No cambia formatos históricos de persistencia ni sus escritores.

Para este perfil DEV se exige PREPARADO, prioridad vacía,
magnitudes ND con motivos exactos, caracterización de generación
cero y referencias dinámicas de la generación solicitada.

Se rechazan documentos ajenos, inventarios incompletos o
duplicados, caracterizaciones alteradas y magnitudes promovidas.

El pin esperado debe suministrarse externamente al lector.
La integridad de una huella no demuestra por sí sola su custodia,
autenticidad, vigencia o independencia humana.

Esta interfaz no acredita la semántica operacional completa
de las cargas referenciadas ni identidad efectiva de servicios.
No se usa como autorización para despacho.

AL-06 y AL-07 permanecen abiertos.
A6 ND; Rf no confirmado; A9 no publicado.
P7 sin congelar; P8 NO-GO.

Las pruebas CI son sintéticas. La reproducción privada R378
se verifica separadamente en el laboratorio del operador.

## English

R379 adds explicit snapshot binding for non-operational DEV
review archives. It binds the expected snapshot digest, record,
execution, configuration, generation and characterization set.

Existing native archive and reference resolution mechanisms
are reused without changing historical persistence formats.

PREPARADO, empty priority and exact ND reasons are required.
Frozen characterization objects originate at generation zero;
dynamic references must originate at the requested generation.

Foreign contexts, missing or duplicate services, altered
characterizations and numeric magnitude promotion are rejected.

External custody, freshness, effective service identity and
full operational payload semantics remain outside this proof.

No authorization, dispatch, confirmed risk, operational
publication or experimental admission is produced.
AL-06 and AL-07 remain open; P8 remains NO-GO.
