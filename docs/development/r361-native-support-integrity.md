# Integridad material de soportes / Material support integrity

## Espa??ol

R361 extiende la procedencia nativa R360 con la verificaci??n
material de los soportes declarados en recibos incorporados.

El manifiesto se vincula mediante una huella suministrada
separadamente al informe de procedencia. Cada entrada conserva
la identidad del caso, condici??n, intento, solicitud, resultado,
generaci??n, evento y referencia de par??metros efectivos.

Los soportes se almacenan bajo nombres derivados de SHA-256.
La lectura utiliza descriptores propios, no sigue enlaces,
verifica propiedad, permisos, tama??o, identidad y contenido.

Los l??mites iniciales son 1 MiB por soporte, 64 MiB por
manifiesto y 4096 entradas. Son l??mites de implementaci??n,
no l??mites derivados de las ecuaciones de la tesis.

La ausencia de un soporte se conserva expl??citamente.
Los soportes alterados o vinculados a recibos ajenos se rechazan.

La cobertura representa las referencias declaradas por los
resultados documentales. No representa autom??ticamente los
requisitos de aceptaci??n de una familia t??cnica.

Los bytes verificados no demuestran origen f??sico, par??metros
efectivos ni verdad t??cnica. A6 permanece ND.
AL-06 y AL-07 contin??an abiertos; P8 permanece NO-GO.

## English

R361 extends R360 native provenance with material verification
of supports declared by incorporated receipts.

The separately pinned manifest binds provenance, case, condition,
attempt, request, result, generation, incorporation event and
effective-parameter reference.

Supports use SHA-256-derived filenames. Descriptor-based reads
reject links and check ownership, permissions, size, identity
and contents.

Initial implementation limits are 1 MiB per support,
64 MiB per manifest and 4096 entries.

Missing supports are represented explicitly. Altered supports
and foreign receipt bindings are rejected.

Coverage describes references declared by documentary results,
not automatic fulfillment of technical family requirements.

Verified bytes do not establish physical origin, effective
parameters or technical truth. A6 remains ND.
AL-06 and AL-07 remain open; P8 is NO-GO.
