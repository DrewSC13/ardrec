# R262 — Selección adaptativa prospectiva

Se reutiliza el selector exacto A4 existente.

Los casos no elegibles se excluyen antes del cálculo.
Si un caso elegible tiene una prioridad indeterminada,
no se selecciona arbitrariamente otro caso del conjunto.

ND no equivale a cero. Las prioridades completas se
recalculan mediante el selector nativo y sus desempates.

Consulta / Review:

    python -m ardrec estudio --prioridad-piloto ARCHIVO --sha256 HUELLA --texto

Las entradas prospectivas no conceden autoridad operacional.
La selección analítica no inicia A5 ni confirma A6, Rf o A9.

Weights remain unfrozen. Operational dispatch and
experimental admission remain disabled.
