# R281 — Reapertura histórica por unidad

`estudio --archivo-piloto ... --unidad-replay PILOT-FTP-01 --texto`
reconstruye R278 antes de proyectar una unidad. La huella del informe R278
no cambia. La salida presenta la decisión A8, el rechazo T1 nativo y la
primera guarda en el orden de bloqueos archivado, no una prioridad
operacional nueva. Vincula I1, I2, plan, prerregistro y referencias nativas.
El estado operacional actual queda ND; no se despacha ni se publica A9.

## English

Per-unit historical replay after full source-bound R278 reconstruction.
The legacy report remains unchanged. The first archived blocker is not a
new live authorization or runtime guard precedence. No dispatch or publication.
