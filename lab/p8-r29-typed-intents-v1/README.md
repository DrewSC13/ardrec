# ARDREC P8-R29 — Validación tipada de declaraciones simbólicas (29 perfiles)

Modelo determinista de **diseño**, exclusivamente source-only; no es traductor de CLI ni autoriza pruebas de penetración. Anclado mediante SHA-256 a las matrices públicas R1/R10/R13/R15 y a los verificadores heredados R17/R23/R24/R26. El recibo privado R27 y el informe R28 se mencionan únicamente por SHA-256; **la CI no los lee**.

Cada perfil mantiene una operación semántica distinta, una secuencia exacta de nombres de referencias materiales (sin valores), sus controles protocolarios obligatorios, sus precondiciones, soportes de aceptación, once o nueve vínculos documentales de control y riesgos asociados. Las cinco variantes de escritura requieren `VERIFY_THEN_REMOVE_MARKER`, preparación de fixture y confirmación de limpieza. La función `review_declaration` rechaza campos extras como `argv`, `command`, `secret`, `authorization`, `dispatch_allowed`, rutas o banderas libres; si la declaración simbólica coincide, devuelve **DENY** de todos modos.

Los 348 campos materiales siguen nulos, las 261 barreras de prueba runtime siguen sin verificar, y no existen opciones CLI ni `argv` aprobados. La fuente SSH R27 es un **grafo candidato basado en bytes observados**, no la configuración efectiva. FTP 10 y SMB 11 tampoco tienen afirmaciones de capacidad operativa. P8 permanece abierto, AL-06/AL-07 pendientes; P9 y A1–A10 no iniciados.

CI: `python3 -B lab/verify_p8_r29_typed_declaration.py` y `python3 -B -m unittest discover -s lab/tests -p test_p8_r29_typed_declaration.py -v`.

**EN:** Immutable public symbolic design constraints for 29 profiles. All valid symbolic declarations remain denied. No runtime, VM, client invocation, authorization, secrets, or command rendering.
