# R267 — Controlador nativo de preejecución

Vincula los expedientes I1, I2, I3, I6 e I7 con el
prerregistro, selección prospectiva y núcleo matemático.

Utiliza GlobalState, TransitionContext y el códec
nativo sin crear autoridad física ni iniciar A5.

El estado es explícitamente de revisión, simulation=True
y authority=ND. T1 se rechaza mediante la máquina nativa.

No se crea una generación operacional A9. La recuperación
documental del estado no equivale a publicación operacional.

## Consulta / Review

    python -m ardrec estudio --controlador-piloto DIRECTORIO --sha256 HUELLA --texto

Los datos privados permanecen fuera del repositorio.

No physical dispatch, operational publication or
experimental admission is granted by this controller.
