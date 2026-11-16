# ARDREC R58-A / FTP — integración de CI (F3)

Esta fase modifica únicamente el workflow Python de CI, añade una prueba de presencia del gate y documentación de procedencia. No hay ejecución ni modificación de host, nftables, libvirt, systemd, VM ni tráfico.

## Referencias fijadas

- Base histórica: `be7bc497bbbb45b585ac308066d6ff08b07775bd`
- Commit firmado local FTP F2: `6e8f95843e4ad2747056d8e6a7216493b0042e65`
- Rama: `feat/p14-r58a-ftp-nic-readonly`
- Workflow remoto base (Git blob SHA-1): `5fd2ee88a8afa79c4ad68ad8105c2bec04b625a4`
- Pruebas FTP F2: 55 casos aprobados localmente en Prometheus.

## Control

Se añade un único step inmediatamente posterior al R56 para ejecutar `test_p14_r58a_ftp_*.py` bajo el job `python` de pull request. La suite adicional comprueba la presencia y colocación de ese step, el mantenimiento de los jobs Python/Rust y la ausencia de comandos físicos en el nuevo step. No implica atestación física ni aceptación A6/A9.

**F11-P**: habilitación observada, primera ejecución no acreditada. **FTP**: solo candidata XML en memoria; requiere transición física y recuperación independiente antes de aplicar. **P8**: NO-GO. **Validación experimental**: NOT_RUN.

## Privacidad de publicación

La consulta GitHub del 15 de noviembre de 2026 devolvió visibilidad `public` para `DrewSC13/ardrec`. El operador había indicado mantenerlo privado. Por ello F3 es deliberadamente local y no hace `git push`, PR ni merge. Verificar y resolver visibilidad antes de publicar esta rama.
