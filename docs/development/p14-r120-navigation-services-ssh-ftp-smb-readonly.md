# ARDREC R120 — Navegación por servicios SSH / FTP / SMB, SOURCE_ONLY

## Alcance

La TUI R38/R119 conserva A1–A10 y ofrece una segunda vista `SERVICIOS` con
SSH (8 familias), FTP (8 familias) y SMB (9 familias). Las 25 familias, sus
condiciones, precondiciones, soportes mínimos y límites interpretativos se
derivan exclusivamente del catálogo P7 versionado, fijado por SHA-256 en el
contrato F14. No se inventan casos ni resultados.

## Controles

- `F6` o `v`: alternar ALGORITMOS/SERVICIOS en la captura R119.
- `a`: volver a A1–A10.
- En SERVICIOS, `↑/↓`: cambiar SSH/FTP/SMB; `1/2/3`: selección directa.
- En SERVICIOS, `←/→` o `[` y `]`: cambiar la familia seleccionada.
- `Tab` conserva los focos originales; `F1` despliega ayuda; `q` sale.
- En modo ALGORTIMOS, se preservan las teclas existentes, incluido `1..9,0`.
- Los accesos `F3`, `F4` se mantienen para la vista de algoritmos.

## Datos y semántica

La cabecera identifica la vista, el servicio y la familia. El detalle muestra
los estados capturados de la VM, su definición, las interfaces, runner, nft y
F11. Estos valores proceden del recibo de captura R115-F5, que puede ser
una reproducción histórica. Un estado `OFF`, `ND` o `MATCH` no acredita una
prueba de explotación ni es autorización operativa.

Para cada familia aparecen el identificador, la tabla de la tesis, la condición
técnica, la acción mínima **documental**, las precondiciones declaradas y
los soportes requeridos. El catálogo mantiene `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`,
`execution_enabled=false`, `catalog_frozen=false`. Los diarios F13/F14
seleccionados para FTP, cuando existen, se muestran como candidatos, nunca como
evidencia física admitida.

La vista no modifica ninguna guarda, credencial, autoridad, archivo de
persistencia, regla nft, máquina virtual, socket o estado de A1–A10.
A6 permanece `ND`, Rf `ND`, A9 sin nueva generación y P8 `NO-GO`.
La lógica de navegación es pura; la captura o reproducción ocurre antes de
entrar en la TUI.

## Verificación

La suite `test_p14_r120_service_tui.py` cubre 36 pruebas unitarias: selección
de 3 servicios, 25 familias en orden, navegación con teclas, no-regresión de
A1–A10, 2 anchos de terminal, integridad del catálogo, rechazo de autoridad
falsa y ausencia de llamadas de captura durante navegación. CI exige el mínimo
36 y conserva R119, R118, R117, R38 y demás checks existentes.

Este incremento resuelve únicamente la navegación por servicio y sus familias.
No autoriza aún pilotaje físico, A6 positiva, recálculo confirmado ni generación
A9 publicada. Para una ejecución real continúan siendo necesarias las
autorizaciones específicas y la validación operacional independiente.
