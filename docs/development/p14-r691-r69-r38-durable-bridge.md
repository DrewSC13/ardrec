# ARDREC P14-R69.1 · Enlace de la sesión durable al monitor R38

**Base:** merge R69 PR #164, `08415a83fdc0b21491881d4234790c017ac35773`.

## Problema y decisión

R69 introdujo `run_dev_tui` (una pantalla plana temporal) aunque el proyecto ya disponía del tablero **R38**, con tres paneles, búsqueda, filtros, F1–F5, teclado directo y modo compacto, ampliado por R42.5/R59H. El modo `--tui` de la sesión durable abría la vista equivocada.

## Cambio mínimo

El mismo `--tui` de `python -m ardrec` y de `scripts/demo_p14_r28_a1_a10_tui.py`, cuando recibe `--durable-dev-root`, ahora usa `dashboard_tui.run_dashboard_tui` (R38) con un adaptador de lectura `durable_dashboard_bridge.build_durable_dashboard`.

- Construye una vista del **documento R69 recuperado**. Verifica sus huellas, enlace al caso, reglas R68, configuración, estado PREPARADO y referencia de generación confirmada.
- A1 muestra las decisiones calculadas por R68 y su contexto; A2 muestra la configuración de la generación 0; A9 muestra la generación **inicializada** y el HEAD durable. No confunde ese hecho con **publicación analítica posterior**.
- A3–A8 y el ciclo A10 completo quedan señalados como no ejecutados en la ruta durable R69. No se superpone la vista histórica R28 como si perteneciera a la misma generación.
- El motor de renderizado, navegación, foco, resaltado y controles de R38 permanece sin duplicarse; solo consume datos del adaptador.
- `--texto` y `--json` de R69 mantienen los mismos bytes; `--tui-clasica` de R28 conserva el comportamiento heredado como modo explícito, sin convertirse en modo por defecto.
- El contrato bloquea reportes alterados, publicaciones no acreditadas, autoridad falsa, riesgo final fabricado y pines no vinculados. No añade llamadas físicas, acciones de red, acceso a VM ni escritura desde la interfaz.

## Ejemplo no privilegiado

```sh
cd /home/cicada/Development/GitHub/ardrec
PYTHONPATH=src python3 -B -m ardrec --durable-dev-root /home/cicada/ardrec-lab/r69-dev-tutor-001 --tui
```

Cerrar con `q`; las teclas F1–F5, Tab, flechas, 1–0 funcionan como en R38. La sesión se recupera antes de abrir la interfaz. Una segunda apertura tiene el mismo recibo y diario de la generación inicial.

## Pruebas y no-alcance

R69.1 aporta 14 oráculos, incluido un PTY con curses real y retorno normal con `q`. Se ejecutan además las regresiones R69, R38, R28, R67, R68 y R42.5. El instalador comprueba la base, SHA-256, miembros de ZIP, árbol local, remoto y ámbito antes de aplicar.

**No cierra A3–A10, publicación analítica posterior, uso de SSH/FTP/SMB físico, riesgo final, piloto ni muestra experimental. P8=NO-GO.** R70 conserva como objetivo el ciclo analítico real y la recuperación multigeneracional. Los hashes de las vistas se derivan, pero no otorgan confianza externa a un origen no acreditado.
