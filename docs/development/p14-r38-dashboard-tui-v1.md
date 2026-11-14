# P14-R38 · Tablero TUI interactivo de desarrollo A1–A10

**Base material:** R37, PR #108, commit `9e4c166297a3b87b52d664ce651d61b18e7c9399`.
**Ámbito:** exclusivamente presentación; no modifica A1–A10, clasificación A6, P8, diario, red, procesos ni máquinas virtuales.

## Alcance e interacción

- `--tui`: monitor `curses` de tres paneles cuando hay espacio: etapas, detalle, auditoría. Diseño adaptable a terminales medianas y compactas; admite terminal monocromo.
- `--tui-clasica`: conserva la TUI R28/R37 original con páginas. `--texto` y `--json` permanecen sin modificación de semántica y siguen siendo aptos para comparación de bytes.
- ↑/↓ o `j/k` navegan por etapas. Con foco en el detalle, ↑/↓ desplazan sus líneas. ←/→ o `h/l` cambian la etapa. `1`–`9` y `0` saltan a A1–A10.
- `Tab` cambia el foco. `d` expande el detalle. `F1`/`?` abre ayuda; `F2`/`c` vista compacta; `F3`/`/` búsqueda local; `F4`/`f` alterna filtro de asuntos pendientes; `F5`/`s` alterna resumen. `g/G` primera/última etapa, `r` redibuja sin hacer trabajo nuevo y `q` sale.
- En búsqueda, `Enter` confirma, `Escape` cancela y retroceso elimina un carácter.
- La información A6 importada indica **admisión documental**, huella de soporte y fuente declarada. Nunca acredita una máquina, prueba efectiva, CVSS/EPSS ni `Rf` final.

## Invariantes

Antes de abrirse, el tablero rechaza reporte incompleto, orden distinto de A1–A10 o afirmación `GO`, despacho, observación de VM, riesgo final o publicación A9 en el contrato de desarrollo. El CLI previamente verifica la integridad global del ciclo R37 (`verify_development_cycle`). La capa de UI no recalcula ni altera hashes. El rótulo `VISTAS: 10/10` cuenta pantallas disponibles; **no** expresa conformidad total de los diez algoritmos.

El monitor **no** invoca un comando del sistema, lee archivos, inicia temporizadores, vuelve a importar fuentes ni crea diarios. Es una visualización reactiva a teclado de un reporte congelado. Las unidades mostradas son DEV sintéticas cuando el origen del reporte así lo indica.

## Verificación

```sh
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r38*.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14*.py'
python3 -B scripts/verificar_trazabilidad_actual.py
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --preview --texto
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --preview --json
```

Para inspección interactiva ejecutar **sin tuberías**:

```sh
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --preview --tui
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --preview --tui-clasica
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --preview --import-defensive-receipt lab/p14-r37-a6-defensive-import-v1/synthetic-receipt.json --import-defensive-support lab/p14-r37-a6-defensive-import-v1/synthetic-support.txt --as-of-utc 2026-11-14T20:00:00Z --tui
```

## Estado

R38 no adelanta AL-06 ni AL-07. La aceptación funcional integrada y el experimento de la tesis continúan pendientes. La transición hacia evidencia física acreditada es un incremento distinto y exige autorización, fuentes y oráculos verificables.
