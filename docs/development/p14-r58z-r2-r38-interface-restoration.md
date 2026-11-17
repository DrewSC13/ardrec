# ARDREC P14-R58-Z-R2 — Restauración del tablero oficial R38/R42.5

## Corrección

R58-Z (source-only) introdujo por error una TUI monocromática simplificada de
solo dos paneles que no respeta el diseño visual elegido del sistema.
Se conserva íntegramente la persistencia documental R58-Z y la base R58-Y.
El modo `--tui` del CLI R58-Z usa ahora el **monitor R38** existente mediante
`r58z_r38_dashboard_adapter.py`. El motor de paneles, navegación, búsqueda,
filtros y resaltado es `dashboard_tui.py`, reutilizado sin modificaciones.

La TUI original R38 muestra tres paneles adaptables: ALGORITMOS, DETALLE y
ESTADO / AUDITORÍA. Se conservan 1..9/0 para A1..A10, j/k, cursores,
Tab, F1–F5, `?`, `/`, `f`, `s`, `q`. Se añade `v` (servicio siguiente)
y `V` (servicio anterior). **1, 2, 3 ya no cambian servicios**, pues son
accesos directos a A1–A3, como en el diseño aprobado.

El adaptador transforma una sesión documental verificada R58-Z en un informe
**estrictamente de presentación** que el renderizador R38 admite. Los
estados A1–A10 son los del documento fuente, NO los de un ciclo ejecutado.
La pantalla declara siempre `P8=NO-GO`, `A5 SIN INICIO`, `A6=ND`, `Rf NO`
y `A9 NO PUBLICADA`. El registro físico SSH es histórico, no una prueba
A5/A6. Los servicios FTPS/SMB permanecen sin observación.

## Sin alcance operativo

No se modifica `dashboard_tui.py`, R42.5, las máquinas virtuales, P8,
la validación física R42.2/R42.3, los registros SQLite R58-Y ni la
instantánea documental R58-Z. No existe recolección de red ni ejecución
A5 al pulsar teclas. Los modos `--texto`, `--json`, `--snapshot` y
`--verify` siguen usando exactamente el mismo núcleo R58-Z.

## Uso (Konsole interactiva; NO enviar curses a `more`)

```sh
cd /home/cicada/Development/GitHub/ardrec
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58z_workspace.py --tui
```

## Verificación

```sh
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58z_r38_adapter.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58z_workspace.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r38_dashboard_tui.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r425_classic_evidence_dashboard.py' -v
```

El parche se aplica a la rama local `feat/p14-r58z-verified-workspace`,
con base `5a477100a8c754d6c307357c9091b751725d448d`. No crea commit
ni PR ni merge, para permitir revisión humana de los cambios.
