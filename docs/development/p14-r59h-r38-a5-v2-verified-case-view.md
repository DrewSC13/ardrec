# ARDREC R59-H — Vista R38 de caso A5 v2 reabierto (solo lectura)

## Alcance operativo

Incremento aditivo: el motor `dashboard_tui.py` de R38 y el adaptador R58-Z-R2
permanecen intactos. R59-H agrega una forma opcional de abrir en la TUI de tres
paneles un recibo A5 v2 de R59-F y su evaluación modelo R59-E, verificando
primero la persistencia privada de los tres directorios A5/A6/v2. Mantiene las
observaciones R58-Y/R58-Z como fuente histórica separada.

## Comandos

En la raíz de la rama y sin modificar el host:

```bash
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59h_tui_case_view.py --verify
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59h_tui_case_view.py --render --service FTPS --stage A5 --width 120 --height 32
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59h_tui_case_view.py --render --service FTPS --stage A6 --width 120 --height 32
PYTHONPATH=src python3 -B scripts/ardrec_p14_r59h_tui_case_view.py --tui
```

Se utilizan como valores por defecto únicamente los archivos ya producidos por
R58-Y y R59-F; se aceptan rutas privadas alternativas explícitas. R38 conserva
navegación A1-A10, selección de servicios v/V, F1-F5 y tres paneles en 120x32.
La captura `--render` es una representación textual verificable para pruebas
sin terminal interactiva. `--tui` requiere TTY real.

## Semántica de evidencia

Un `NO_START` no es un intento real; el resultado, familia, variante, soporte
y estado de reglas se presentan como datos declarados y verificados en el
almacén privado, **no** como verdades técnicas operacionales. Una clasificación
hipotética del motor P7 no es A6 acreditada. Se mantienen `A5 físico=NO`,
`A6=ND`, `Rf=None`, `A9=None`, `P8=NO-GO`. La TUI no contiene `sudo`, comandos
libvirt, nftables, SSH, FTP o SMB, red ni lanzamiento de intentos.

## Limitaciones y comprobaciones

R59-H verifica todas las fuentes al abrir el visor. El contenido visual es una
instantánea: no afirma observar cambios posteriores en tiempo real. No acredita
arranques de VM, no ejecuta pruebas de penetración y no modifica ningún dato de
los recibos. Antes de cualquier ejecución física debe acreditarse F11 y el
P8 autorizado por separado. Las pruebas locales usan un sustituto de R38
solo para contratos de visualización; las regresiones en Prometheus usan su
motor R38 auténtico.
