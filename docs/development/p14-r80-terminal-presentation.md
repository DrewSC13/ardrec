# ARDREC R80 — Presentación selectiva de terminal, R79 y monitor R38

**Objeto:** entrada única de presentación de **solo lectura**, con vistas seleccionables
por parámetros, sin curses ni ejecución física. Fuente: merge R79
`6e5047b7d13cd3e4060febd67db3edb7eb26aa1d`.

La utilidad `scripts/ardrec_p14_r80_terminal_presentation.py` consume
R75 (recibo original), R76 (puente tipado), R78 (sensibilidad matemática)
y R79 (recorrido académico). Antes de imprimir cualquier información, lee
JSON canónicos privados (0600, propietario y padre 0700), reconstruye R79
mediante el verificador existente, valida los enlaces a R75/R76/R78 y mantiene
las restricciones P8. No obtiene información técnica de firmas sin testigo
independiente ni modifica el monitor original.

## Vistas disponibles

- `--vista resumen`: datos sintéticos, límites de acreditación y recibo.
- `--vista etapas`: los diez algoritmos, sus fuentes y descripción.
- `--vista etapa --etapa A7`: explicación focal para cualquiera de A1–A10.
- `--vista familias [--protocolo SSH|FTP|SMB]`: tabla de fracciones exactas,
  sobre las 25 familias o un protocolo seleccionado.
- `--vista familia --familia FTP-T01`: origen de reclamo, intervalo y
  tres puntos contrafactuales, nunca `Rf` confirmado.
- `--vista evidencias`: encadenamiento de seis identificadores SHA-256.
- `--vista r38`: instantánea original R38 de 152 columnas y 36 líneas
  procedente del recibo R75 validado.
- `--vista todo`: resumen, 25 familias e integridad en una sola salida.

Todo texto se produce en stdout sin guardar archivos. `--vista` exige un valor
de la lista; opciones incompatibles, familias desconocidas y cualquier deriva
de una fuente son rechazadas. La aplicación opera como usuario no root desde
el repositorio principal y no ejecuta subprocesos.

## Ejemplo para presentación

```zsh
cd /home/cicada/Development/GitHub/ardrec
function ardrec_r80_mostrar() {
  emulate -L zsh
  local lab='/home/cicada/ardrec-lab'
  PYTHONPATH=src python3 -B scripts/ardrec_p14_r80_terminal_presentation.py \
    --receipt-dir "$lab/r75-demo-20261118T035215Z-241956" \
    --r76-report "$lab/r76-demo-20261118T115635Z-6283/report.json" \
    --r78-report "$lab/r78-demo-eTecV3I2/report.json" \
    --r79-report "$lab/r79-demo-OYgVyte7/report.json" \
    --vista "$1" "${@:2}" | more
}
ardrec_r80_mostrar resumen
ardrec_r80_mostrar etapa --etapa A7
ardrec_r80_mostrar familias --protocolo SSH
ardrec_r80_mostrar familia --familia SSH-T01
ardrec_r80_mostrar r38
unfunction ardrec_r80_mostrar
```

Los datos de R75 (tres servicios durables), de R76–R78 (25 familias) y del
escenario sintético A2 (54 unidades) tienen poblaciones distintas; no son 54
observaciones ni 25 pruebas reales. Los escenarios `E=0,1/2,1` son
**contrafactuales**, no mediciones. R77 conserva únicamente atribución
criptográfica documental sin pin de autoridad externo. Continúan
`A6=ND`, `Rf confirmado=null`, `A8=0`, `A9 GEN2=0`,
`system_functional_acceptance=PENDING`, `experimental_validation=NOT_RUN`,
y `P8=NO-GO`. Los requisitos físicos F11 y la autorización siguen pendientes.
