# P14 / R58-Z — A10: sesión documental recuperable basada en observaciones físicas R58-Y

## Identidad y alcance

Base de desarrollo: commit SSH local `5a477100a8c754d6c307357c9091b751725d448d` de R58-Y, rama `feat/p14-r58y-observation-register`, no integrada aún a main. Los seis archivos de R58-Y se mantienen intactos. La verificación de firma en GitHub está pendiente: no impide la continuación **source-only**, pero debe resolverse antes de aceptar el merge protegido.

Nuevo comando `scripts/ardrec_p14_r58z_workspace.py`: lee **el mismo registro privado real** R58-Y y vuelve a ejecutar su validador de recibos R42.2/R42.3 antes de construir un reporte A10 de *observación*, con estado de A1–A10 por servicio. No vuelve a usar fixtures de sesión R26 ni intervalos matemáticos sintéticos como si fuesen hallazgos reales. Crea opcionalmente un testigo documental canónico, inmutable y content-addressed, que se recupera y compara contra los recibos originales tras cerrar el proceso.

### Funcionalidad implementada

- Identidades R58-Y intactas, orden estable, recuentos por servicio, fecha declarada de captura, hashes SHA-256 y resúmenes seguros del estado de la NIC.
- SHA-256 canónico del reporte de observación; persistencia privada con exclusión de enlace simbólico, permisos 0600, exclusión de sobrescritura, fsync de archivo y directorio e idempotencia de lectura.
- `--snapshot`, `--verify`, `--texto`, `--json` y `--tui` sobre el mismo origen autenticado. Vista A1–A10 por servicio con selección SSH/FTPS/SMB. La fuente R58-Y solo admite SSH; FTPS/SMB se muestran sin observaciones verificadas.
- Si se pierden o cambian los recibos privados después de guardar, la reapertura falla cerrada; igual ante alteraciones de copia, identidad, procedencia, estado ND, o falsificación de resultados.
- **A5 sin intento vinculado; A6=ND; A7 sin Rf confirmado; A9 sin publicación; P8=NO-GO**. El testigo R58-Z **NO ES UNA GENERACIÓN A9**. No interpreta ausencia de paquetes como prueba de aislamiento ni como ausencia de vulnerabilidad.

## Uso en Prometheus / Zsh

Desde `/home/cicada/Development/GitHub/ardrec`, tras aplicar el ZIP:

```
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58z_workspace.py --snapshot
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58z_workspace.py --verify
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58z_workspace.py --texto --service SSH --stage A10 | more
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58z_workspace.py --tui
```

El SQLite fuente predeterminado es `/home/cicada/ardrec-lab/r58y/observations.sqlite3`; el directorio nuevo privado es `/home/cicada/ardrec-lab/r58z`. Ningún archivo privado se publica en GitHub. El CLI exige raíz del repositorio; no instala, arranca ni consulta máquinas virtuales, no modifica nft/libvirt/systemd y no cambia el estado de P8.

## Pruebas y límites

19 pruebas nuevas en entorno aislado Python 3.13 con un sustituto controlado del importador físico R42.4, sobre el **código real R58-Y suministrado**: 19 PASS. La prueba directa con el registro SSH privado de Prometheus y toda la regresión deben ejecutarse por el operador. El parche CI suma una prueba aislada R58-Z y deja las suites preexistentes.

La construcción del informe no es la coordinación operacional A10 de los diez algoritmos; es una **vista A10 de observaciones existentes** con estados de aceptación explícitos. Los estados marcados como no vinculados son ausencia de artefactos acreditados en este contrato, no prueba global de inexistencia de ejecuciones fuera de él.

## Próximo incremento funcional

Vincular un verdadero recibo de intento A5 (reserva/aceptación/inicio/resultado) generado por el runner autorizado con la condición declarada y su soporte, y ejecutar el contrato A6 con procedencia y testigos independientes. Solo entonces alimentar A7 y A9 operacional. En paralelo, F11 debe demostrar las barreras físicas de host antes de desbloquear FTPS/SMB.
