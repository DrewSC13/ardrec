# R113-F6R — Corrección del empaquetador F5 (stderr vacío)

**Incidente fuente:** R113-F6, commit `f5e79dd5adb99579bbc87d8715e476eea2d882a0`. El ensamblador de recuperación se detuvo antes del staging root con `PRIVATE_FILE_INVALID_binding_a33d30r.stderr`. El archivo proviene del preflight F5, donde el comando tuvo éxito y `stderr` vacío queda autenticado por `SHA-256(epsilon)` en el manifiesto F5 fijado. No existe fallo de captura de datos.

## Alcance mínimo

- Permitir tamaño cero **únicamente** para capturas `*.stderr` cuyo directorio padre es el F5 fijado; el manifiesto F5 con SHA-256 fijado autentica cada archivo, incluso los vacíos.
- Seguir rechazando stdout, XML, manifiestos y archivos del bundle vacíos; rechazar permisos distintos de 0600, enlaces duros, simbólicos y tamaños excesivos.
- Resolver el paquete `ardrec` desde `src/` del propio repositorio para ejecutar el empaquetador directamente, sin PYTHONPATH externo.
- No cambiar `root-recover.py`, el staging root, la semántica DENY, los XML físicos ni el manifiesto F5.
- No reejecutar el instalador F6 original. F6R agrega una regresión propia, genera un nuevo bundle y exige replay antes de cualquier autorización root.
- No se autorizan tráfico, reglas ALLOW, VM guest-exec, inicio de servicios, push ni merge. `P8=NO-GO`.

## Continuación

Tras el commit firmado F6R y el replay del bundle: autorización independiente para instalación root, auditoría read-only DENY, y otra autorización distinta para reaplicar DENY físico. Todo fallo conserva recibos y se detiene sin reintento automático.
