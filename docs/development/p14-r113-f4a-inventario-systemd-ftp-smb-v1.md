# R113-F4A — Diagnóstico local de unidades FTP y SMB

**Naturaleza:** inventario de solo lectura mediante ejecución acotada en invitados QGA.

**Antecedente:** R113-F3T `6ac8342393063f1ee3d600007eb9e6f15965b8c9`; manifiesto privado `08ff65f60f3967276e03ef9f47f24ea21ee574e095c0c07f304d91426b63afd0`. En F3T SSH escucha en TCP/22; FTP y SMB no escuchan en TCP/21 ni TCP/445. La ausencia de escucha no demuestra ausencia de software instalado.

## Ejecución autorizada

Cuatro procesos locales en total, dos por VM: `/usr/bin/systemctl list-unit-files --type=service --no-legend --no-pager --plain` y `/usr/bin/systemctl list-units --all --type=service --no-legend --no-pager --plain`. No se ejecutan comandos en SSH ni runner y no se usa shell.

La inspección valida previamente la evidencia F3T, los controles físicos F11/R34 y la identidad MAC/IP desde QGA. Se escribe un marcador exclusivo antes de cada `guest-exec`; cada respuesta completa se persiste antes de clasificarla. Ante error o indeterminación, se detiene la sesión; no se realizan reintentos automáticos ni restauraciones implícitas.

## Interpretación conservadora

Una unidad listada indica presencia en el catálogo de systemd o en su estado cargado, no acredita por sí misma versión, configuración, paquete instalado ni disponibilidad de puerto. La ausencia de una unidad listada es `NOT_OBSERVED_IN_SYSTEMCTL`, no `NOT_INSTALLED`. En ningún caso se afirma que R113-F4 haya autorizado comunicación, que A5–A9 estén acreditados o que P8 pueda avanzar.

## Evidencia y replay

Los originales `capture-<rol>-<consulta>.json`, marcadores, instantáneas antes/después, clasificación, recibo y manifiesto se conservan bajo `/home/cicada/ardrec-lab/r113-f4a-service-inventory-v1/` con directorios `0700` y archivos `0600`. El replay sin QGA vuelve a verificar hashes, alcance y procedencia F3T y reproduce las clasificaciones con los bytes originales.

**Siguiente paso:** con el inventario real decidir intervención mínima sobre servicios únicamente con autorización independiente; el firewall permanece en DENY y P8 en NO-GO.
