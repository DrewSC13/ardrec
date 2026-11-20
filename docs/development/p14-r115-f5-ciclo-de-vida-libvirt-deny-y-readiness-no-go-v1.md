# P14 / R115-F5 — Ciclo de vida libvirt, DENY y preparación A3 (solo lectura)

## Contexto factual que motivó la implementación

En Prometheus, el 20 de noviembre de 2026, R115-F4 confirmó las huellas de
`root-recover.py` y el hook F11. El modo `--attest-deny` terminó con
`host_command_failed_virsh` al solicitar las seis vinculaciones dinámicas.
La lectura posterior, realizada sin modificar el laboratorio, demostró:

- R34 nftables: `MATCH` con la política de denegación esperada.
- Cuatro dominios: `shut off` (runner, SSH, FTP y SMB).
- Cuatro XML de VM: accesibles; seis interfaces previstas en sus definiciones.
- Las seis consultas `nwfilter-binding-dumpxml`: enlace inexistente; 0/6 vínculos
  dinámicos porque **no había interfaces de invitados en ejecución**.

La ausencia de un vínculo dinámico al estar apagada su VM no prueba una
configuración dañada. Tampoco acredita aislamiento operativo para una futura
ventana de tráfico. La política nftables, las definiciones de dominios y los
vínculos dinámicos son fuentes distintas con ciclos de vida distintos.

## Cambio R115-F5

`r115_f5_lifecycle_readiness.py` hace lecturas **actuales** y no mutantes de
nftables, huellas del recuperador y F11, estado/XML de las cuatro VM, inventario
`nwfilter-binding-list` y los seis `nwfilter-binding-dumpxml`. Emplea solo
comandos fijos con `sudo -n`, tras la autenticación interactiva explícita del
operador en la terminal habitual. Reutiliza el validador de nftables exacto del
recuperador R113-F6 previamente fijado por SHA-256 y los validadores de
identidad de R112/R113.

La evaluación distingue:

| Estado | Condiciones | Significado |
|---|---|---|
| `OFFLINE_DENY_BASELINE_MATCH` | Cuatro VM OFF, cero vínculos de esas seis TAP, XML coincidentes, nftables DENY y hashes F11/F6 | Estado apagado esperado **en el instante observado**, NO-GO |
| `RUNNING_SIX_DENY_BINDINGS_MATCH` | Cuatro VM RUNNING, seis bindings DENY con identidad correlacionada, hashes y nftables coincidentes | Atestación de vínculos de denegación en marcha, **no concede tráfico** |
| `DRIFT_NO_GO` | Configuración o vínculo presente distinto de lo esperado | Revisión de deriva obligatoria |
| `INCOMPLETE_OR_TRANSITION_NO_GO` | Estados mixtos, consulta ilegible, vínculo faltante con VM activa o lectura sin evidencia suficiente | No se infiere éxito ni se repite ninguna acción |

Las cuatro categorías conservan A5=`NO-GO`, A6=`ND`, P8=`NO-GO`,
`SCOPE_APPROVED=ND`, `LAB_ISOLATION_CONFIRMED=ND` salvo deriva material,
`DESTINATION_AUTHORIZED=ND` y `CLIENT_COMPATIBLE=ND`. La guarda
`SERVICE_READY=FALSO` cuando el runner o FTP están apagados. La ejecución
no valida credenciales, protocolo FTP, orden de autorización ni disponibilidad
real del servicio.

Un `OFFLINE_DENY_BASELINE_MATCH` **no** sustituye el check F11/F34/R113
inmediatamente después de un arranque autorizado. El operador debe pasar por
la autoridad acotada, la precondición de arranque aprobada, la conciliación de
libvirt y las seis vinculaciones efectivas antes de cualquier ventana P8.

## Salida, seguridad y recuperación

- Código probado por separado y con regresión, sin VM ni sockets en el entorno
  de desarrollo. No hay cambios al recuperador root ni a F1–F4.
- Recibos privados nuevos bajo `/home/cicada/ardrec-lab/r115-f5-lifecycle-deny-v1/`,
  con archivos exclusivos `0600`, manifiesto SHA-256 y hora UTC por lectura.
- `sudo -v` es explícito, interactivo y NO se encadena a `more`; las lecturas
  posteriores usan `sudo -n` sin ampliar permisos.
- No se llama `--restore-deny`, `nwfilter-binding-create`, `virsh start`,
  `virsh domif-setlink`, `nft -f`, QGA ni comandos de red.
- Si una lectura falla o las fuentes están incompletas, la captura se conserva
  con `ND` y `NO-GO`. No se cambia un identificador para ocultar reintentos.
- El siguiente incremento significativo es completar la autoridad independiente
  con raíz de confianza instalada por un actor autorizado, revocación vigente,
  preparación FTP/cliente y un ciclo A5–A10 autorizado, con generación confirmada.
  R115-F5 no realiza esa integración.

## Trazabilidad

Contrato: tesis Cap. III A3/A5/A6/A9; R112 (NIC/redes); R113-F6 (DENY,
recuperación, seis bindings); R115-F1 (contrato P7 DEV); F2 (fuentes actuales);
F3 (identidad y autoridad documental); F4 (lectura privilegiada); F5
(lifecycle sin mutación). El histórico NO-GO de R114 queda inalterado.
