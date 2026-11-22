# R130 / B17-R6 — Instalación independiente de B4 y B9

## R6A — Contrato de admisión de fuentes

Base de fuente: `7cee2ebf7a27475dbfc77619edf40f82db17949b`.

Se valida el ZIP privado B17-R5b por digest exacto, estructura ZIP,
archivos con permisos 0600, cinco entradas permitidas, bytes fijados
de R126-B4/R128-B9 y manifiestos fuente todavía no autorizados.

El resultado es solamente una evaluación reproducible. Una afirmación
de GitHub dentro del archivo no constituye, por sí sola, una firma
de autoridad operacional.

No existe modo `--apply` en R6A. No ejecuta sudo, root,
nftables, libvirt, systemd, sockets ni administración de claves.

## R6B — Instalador transaccional pendiente en esta misma rama

Implementar, someter a revisión y probar un instalador raíz
independientemente autenticado. Requisitos obligatorios:

- Autoridad Ed25519 externa para instalación, distinta de las
  autoridades de alcance, tráfico y revocación.
- Claves públicas de confianza provisionadas por un operador
  independiente, con política root y permisos estrictos.
- Verificación de firma, vigencia, revocación y unión al HEAD,
  fuentes exactas, destino, operación y manifiestos.
- Instalación por árbol privado 0700, archivos 0600,
  fsync, manifest de recibo y publicación atómica.
- Protección ante sustitución de archivos, carrera TOCTOU,
  symlinks, permisos incorrectos y estados parciales.
- Inyección de fallos, pruebas de crash/replay y rechazo de
  reinstalaciones no autorizadas.
- Prohibición de ejecutar scripts desde un checkout mutable.
- Sin claves privadas generadas automáticamente.
- La instalación por sí sola no habilita tráfico ni confirma
  FTP-T01, A6, A9 o restauración física.

R116-F1 y R116-F3 permanecen intactos.

P7=DRAFT, A6=ND, P8=NO-GO.

## R6A-CI1 — Corrección de rutas privadas

Se sustituye la comparación exacta `type(path) is Path` por
`isinstance(path, Path)` para admitir objetos `PosixPath`.

Se preservan las comprobaciones de ruta absoluta, enlace simbólico,
propietario, permisos, número de enlaces, tamaño, lectura mediante
`O_NOFOLLOW` y detección de sustituciones durante la lectura.

Se incorporan pruebas negativas para enlaces simbólicos, permisos
inseguros, enlaces físicos y directorios no privados.

La validación de un ZIP de revisión no concede autorización root.

## R6B1 — Verificación Ed25519 y staging privado

El módulo `r130_b17_r6_signed_stage` implementa una revisión
criptográfica real con Ed25519 y OpenSSL.

Verifica la vinculación del HEAD, árbol Git, ZIP R5b,
hashes de R126-B4/R128-B9, destinos declarados,
ventana de aprobación, identidad de arranque,
revocación y separación de dos firmantes.

Los documentos de prueba utilizan exclusivamente
claves efímeras generadas durante las pruebas unitarias.
Estas claves no son autoridades operacionales.

La validez de una firma no demuestra que la clave pública
haya sido provisionada por un operador independiente.
La exclusión de los firmantes operacionales tampoco está
acreditada en este incremento.

Por lo tanto, `root_install_authorized=false` permanece
obligatoriamente en todos los resultados.

El staging privado utiliza:

- Directorio propiedad del usuario y modo 0700.
- Creación exclusiva de archivos con modo 0600.
- Escritura completa y fsync.
- Publicación del candidato mediante rename.
- Preservación del directorio incompleto ante fallo inyectado.
- Rechazo de destinos de revisión preexistentes.

No hay instalación root, configuración de nftables,
inicio de máquinas virtuales ni ejecución FTP-T01.

## R6B2 — Pendiente

Implementar el agente root independiente con confianza
preinstalada, exclusión de autoridades operacionales,
autenticación del host, comprobación actual de revocaciones,
instalación durable y recuperación de transacciones parciales.

R116-F1 y R116-F3 permanecen inalterados.

P7=DRAFT.
A6=ND.
A9=NO_PUBLICADO.
P8=NO-GO.

## R6B2 — Compatibilidad Linux PosixPath de B4/B9

Se identificaron dos errores de validación de rutas:

- R126-B4, función `safe_read`.
- R128-B9, función `read_root`.

Ambas funciones utilizaban una comparación exacta
`type(path) is Path`, incompatible con objetos `PosixPath`.

Se crean nuevas fuentes candidatas sin modificar los
archivos originales integrados mediante B16.

Cambios exactos:

1. Sustituir `type(path) is Path` por
   `isinstance(path, Path)` en B4 y B9.
2. Actualizar el SHA-256 B4 incorporado en la fuente B9.

Se preservan las rutas root, la identidad del ejecutor,
el guardián R116, su SHA-256, los límites temporales,
la semántica de autorización y las restricciones de red.

Las nuevas fuentes se acompañan de un lock canónico
con los hashes históricos y los hashes candidatos.

El lock no es una aprobación ni un manifiesto operativo.
Las fuentes nuevas aún no están integradas mediante
un commit firmado y no tienen release independiente.

El archivo ZIP R5b histórico permanece intacto.
No debe utilizarse para instalar las fuentes V2.

La instalación root transaccional, la autoridad externa
y la ejecución física FTP-T01 siguen pendientes.

P7=DRAFT.
A6=ND.
A9=NO_PUBLICADO.
P8=NO-GO.

## R6B3 — Núcleo transaccional privado del instalador

El código R130-B3 comprueba los hashes de las fuentes
R126-B4 V2 y R128-B9 V2 y su lock histórico canónico.

Construye los manifiestos candidatos con:
`approved_head=null`, `root_install_independent=false`
y `root_staged_independently=false`.

Registra los nombres de archivos que exigen los ejecutores
originales y los destinos root fijos. No inventa concesiones,
permisos, revocaciones ni materiales de confianza.

La preparación de prueba usa un directorio privado 0700,
archivos 0600, bloqueo cooperativo mediante flock,
escrituras exclusivas, fsync y un solo rename para publicar
ambas fuentes como una unidad de revisión.

La inyección de fallos se prueba después de B4, después de
B9 y antes de la publicación. Los estados incompletos
se conservan y no se publican.

Se añaden pruebas funcionales que comprueban la aceptación
de objetos PosixPath en los lectores root V2. Las pruebas
se realizan con archivos propiedad del usuario y comprueban
el posterior rechazo por metadatos no root.

Este mecanismo NO constituye una transacción privilegiada
de los dos destinos root reales. Para esa operación serán
necesarios un agente autónomo instalado por un operador
independiente, release firmado sobre HEAD definitivo,
exclusión de firmantes operacionales, revocación fresca y
protocolo de recuperación ante publicación parcial.

No se han instalado controladores, activado redes, armado
temporizadores de sesión ni ejecutado FTP-T01.

A6=ND. A9=NO_PUBLICADO. P8=NO-GO.

## R6B3-CI1 — Prioridad de rechazo root

Se detectó una discrepancia en el orden de validaciones
de `private_parent()` durante la prueba de UID 0.

Antes de la corrección, la función comprobaba primero
la propiedad del directorio y emitía
`PRIVATE_PARENT_REQUIRED`.

La función corregida rechaza primero cualquier
ejecución con UID 0 mediante
`ROOT_EXECUTION_FORBIDDEN`.

Las comprobaciones de ruta absoluta, enlaces simbólicos,
propietario y permisos 0700 permanecen activas.

No cambia ninguna autoridad, revocación, fuente B4/B9
ni política de control de tráfico.

La transacción de R6B3 continúa siendo exclusivamente
una preparación privada de revisión, sin instalación root.

A6=ND. A9=NO_PUBLICADO. P8=NO-GO.
