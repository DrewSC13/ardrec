# R126–R129 | Una rama, cuatro etapas, integración de fuente y aceptación operacional separadas

**Repositorio base:** `DrewSC13/ardrec` — `7c1bf90c36b17ace9b670b360b6c183770297bec`, PR #209 fusionado.

## Principios

- P7 actual: `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`; P8 físico: `NO-GO`; A6: ND; A9: ninguna generación.
- Fuente y autorización son autoridades distintas. La aprobación documental F15 no abre red ni arranca VM; el estado DENY de R124 tampoco.
- No hay cuatro PR intermedios: la rama local `feat/p14-r126-r129-integrated-physical-pilot` concentra el incremento y se somete a un único PR protegido **después de aprobar los controles de integración de fuente**. La aceptación física y matemática sigue un proceso independiente.
- El parche crea código y tests; no instala ni activa servicios raíz, no genera firmas de producción, no hace sockets, no arma el guardián y no publica A9. Deben presentarse recibos auténticos antes de declarar funcionalidad física.

## R126 — Autoridad y control operacional

Se reutiliza `r115_f15_p7_independent_pilot.signed_pilot_review` con sus rutas de confianza de root; se vinculan las revisiones R124 y R125 a un `head` común. El informe R126 es un *handoff fail-closed*, nunca una autorización de tráfico. Falta un **controlador raíz independiente** que obligatoriamente valide permiso firmado nuevo, revocación fresca, ciclo de vida 5/1 y comprobación del watchdog antes de conceder una ventana operacional. No reutilizar R117/F5B como permiso.

## R127 — Prueba de recuperación real

El verificador Ed25519 exige un testigo de cierre independiente, confianza raíz instalada en `/etc/ardrec/r127-root-closure-witness-v1.json`, firmante separado de las autoridades de alcance y revocación; hash exacto de R116, readbacks R124 pre y post, SHA del recibo real `restore-*.json`, identidad de arranque y reloj monotónico. La prueba debe incluir caída forzada del ejecutor bajo una autorización piloto específica. El cierre DENY puede dejar las máquinas en topología 5/1 DENY o cerrarlas en 0/6 DENY. El límite de aceptación es ≤60s, objetivo técnico ≤45s. **Una traza sintética de test no acredita cierre físico**, aunque su firma de prueba sea matemáticamente válida.

R116 escribe el nombre del recibo `restore-<primeros 16 hex del SHA del contenido>.json`, no `restore-<id de armamento>.json`; la inspección debe comparar el digest completo de bytes y no inferir el vínculo de sesión desde el nombre. Una restauración DENY puede terminar después del vencimiento; debe medirse hasta la lectura física final.

## R128 — FTP-T01 / A5

`r128.prepare` comprueba identidad de F13 y presupuesto F12 antes de reservar. `r128.reserve_prepared` llama a F13 para registrar **una sola reserva irreversible**, sin conexión. `r128.reconcile` revisa F13/F14 y, cuando está disponible, verifica la prueba R127 anclada de forma independiente. La ejecución de la conexión FTP requiere la implementación y autorización separada del root controller de R126; no se considera realizada por usar `reserve_prepared`.

## R129 — A6→A10

La clasificación F14 sigue ND hasta verificar soporte de origen FTP y semántica técnica por autoridad independiente. `r129.reconcile` conserva el intervalo racional exacto R121/R58-E y la sugerencia A8 sin hacerla autoritativa. `store_private` crea un A10 inmutable de desarrollo y `verify_private` reabre las fuentes F13 y su manifiesto. No confundir este recibo privado con el HEAD de `DurableStore`. Cuando exista admisión A6 auténtica, la publicación debe invocar el **`DurableStore.publish` existente**, sometiéndose a sus guardas de CAS y transiciones; no implementar almacén paralelo.

## Integración de fuente y aceptación operacional posterior

La integración de código exige pruebas, firma válida, revisión y CI del commit exacto. Los puntos físicos y matemáticos enumerados a continuación constituyen criterios de aceptación operacional posterior y no deben declararse cumplidos por fusionar código. La autorización de fuente no concede permiso de tráfico, instalación root ni ejecución en laboratorio.

1. CI y pruebas R126–R129 en conjunto y regresiones R125–R115, F13/F14, motor matemático y persistencia.
2. Firmas independientes vigentes, revocación actual y root controller instalado en sistema aislado, no derivado de la TUI ni del checkout.
3. Testigo real de caída + cierre DENY ≤60s, SHA de recibo root, mediciones monotónicas, reinicio/fallo, relectura F11/R34/libvirt.
4. FTP-T01 legítimamente autorizado con presupuesto acotado y caso F13 irrepetible; evidencia de origen realmente independiente.
5. A6 técnico conservador, A7 racional exacto confirmado solo con soportes, A8 transición por guardas, A9 publicación CAS y recuperación A10; ND permanece ND cuando faltan soportes.
6. Posteriormente, P7 calibrado/congelado y extensión a SSH/SMB y las 54 **observaciones físicas**, no solo plazas planificadas.

**Estado de la entrega:** fuente local implementada y validada por pruebas; puntos físicos 2–6 pendientes de evidencia real. **Se permite integrar la fuente tras aprobar sus controles Git/CI; la aceptación física y matemática permanece pendiente. P8 continúa NO-GO hasta obtener autorización y evidencia operacional auténtica**.

## Corrección B1 — Entrada de autoridad F15 y solicitud sin firma

La inspección inicial informaba `DOCUMENTS_NOT_PRESENT` porque la CLI no
aceptaba contrato, autorización ni permiso piloto. **No demuestra la ausencia
física de esos documentos en Prometheus.** La CLI dispone ahora de:

- `--authority-metadata`: inspección exclusivamente de metadatos de rutas fijas
  de confianza y revocación F15/F7/F11 y del testigo R127; nunca autentica una firma ni otorga P8.
- `--unsigned-pilot-request --head HEAD --contract /ruta/privada/contract.json
  --request-output /ruta/privada/nueva-solicitud.json`: valida el contrato
  contra el catálogo P7, verifica HEAD actual y produce la solicitud sin firma
  F15; directorio de salida privado, escritura exclusiva 0600; no se modifica P7.
- `--inspect --head HEAD --capture /ruta/captura --contract /ruta/contract.json
  --authorization /ruta/autorizacion.json --pilot-permit /ruta/permit.json`:
  exige las tres entradas privadas y ejecuta `F15.signed_pilot_review` real
  con confianza y revocación de rutas raíz; rechaza documentos parciales.
  **Incluso con `DOCUMENT_SIGNED`, la concesión raíz queda `False` y el
  despacho `BLOCKED`.**

El HEAD actual de la rama sin confirmar es el commit R125; la solicitud
obtenida es exclusivamente documental. Tras un merge futuro cambiará el HEAD,
por lo que cualquier autorización vinculada a un commit anterior no debe
reutilizarse como permiso del nuevo ejecutor. El controlador raíz operacional
independiente, su instalación segura y la acreditación física siguen pendientes.

## B2 — R126 Scope V2 (nueva raíz documental; sin permisos)

El inventario real en Prometheus mostró únicamente autoridades de instalación
R117. Las antiguas rutas F6/F7/F11/F15 y la confianza R127 estaban ausentes.
No está permitido usar claves de instalación R117 para el piloto o para un
permiso P8. La versión anterior F6 además exige el commit histórico
`a652195a544a549dbad6a44120e3d447cf4d4994`, por lo que no puede autenticar
un candidato R126–R129 actual.

`r126_scope_v2` se conecta a F15 mediante un revisor independiente que exige
que `source_commit` coincida con el HEAD que se quiere autenticar. Usa dos
archivos nuevos, nunca el trust F6 antiguo:

- `/etc/ardrec/r126-ftp-t01-scope-trust-v2.json`: esquema exacto F3,
  dos claves públicas Ed25519 **diferentes** de autoridad de alcance y revocación.
- `/etc/ardrec/r126-ftp-t01-scope-revocation-v2.json`: revocación firmada
  sobre el digest de la autorización; vigencia de 30 segundos.

Ambos son materiales **provistos por un operador independiente** con
propietario root, modo 0600, sin symlinks, un solo enlace y directorio
`/etc/ardrec` privado. El verificador nunca crea claves privadas, firmas,
confianza raíz ni autorizaciones. El código del repositorio no debe ejecutarse
como root desde el árbol sin confirmar.

La función `scope_v2.review_scope` verifica el contrato canónico F1, el HEAD,
las firmas F3 y la revocación actual; `r126.signed_documents` pasa su resultado
a F15, que todavía exige un permiso piloto adicional con firmantes separados.
`VERDADERO` en Scope V2 describe **solamente una revisión documental**, no P8,
no privilegia arranque, no arma el guardián, no conecta sockets y no acredita A6.

El plan sin firma se obtiene en la rama mediante:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -B \
  scripts/ardrec_p14_r126_r129_integrated.py --scope-v2-plan \
  --head "$(/usr/bin/git rev-parse HEAD)" | /usr/bin/more
```

El HEAD de la rama actual corresponde al último commit R125 y NO autentica
el código R126–R129 aún sin confirmar. Antes de solicitar aprobación real,
crear un candidato firmado y revisable, mantener las firmas independientes y
actualizar cualquier autorización emitida para un commit anterior. En ausencia
de confianza vigente, todo despacho sigue `BLOCKED` y `P8=NO-GO`.

## B3 — R126 Window V2: ventana de tráfico firmada, vinculada a Scope V2

El módulo F11 histórico verificaba el alcance mediante F6 con un HEAD fijo
anterior. B3 no altera ese código histórico ni sus verificaciones: introduce
`r126_window_v2`, que verifica el **mismo formato F11** de ventana y revocación,
las **mismas firmas Ed25519** con sus separadores de dominio y el **mismo límite
F11** de un intento y una conexión, pero exige previamente el Scope V2 del
**HEAD exacto** y un permiso piloto F15 firmado y vigente. La ventana puede
restringir, nunca ampliar, el presupuesto aprobado del piloto.

La ventana B3 tiene vigencia máxima de **60 segundos** y revocación firmada
cuya antigüedad máxima es **30 segundos**, sin reintentos ni ampliaciones de
alcance. Un revisor operacional usa exclusivamente los materiales de confianza
root en `/etc/ardrec` a través de `review_current`; se exige separación
criptográfica de **seis claves públicas e identificadores** (scope,
revocación de scope, piloto, revocación de piloto, ventana, revocación de
ventana). No se aceptan fuentes de autoridad aportadas por el solicitante.

La CLI añade un modo de capacidades de solo lectura:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -B \
  scripts/ardrec_p14_r126_r129_integrated.py --window-v2-capabilities | /usr/bin/more
```

El modo `--window-v2-review` exige `--head`, `--contract`, `--authorization`,
`--pilot-permit` y `--traffic-window`; verifica el HEAD real y rechaza el árbol
sin confirmar. La revisión **no** arma un temporizador, no enciende VM, no
abre nftables, no conecta FTP, no concede P8 ni admite A6/A9.

### Bloqueos reales que siguen presentes

- Ninguna de las autoridades raíz Scope V2/F15/F11/R127 necesarias ha sido
  provisionada por una persona independiente en Prometheus. Las claves R117
  siguen siendo exclusivamente de instalación.
- Una ventana/documento F11 **no incluye por sí misma** el digest de la
  aprobación F15 en un recibo de root: se necesita un permiso raíz de sesión
  que vincule **ambos** documentos firmados, el HEAD, el caso F13 y la instancia
  única del guardián R116.
- Debe implementarse y desplegarse un supervisor root independiente que mida y
  verifique el retorno DENY después de una caída real, sin ejecutar código
  mutable del checkout como root. R127 no puede certificar ese hecho solo con
  pruebas unitarias.
- El controlador físico y la ejecución FTP-T01 de R128, el testigo de origen
  A6 y el commit transaccional A9 en DurableStore siguen pendientes.

B3 aporta **autenticación documental completa de la ventana** pero no es un
permiso operacional. `P8=NO-GO`, `A6=ND`, sin generación A9 y sin acciones
físicas de red o de VM. No se crea PR ni merge en esta fase.


## B4 — Guardián raíz autónomo de sesión (DENY-only; no instalado)

Archivo fuente: `scripts/ardrec_p14_r126_root_session_guard.py`; 38 pruebas
herméticas: `lab/tests/test_p14_r126_root_session_guard.py`. El script es
**autónomo** (no importa código del árbol editable de ARDREC) y soporta
`--capabilities`, `--preflight` y `--arm-deny`.

**No ejecutar `--arm-deny` desde el repositorio, ni instalar el script como root
por la aplicación del ZIP.** Las dos rutas privilegiadas requieren que un
operador independiente haya realizado un despliegue revisado y de solo lectura
para terceros en:

- `/var/lib/ardrec/r126-ftp-session-guard-v1/root-controller.py` (root, 0600);
- `/var/lib/ardrec/r126-ftp-session-guard-v1/manifest.json` (root, 0600,
  SHA-256 exacto del script y `approved_head` del commit firmado definitivo);
- manifiestos y documentos de contrato, alcance, permiso piloto y ventana
  root-owned en ese directorio, sin claves privadas;
- `/etc/ardrec/r126-root-session-trust-v1.json` y
  `/etc/ardrec/r126-root-session-revocation-v1.json` (root, 0600);
- confianza y revocaciones previamente exigidas por Scope V2, F15 y Window V2;
- guardián R116 inmutable anclado en SHA-256
  `c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7`.

B4 verifica Ed25519 con `/usr/bin/openssl` y descriptores anónimos `memfd`
(sin archivos temporales ni dependencia Python `cryptography`). Exige ocho firmantes Ed25519 distintos (alcance, revocación de alcance,
piloto, revocación piloto, ventana, revocación ventana, concesión raíz de
recuperación y revocación raíz); cuatro revocaciones firmadas y actuales;
identidad de sesión, destino FTP aislado 10.203.31.2:21, HEAD del manifiesto,
identificador de arranque, vigencia de hasta 60 segundos y mínimo de 46 s
disponibles. La acción de concesión debe ser **`ARM_DENY_BACKUP_ONLY`**;
`network_traffic_authorized=false` y `p8=NO-GO` son obligatorios.

`--preflight` verifica documentalmente y consulta `R116 --check`: exige 5
bindings DENY y 1 ausente (SMB OFF), sin alterar el host. `--arm-deny` solo
puede ejecutarse con el código instalado bajo ruta root exacta, después de
preflight y una segunda validación de vigencias. Antes de invocar el comando
raíz fijo de R116 reserva `attempt-consumed.once` con O_EXCL y fsync. Si
falla la orden o el temporizador, no se abre tráfico ni se permite reintentar
la misma sesión. Si funciona, reconfirma el temporizador concreto a los 45 s
y escribe un recibo raíz inmutable que vincula sesión, HEAD, hashes, boot ID
y tiempo monotónico; **no** es una prueba física de cierre ante caída.

La publicación del parche únicamente copia código, pruebas, CI y
documentación al repositorio: **no instala el servicio raíz, no provisiona
firmas ni claves, no arma el temporizador ni abre puertos**. El despliegue
exige autorización externa, commit definitivo firmado y revisión del bundle
privilegiado. Las aprobaciones R117 históricas no sustituyen autoridad de
tráfico. F13 y cualquier promoción A6–A9 quedan pendientes de etapas
posteriores. La prueba R127 exige observar la restauración física de DENY y
recibo independiente; las 54 unidades no son todavía casos ejecutados.

Capacidades sin sudo:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 -B scripts/ardrec_p14_r126_r129_integrated.py --root-deny-controller-capabilities | more
```


### B5 — Revisión de entrega al operador, sin despliegue raíz

B5 ancla el código fuente exacto del controlador B4 mediante SHA-256 y revisa
el estado de los **16 archivos de la única rama pre-PR**. Su paquete privado
se guarda bajo `ardrec-patches/b5-source-handoff-<sha256>` y contiene
`root-controller.py.source-only`, `manifest.json.draft` y `review.json`. El
manifiesto borrador **no satisface** `protected_root()` de B4:
`approved_head=null` y `root_install_independent=false`. No debe renombrarse
ni copiarse directamente a `/var/lib/ardrec`.

La preparación solo crea documentación y una copia de fuente para revisión;
no instala como root, no firma, no provisiona confianza, no abre tráfico, no
arma el temporizador y no adelanta P8. Las aprobaciones R117 no constituyen
aprobación FTP-T01. El operador independiente deberá revisar el futuro commit
firmado y producir un manifiesto operacional, una cadena de confianza fresca
y un artefacto raíz **distintos** de este borrador; la revisión de B5 no
atesta su existencia. La prueba física de restauración dentro de 60 s y la
cadena A6–A9 siguen pendientes.

Uso en Zsh sin sudo desde el repositorio principal:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/ardrec_p14_r126_b5_operator_handoff.py --review | more
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/ardrec_p14_r126_b5_operator_handoff.py --prepare | more
```


### B6 — Observación R127 real read-only y enlace R128→R129/A10

Se añade un observador ejecutable (`ardrec_p14_r127_failure_observer.py`)
que consulta exclusivamente `r124.inspect()` sobre el R116 instalado y,
cuando existe, lee el marcador raíz con la llamada de lectura fija permitida.
Tiene dos rutas: `--snapshot --head <commit>` para una única comprobación
DENY y `--watch --head <commit> --session <16hex>` para observar una sesión
**previamente armada por una autoridad independiente** en topología 5/1.
La observación queda limitada a 70 segundos y 90 muestras. Si R116 no está
armado, la ruta `--watch` termina antes de esperar. No se incluye ningún
comando para armar, matar procesos, arrancar VM, cambiar nft o abrir sockets.

Cada muestra conserva SHA-256 del informe R124 verificado, identidad de
arranque `/proc/sys/kernel/random/boot_id`, inicio y fin monotónicos y
estado de marcador/temporizador. Los informes se enlazan en una cadena SHA
reproducible y se guardan en una carpeta privada 0700 con archivo 0600,
`fsync` y rechazo de sustitución o alteración. `--verify-folder` reconstruye
el expediente sin consultar el host.

**Límite de evidencia:** la transición `timer active`→`inactive` puede deberse
al vencimiento, cancelación o a otro evento. El observador NO atribuye
causalidad, no demuestra un `SIGKILL` externo, ni certifica que DENY fuera
restaurado en <=60 s desde el armado real. R127 exige todavía testigo firmado
independiente, recibo de restauración del R116, identidad de boot y medición
monotónica desde el instante auténtico de armado. B6 conserva
`verified_physical_60s_restore=false`, `p8=NO-GO` y `a6=ND`.

R128 puede adjuntar opcionalmente el expediente B6 a su conciliación F13/F14,
pero exige el mismo HEAD y el identificador de sesión `session_id` F13 =
16 caracteres hexadecimales del marcador R116. R129 conserva el SHA de la
observación como **candidato no autorizado** y puede archivar las muestras
junto con R121/intake/report en A10 privado, reproducible y resistente a
alteraciones. No concede A6, no confirma `Rf`, no ejecuta A8 y no abre el
almacén global de publicación A9. Las 54 posiciones permanecen sin asignar.

Uso inicial, sin requerir topología 5/1 ni permisos operacionales (se necesitan
credenciales sudo solo para ejecutar las lecturas fijas R124):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r127_failure_observer.py --capabilities | more
sudo -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r127_failure_observer.py --snapshot --head "$(git rev-parse HEAD)" | more
sudo -k
```

`--watch` solo corresponde a un ensayo físico con una sesión que haya sido
armada después de revisión independiente y con permiso vigente: no ejecutarlo
para consumir tiempo o simular un piloto inexistente.

R126–R129 se mantienen en una sola rama sin PR/merge hasta que terminen las
cuatro etapas de implementación. La aceptación física de la versión definitiva
requiere un commit firmado y un despliegue autorizado, no un árbol sucio.

### B6-R2 — Almacén privado separado de parches

El observador R127 registra las muestras en `/home/cicada/.ardrec-r127-b6-observations-v1` (propiedad del usuario y modo 0700), no directamente en `ardrec-patches`, cuyo modo compartido puede ser válido para distribuir parches pero no para conservar evidencia privada. La creación de la carpeta de evidencia exige un directorio `/home/cicada` confiable, sin escritura de grupo u otros. Si ya existe, se comprueban propiedad, modo exacto 0700 y ausencia de enlaces simbólicos. Nunca se modifican automáticamente permisos de directorios existentes. Los expedientes siguen siendo **observaciones candidatas**: P8 NO-GO, A6 ND, sin afirmación de recuperación autónoma certificada.


### B7 — Ejecución integrada A5–A10 no autorizante y ensayos de interrupción

R128/R129 B7 conecta los componentes reales ya existentes: el diario F13 de
reserva irreversible y consumo de un socket **ya conectado**, revisión de
soportes F14, R121/R58-E para aritmética exacta con `Rf` no confirmado,
conciliación R128/R129 y archivo A10 privado con apertura y validación posterior.
La API `r128_r129_end_to_end.reconcile()` rehace los 10 bloques A1–A10 y
rechaza cambios de identidad, fuente, hash, clasificación o estado de
publicación; `persist_a10()` usa el archivo privado existente de R129 y vuelve
a abrirlo antes de reportar éxito. La CLI B7 acepta exclusivamente recibos
JSON canónicos, privados y aportados explícitamente. Nunca recibe un socket,
nunca abre uno ni llama al `DurableStore` global.

Las pruebas B7 **sí ejecutan el F13 real** (con socket IPv4/TCP falso en memoria)
y cubren saludo FTP 220, error FTP 421, respuesta malformada, cierre de
conexión, denegación/revocación entre lecturas, peer incorrecto, interrupción
tras reserva o tras consumo, doble intento, alteración de origen, fallo de
restauración del archivo A10 y falta de confirmación matemática. Son pruebas
de software y de tolerancia simulada a fallos, **no evidencia de ejecución
física, prueba de caída de Prometheus ni habilitación P8**.

R126–R129 continúan en una sola rama y no se crea PR hasta el cierre de la
implementación. La admisión de origen físico A6 y la publicación A9 necesitan
una autorización raíz independiente vigente, un controlador de ventana de
tráfico auditado y resultados físicos firmados; no se sustituyen con simulación.

Uso de capacidades, no privilegiado:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r128_r129_end_to_end.py --capabilities | more
```

### B8 — Un solo ejecutor físico R116-F3, sin doble conexión F13

La inspección root real en Prometheus confirma el archivo histórico
`/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/root-pilot.py` (uid 0, modo 0600,
22735 bytes), así como R116-F1, R114 y R113. Su integridad de contenido
se **debe verificar** frente al SHA-256 de la fuente
`37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c`;
una coincidencia de tamaño no sustituye esa comprobación. La topología
observada es 0/6, DENY MATCH; no existe ventana FTP ni prueba de caída.

**Limitación estructural de F3 histórico:** selecciona `secrets.token_hex(8)`
*dentro* del ejecutor, tras pasar a la ruta privilegiada, y el manifiesto
raíz fija una revisión anterior. Por tanto, no es compatible directamente
con la reserva previa F13 o con las autoridades Scope/Window V2. Nunca
ejecutar F3 y F13 como dos conexiones independientes; tampoco registrar
una reserva después del intento como si hubiera existido antes.

El puente `r128_f3_receipt_bridge` introduce comprobación de un resultado
**ya obtenido** del ejecutor físico: identidad de sesión de 16 caracteres
hexadecimales conocida por F13, estado F13
`ATTEMPT_CONSUMED_UNRESOLVED` (sin haber usado su lector de socket), HEAD
exacto del manifiesto, SHA de la fuente raíz, contexto firmado original,
recibo F3 con temporizador previo y DENY restaurado, SHA del resultado, y
cadena entre QEMU Guest Agent y los bytes de respuesta. Se rechazan estados
con terminal de socket F13 ya existente, falsos `A6`/`A9`, destinos distintos,
permisos inseguros o corrupción de la fuente.

`--fingerprint-root` solo realiza llamadas `sudo -n` de lectura `stat` y
`sha256sum` sobre una ruta inmutable; `--read-installed` lee únicamente
`pilot-<16hex>` a través de `stat` y `cat` fijos y vuelve a verificar los
metadatos. No ejecuta `root-pilot.py`, no abre conexiones, no concede P8,
no modifica F13 ni el laboratorio. La ejecución física nueva requerirá un
**ejecutor R126 V2** que reciba la sesión preasignada, verifique su reserva
*antes* de abrir la ventana y use una única vía QGA. El recibo histórico
importado sigue siendo CANDIDATO; la atribución independiente del origen FTP,
el testigo R127 y la admisión A6 continúan pendientes.

CLI de solo lectura desde la rama no privilegiada:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r128_f3_receipt_bridge.py --capabilities | more
sudo -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r128_f3_receipt_bridge.py --fingerprint-root | more
sudo -k
```

No usar `--read-installed` si no existe una sesión física genuina.
No generar ejemplos de recibos para hacerlos pasar por evidencia real.

## B9 — R128 un solo ejecutor raíz V2 / prebinding F13 (SOURCE_ONLY)

- Fuentes: `src/ardrec/coordination/r128_prebound_session_v2.py`, `scripts/ardrec_p14_r128_root_v2_executor.py`. Pruebas: `lab/tests/test_p14_r128_root_v2_executor.py`.
- **F13 primero:** `f13.reserve` crea un caso irreversible. Solo en una sesión legitimada un operador no privilegiado ejecutará `spend_before_root`, que escribe `spent.json` y su manifiesto con `O_EXCL` y `fsync`. Esto **no demuestra** que un paquete salió por la red. El expediente congelado se reabre y vincula por `head`, sesión hexadecimal, caso, SHA de contrato, alcance, ventana y presupuesto. Un operador independiente debe verificar el original antes de sellar una copia bajo root.
- **Separación de autorización:** B4 sigue con `ARM_DENY_BACKUP_ONLY` y `network_traffic_authorized=false`. B9 necesita, además, un permiso **distinto** con dominio `ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-traffic-grant\0`, Ed25519 con otra clave, revocación específica firmada con otra clave, vigencia hasta 60 s y edad de revocación máxima 30 s. Se exigen diez firmantes distintos contando alcance, piloto, ventana, B4 y B9. Las claves R117 históricas no confieren tráfico. `P8=NO-GO` sigue significando que no se libera la operación ordinaria; el permiso B9 sería una **excepción individual** solo para FTP-T01.
- **Stage root requerido, NO incluido:** `/var/lib/ardrec/r128-one-session-v2/root-executor.py` solo podrá instalarse **después del commit definitivo firmado**, revisión independiente y un manifiesto root 0600 con `approved_head` exacto y SHA-256 del programa, de B4, de R116-F3 y del R116 guard. No se ejecuta código root desde Git. Se requieren `/etc/ardrec/r128-root-traffic-trust-v1.json` y `/etc/ardrec/r128-root-traffic-revocation-v1.json`, más todas las políticas B4, F15, F11 y Scope V2, cada una provista independientemente. Solo se permite una sesión por instalación y una marca root `attempt-consumed.once` irreversible.
- **Motor físico existente, única conexión:** en instalación futura, B9 cargará **por SHA** los helpers de R116-F3 (`37dae375...ba3c`), *no* su `main` históricamente fijado. Antes de cambios comprueba la topología 5/1 DENY. Arma el R116 autónomo (restauración a los 45 s), verifica temporizador, reaprueba firmas y revocaciones justo antes de cada acción, aplica exclusivamente los candidatos NFT R34/FTP fijados, y hace una sola lectura QEMU Guest Agent desde `ardrec-r33-dev-runner` a `10.203.31.2:21`. Se prohíben arranques VM, credenciales, reintentos y objetivos variables. El `finally` solicita `--restore-deny` y prueba nuevamente el 5/1. Una excepción consume la sesión sin promoción.
- **Resultado académico:** el recibo B9 será candidato de procedencia A5; **no** confirma evidencia A6, Rf, transición A8 ni publicación A9. Hace falta testigo independiente R127, revisión física de fuentes y conciliador A10/DurableStore específico de B9. No se confunda un test unitario con ensayo de caída real.
- **Sin efectos:** este parche incremental solo cambia fuente, CI y pruebas. No ejecuta `--inspect-root`, `--execute-pilot`, `--arm-deny` ni `nft`, no crea root stage, ni commit, PR o merge.
- **Riesgos residuales antes de producción:** revisar si el R116-F3 histórico puede operar solamente como biblioteca de funciones fijadas sin inicializar autoridad vieja; revisar pruebas de muerte abrupta con testigo independiente, sincronización de RTC, revocación concurrente y fallo del temporizador. No conceder P8 sin evidencia.

## B10 — R129: recibos B9 exportados y barrera A9 (SOURCE_ONLY)

- `r129_b9_receipt_gate.review()` reconstruye el diario privado F13 de un único intento previamente consumido (`ATTEMPT_CONSUMED_UNRESOLVED`), verifica el `handoff` preasignado y enlaza el `intent`, `receipt`, `guest-result` y `guest-qga` B9. Se verifica SHA-256 de cada documento, el hash esperado de la respuesta, el destino de FTP-T01, la coherencia QGA y el presupuesto del saludo. No realiza una segunda conexión.
- El recibo root es **una copia exportada**: su integridad no establece propietario root, arranque ni autoridad externa. Incluso una respuesta completa `220` constituye A5 candidato, no soporte de vulnerabilidad, ni A6 técnico, ni un intervalo A7 confirmado. Los fallos consumidos siguen sin reintento.
- `r129_b9_receipt_gate.a9_barrier()` recalcula el expediente antes de aceptar la barrera; no abre ni publica `DurableStore`. La primitiva global que deberá emplearse, una vez admitidas la procedencia física, la verdad técnica y la transición, es `DurableStore.publish` existente con `expected_generation` CAS y todas sus guardas.
- La CLI `scripts/ardrec_p14_r129_b10_receipt_gate.py --capabilities` no requiere privilegios. `--replay` y `--a9-barrier` exigen copias JSON privadas propiedad del usuario, con permisos `0600` y padre `0700`; el JSON QGA no necesariamente es canónico y se somete a parser anticolisiones. **No correr el código editable como root.**
- No se declaran pruebas físicas R127, P8=GO, admisión técnica A6 ni A9. Los siete archivos de autoridad aún no provisionados, el artefacto final firmado y la acreditación del laboratorio siguen siendo precondiciones externas.
- Tests B10 prueban diario F13 real con QGA simulado y rechazos por modificación de firmas/hashes, destino, duplicados, sesión, temporizador, reversión y falsos indicadores A6/A9. No sustituyen validación física.


## B11 — Admisión A6 independiente para conectividad FTP-T01

B10 devuelve únicamente un candidato A5, incluso ante un saludo completo `220`.
B11 define dos operaciones separadas y no intercambiables:

1. `signed_review`: comprueba criptográficamente tres firmas Ed25519 distintas
   (procedencia, evaluación técnica y revocación actual), vinculadas a los
   hashes de B9, la sesión, el HEAD, la familia y el testigo R127. Devuelve
   siempre `a6=ND` porque las copias no prueban procedencia root.
2. `admit_live`: es una interfaz para un módulo previamente instalado como
   código root **fijado al HEAD firmado** en `/var/lib/ardrec/r129-a6-ftp-t01-v1/`.
   Lee directamente los archivos B9 originales (modo 0600/root), el handoff
   F13 sellado por root, la política de confianza raíz y comprueba la
   restauración mediante `r127.verify_root_anchored`.

El diario original F13 es propiedad del usuario de ejecución; B10 lo reproduce
sin privilegios ANTES de que se prepare la solicitud. El proceso root no debe
intentar leer ese diario como root, modificar su propiedad ni sustituir la
reserva. Compara el hash de la reproducción B10 con el handoff F13 aprobado y
los cinco documentos root B9, reconstruyendo de nuevo la semántica QGA.

Únicamente una prueba real donde ambos orígenes y todas las autoridades
coincidan podría clasificar la **condición técnica limitada FTP-T01** como
`VERDADERO`: conexión de control a destino autorizado. No implica autenticación,
acceso a archivos, vulnerabilidad ni riesgo final. `Rf`, A8, A9 y la publicación
global conservan su bloqueo hasta calibración y condiciones del núcleo.

La ruta de confianza `/etc/ardrec/r129-a6-ftp-t01-trust-v1.json` no está
provisionada. El parche B11 es SOURCE_ONLY y su CLI expone exclusivamente
`--capabilities`. No contiene comandos de `sudo`, root install, conexión FTP,
arranque de VM, cambios NFT ni operaciones de `DurableStore`.

### Pruebas

- Test Ed25519 auténtico con claves efímeras (solo pruebas herméticas).
- Deriva de hashes, identidad, soporte, revocación, clave reutilizada y tiempo.
- Rechazo de ejecución root desde la fuente Git mutable.
- Casos positivos simulados de lectura root y testigo R127 no son prueba física.
- Integridad de `ROOT/f13-handoff.json` y cuatro documentos B9 de la sesión.
- Sin publicación A9 y sin interpolar un riesgo `Rf` no calibrado.


## B12 — A7 calibración documental firmada y A9 preflight nativo (SOURCE_ONLY)

- `r129_b12_calibration_a9.preview_signed` verifica dos firmas nuevas Ed25519
  con dominios distintos (calibración y revocación), exige separación de los
  tres roles de B11, enlaza HEAD, sesión, caso, A6, catálogo, unidad FTP_DEV,
  índice de evaluación, soporte declarado, pesos y ventana corta. No emite
  claves ni autoriza acciones físicas.
- B11 solo garantiza una verdad **condicionada** sobre conectividad FTP-T01
  tras verificación root y testigo independiente. Una copia JSON de su recibo
  se puede falsificar; B12 no la considera acreditación. La calibración
  documental no puede convertir ese recibo en evidencia física.
- El mismo candidato `Rf` racional se comprueba mediante el oráculo exacto A7
  y `R58-D` con `SYNTHETIC_FIXED` explícitamente identificado como
  **matemático, NO observado**. Resulta `a7_math_candidate` pero
  `confirmed_rf=None`, sin aplicar transición A8 ni generación A9.
- `native_publish_preflight` llama al reductor inmutable **real** de A9
  (`ardrec.persistence._publish`) con un `GlobalState` ya tipado. Rechaza
  generación obsoleta, reutilización de evento, fases no publicables e intentos
  pendientes. El resultado es un **ensayo en memoria**, no un commit ni
  una escritura en `DurableStore`; no se sustituyen sus reglas de CAS,
  journaling y recuperación A10.
- Su CLI solo ofrece `--capabilities`. No hace `sudo`, `nft`, sockets, QGA,
  arranques de VM, instalaciones root, `transition`, `publish`, PR o merge.
- Para un A7 confirmado operativo falta una calibración experimental auténtica
  con procedencia independiente y la verificación en vivo de las fuentes B11
  bajo el ejecutor firmado definitivo. Para A8/A9 falta el handoff explícito,
  autorizado y verificable de los hechos/guardas al estado operacional nativo;
  los tests de preflight no constituyen una publicación física.

## B13 — A8/A9 nativos, escritura de prueba y recuperación de cortes (SOURCE_ONLY)

- `r129_b13_native_a9_replay.py` recibe una revisión B12 **documental y copiable**; recomputa su SHA-256, exige `A6=ND`, `confirmed_rf=null`, `A9=null` y `P8=NO-GO`, y llama al reductor nativo B12 únicamente en memoria. Nunca abre ni escribe `DurableStore`.
- La suite `test_p14_r129_b13_native_a9_replay.py` crea un **almacén local sintético privado** bajo un directorio temporal de prueba; usa los métodos `DurableStore.create`, `transition`, `publish`, `open` y verifica `HEAD`, el diario, la recuperación de CAS, exclusión de escritores, interrupciones y alteraciones. El cambio A8 probado es `DETENER` por `CONTROL` sobre `FTP_DEV`, no el resultado de un ensayo FTP autorizado.
- Los fallos inyectados alrededor de `HEAD` pueden terminar con generación 0 o 1 según el punto exacto de corte; al recuperar se acepta únicamente el estado íntegro que reconstruye el almacenamiento. Una confirmación perdida no permite crear una segunda generación.
- Ninguna generación sintética obtenida en las pruebas acredita A6, Rf, un cierre físico R127, una ventana R128 o una publicación experimental A9. El CLI B13 solo expone `--capabilities`, sin función de escritura. Las pruebas de persistencia se omiten deliberadamente cuando el proceso es root.
- La promoción experimental A6 → A7 → A8 → A9 permanece condicionada a pruebas raíz originales, verificación independiente vigente, calibración no sintética, guarda del núcleo y emisión atómica real. Sin estas condiciones, `P8=NO-GO`, `A6=ND`, `Rf=null` y `A9=null`.
- R126–R129 continúan en una única rama sin commit, push, PR o merge; ninguna operación física se realiza en B13.


## B14 — Liberación raíz firmada y eliminación del replay F8 mutable (SOURCE_ONLY)

- R128/B9 conserva un único intento, reserva F13 consumida, cierre síncrono
  y temporizador R116. El despacho raíz exige **además** una liberación Ed25519
  específica del artefacto y una revocación firmada y fresca. Una declaración
  booleana `root_staged_independently` en `manifest.json` ya no basta.
- Ubicaciones fijas, sin instalarlas desde Git: raíz
  `/var/lib/ardrec/r128-one-session-v2/release.json`, confianza
  `/etc/ardrec/r128-root-release-trust-v1.json` y revocación
  `/etc/ardrec/r128-root-release-revocation-v1.json`.
  Los tres archivos requieren propiedad root, modo `0600`, sin enlaces
  simbólicos. El directorio raíz conserva modo `0700`.
- El operador independiente debe verificar la firma real del commit en Git
  y luego emitir, fuera del repositorio y desde una clave externa, la
  declaración `ARDREC-R128-B14-INDEPENDENT-ROOT-RELEASE-v1`. Esta vincula
  HEAD, boot ID, SHA del manifiesto y ejecutor, SHA exactos B4/F3/R116,
  SHA del registro F8 original, ámbito de FTP-T01, expiración y la
  declaración del operador de haber comprobado el commit firmado.
- El archivo de confianza contiene `release_signer` y `revocation_signer`
  Ed25519 independientes de los diez firmantes anteriores: **12 firmantes
  distintos**. El verificador rechaza claves o IDs repetidos, revocación
  inválida/expirada, release vencida, modificaciones de hash, boot ID, HEAD
  o ámbitos. Revalida la revocación durante toda la ventana.
- El F8 histórico puede utilizarse exclusivamente como *referencia fija de
  trazabilidad* emitida anteriormente bajo root. Se eliminó la invocación
  `legacy.review_boot_provenance` que ejecutaba Python del checkout editable
  como usuario `cicada`. El F3 importado es la versión raíz fijada por SHA;
  `legacy.staged()` comprueba el cierre de sus >=30 dependencias root-owned
  bajo `/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/runtime`.
- La liberación firmada no ejecuta una conexión ni sustituye las firmas
  de alcance, piloto, ventana o tráfico. El estado sigue siendo `P8=NO-GO`.
  Una firma de release expresa la evaluación de la autoridad independiente;
  la verificación del commit en el proveedor Git se debe efectuar por esa
  autoridad y queda declarada en la firma, no se infiere de un SHA.
- Las pruebas unitarias generan claves efímeras exclusivamente locales y
  verifican firmas Ed25519 genuinas. Nunca crean claves operacionales ni
  escriben en `/etc/ardrec` o `/var/lib/ardrec`.

### Condiciones que NO cubre la liberación B14

- Instalar efectivamente un ejecutor raíz aprobado sobre el commit final.
- Ejecución física R127 y R128, evidencia root original y testigo independiente.
- Calibración física A7: B12 sigue produciendo un candidato sintético,
  por lo que `Rf` confirmado y publicación experimental A9 siguen sin estar
  admitidos. Las pruebas B13 de `DurableStore` son solo sintéticas.
- La publicación física requiere un componente raíz independiente de admisión
  y calibración experimental y un escritor nativo auditado que consume tales
  recibos. No se debe presentar el reductor de preflight como ese escritor.
- Para PR: preparar un commit firmado exacto, revisar CI y la dif de todos los
  archivos; el desplegado deberá ser ese commit o una release subsiguiente
  explícitamente autorizada, nunca la fuente mutable sin confirmar.

### B15 — Transición administrativa real con DurableStore (source-only, no riesgo publicado)

B15 implementa el **escritor nativo A8/A9 de cierre administrativo** para FTP-T01,
separado deliberadamente de una publicación **experimental de riesgo**. El
código nuevo `r129_b15_structural_commit.py` reutiliza `DurableStore.open`,
`transition(T10=DETENER)`, `publish` y `open(expected_head=...)` sin crear un
almacén alternativo, sin permitir que el saludo FTP `220` implique vulnerabilidad
y sin convertir calibraciones `SYNTHETIC_FIXED` de B12 en `Rf` confirmado.

**Punto de confianza:** un operador independiente debe instalar una copia
inmutable y verificable de `r129_b15_structural_commit.py` y de las dependencias Python en
`/opt/ardrec/r129-structural-v1/vendor/ardrec`, con archivos y rutas propiedad root, pero el
escritor debe ejecutarse **sin root** como propietario del almacén privado. La
política pública de confianza, anclada por root, se ubica en
`/etc/ardrec-public/r129-structural-trust-v1.json` con modo `0644`. La
revocación firmada se distribuye en
`/etc/ardrec-public/r129-structural-revocation-v1.json` y debe mantenerse
vigente (edad máxima de 30 s). Ambas deben provisionarse fuera del proyecto.
El almacén y las entradas son fijos:
`/home/cicada/ardrec-lab/r129-structural-store-v1` y
`/home/cicada/ardrec-lab/r129-structural-staging-v1`.

El caso debe contar con un A6 *original* acreditado previamente por la ruta
instalada B11, incluyendo testigo físico R127. Una fuente independiente firma
la vinculación del A6, los recibos B9 y el testigo; otro firmante autoriza una
sola transición T10 y generación estructural, vinculada al SHA exacto del HEAD
inicial del almacén, commit firmado aprobado, caso, sesión, versión de las
fuentes `publisher.py`, `ardrec.persistence` y `ardrec.state`; un tercero emite
revocación vigente. Los tres firmantes no pueden reutilizar ninguna de las
cinco claves A6 y A7 listadas en el trust instalado. Se revalida la revocación
**antes de la transición y antes de la publicación**; un cambio o expiración
aborta cualquier nueva generación. Si el proceso cae tras T10, un intento
nuevamente autorizado solo puede continuar si el diario reproduce exactamente
la misma transición y sus referencias. Si cae después del cambio de HEAD, el
nuevo intento comprueba la misma generación existente y no duplica eventos.

El CLI del checkout solamente expone `--capabilities`. `--commit-structural`
rechaza una instalación mutable por ruta, código o propietario distintos del
artefacto aprobado. **No** se instaló ese ejecutor, se emitieron firmas, se
modificó el laboratorio ni se publicó un A9 real. Los tests generan claves
Ed25519 efímeras y usan un `DurableStore` privado sintético, cuyo HEAD no es
una generación experimental de ARDREC. La promoción de un `Rf` numérico sigue
exigiendo un modelo de calibración experimental válido y el anclaje de sus
mediciones auténticas en el archivo analítico; B15 no lo proporciona.

**Criterio de revisión final:** confirmar 52 pruebas B15 más regresión y
compatibilidad con CI, un único commit firmado protegido para R126–R129, y
provisión independiente de autoridad antes de cualquier ejecución real. El
piloto R127/R128 y la generación de riesgo experimental A9 siguen en NO-GO hasta
sus acreditaciones físicas.
