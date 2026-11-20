# ARDREC P14 / R115-F9 — Expediente de autoridad independiente

**Alcance:** coordinación de permisos institucionales e inventario de raíces de confianza para FTP-T01. Este incremento no emite firmas ni aprobaciones, no prepara leases F11, no inicia invitados y no permite tráfico P8.

## 1. Estado de partida reproducible

- Base F1–F6 firmada: `6ce42a1143d50f7adf69ea3159b56c0e993c45cb`.
- F7 firmado: `a017079c8ce60c82f3035d09b0eb5249377bde75`.
- F8 instalado y probado; debe confirmarse mediante **commit local firmado independiente** antes de ejecutar planes reales. El instalador F8→F9 firma F8, instala F9, ejecuta la regresión y firma F9 como commit separado, sin push ni merge.
- FTP-T01 sigue en el catálogo P7 `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`. Ningún documento del operador cambia esta condición ni habilita el conjunto de familias.
- Las VM SSH, runner, FTP y SMB estaban apagadas en la última captura; R34/F11 coinciden, vínculos ausentes mientras están apagadas. No se utiliza un recibo pasado como prueba de que las VM siguen apagadas.
- El arranque se condiciona a una nueva autorización independiente, secuencia `SSH → runner → FTP` y DENY F11/R34 antes y después de cada etapa. SMB no está incluido.

## 2. Dos cadenas independientes de autoridad

**Alcance de FTP-T01 (R115-F3/F6):**

1. Autoridad externa firma una declaración Ed25519 de caso, destino FTP, cliente, perfil, límites, ventana y referencia de catálogo; el contrato del operador liga los bytes firmados mediante SHA-256. No es suficiente que el propio usuario entregue una clave que ha creado.
2. Otra autoridad distinta firma un estado de revocación vigente para la autorización concreta.
3. Un administrador independiente instala la política de claves públicas aceptadas en `/etc/ardrec/r115-ftp-t01-trust-v1.json` y la declaración de revocación en `/etc/ardrec/r115-ftp-t01-revocation-v1.json`, con permisos y procedencia que cumplan R115-F6. Este incremento no crea ni edita esas rutas.

**Arranque único de DENY (R115-F7/F8):**

1. Después de producir un plan físico con hashes y HEAD firmado, autoridad independiente firma un permiso **por rol**, ligado a plan, VM, contrato, autorización y SHA del HEAD. Duración máxima: 120 segundos.
2. Otro firmante distinto acredita la no revocación actual del permiso exacto; recencia máxima: 90 segundos.
3. Administrador independiente proporciona las claves públicas de ambos firmantes en `/etc/ardrec/r115-boot-trust-v1.json` y el documento de revocación en `/etc/ardrec/r115-boot-revocation-v1.json`. El expediente F9 solamente inspecciona estas rutas con las reglas de R115-F7, sin alterar su contenido.
4. Permisos de arranque de SSH no se reutilizan para runner ni FTP. Una fase requiere el recibo físico del predecesor, no una simulación.

**La autorización para arrancar con DENY no es autorización de tráfico FTP-T01.** Para A5/P8 siguen faltando ventana de tráfico separada, límites aplicables y exigibles, perfil y cliente reales, servicio atestado y admisión A3 completa. A6, A7, A8, A9 y A10 no se dan por ejecutados.

## 3. Implementación F9

Módulo: `src/ardrec/coordination/r115_f9_authority_handoff.py`.
CLI: `scripts/ardrec_p14_r115_f9_authority_handoff.py`.

Modo único `--prepare`: crea un expediente JSON privado e inejecutable. Opcionalmente recibe `--contract /ruta/privada` y `--authorization /ruta/privada`; ambos o ninguno. El módulo exige Git limpio y firmado, fuentes F7/F8/F9 presentes en HEAD, pin del catálogo FTP-T01, y revisa las rutas fijas de claves públicas bajo `/etc/ardrec/` con lectores existentes. La firma y revocación se revisan reutilizando R115-F6, **sin permitir al operador elegir raíces de confianza alternativas**.

El reporte separa `ABSENT`, `ND`, `REJECTED` y `STRUCTURE_MATCH` para políticas de confianza. `STRUCTURE_MATCH` significa únicamente *estructura de claves públicas que coincide*: no implica que el operador esté autorizado. Aun cuando el alcance sea `VERDADERO`, quedan `A5=NO-GO`, `A6=ND`, `P8=NO-GO`, `traffic_authorized=false` y `vm_starts=0`.

Los recibos se almacenan bajo `/home/cicada/ardrec-lab/r115-f9-authority-handoff-v1/handoff-*` como JSON canónico y SHA-256, permisos privados, sin claves privadas ni firmas sintéticas.

## 4. Integridad y criterios de aceptación

- ZIP con lista exacta de cuatro archivos F9 y manifiesto con SHA-256; dependencia explícita de los cuatro archivos F8 y del HEAD F7.
- Cierre firmado separado de F8 y F9, seleccionando exactamente cuatro archivos de cada incremento, sin añadir ni omitir entradas.
- Rechazo de un commit firmado pero con árbol modificado, catálogo alterado, ZIP incorrecto o nueva rama.
- Regresión R112–R115. El instalador ejecuta F9 `--prepare` **solamente después** del segundo commit firmado, con Git limpio. Es una preparación documental de solo lectura del estado de las autoridades, no una aprobación.
- No hay comandos de `virsh start`, `sudo`, `restore-deny`, cambios de red, Git push o merge en el instalador.

## 5. Continuidad

El administrador externo debe designar autoridades reales y proporcionar artefactos firmados. Sin ese punto de decisión externo no existe un medio legítimo de iniciar VM ni tráfico. Tras cerrar F9 con firma, el expediente facilitará entregar los datos concretos y verificar lo recibido; después se activarán SSH, runner y FTP de forma autorizada, comprobando las seis vinculaciones DENY, antes de la ventana FTP y de la integración real A5–A10.
