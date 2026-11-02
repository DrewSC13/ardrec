# Laboratorio Prometheus compacto v1 / Compact Prometheus laboratory v1

## Alcance / Scope

**ES.** Diseño del punto 3 sobre la base `d66bb017948fc5e7af1b412729149e27bb423263`.
La tesis vigente se identifica por SHA-256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.
Secciones revisadas: 1.9.4 (pp. 36–37), 2.4.4 (pp. 64–65) y 3.7 (pp. 134–144).
El diseño cumple una función documental; todavía no hay laboratorio instalado o
verificado. Los valores de capacidad son decisiones de ingeniería, no constantes de
la tesis. Las siete obligaciones del punto 1 permanecen abiertas en sus respectivos
alcances; AL-06 y AL-07 no se cierran con este documento.

**EN.** Step 3 design, based on the commit and thesis hash above. This is a documented
architecture, not an installed or verified laboratory. Capacity values are engineering
choices, not thesis constants. All seven retained obligations keep their original gates;
this document does not close AL-06 or AL-07.

## Infraestructura y capacidad / Infrastructure and capacity

**ES.** El inventario comunicado el 2026-11-02 identifica Kali Rolling 2026.3,
kernel 7.1.5+kali-amd64, Ryzen 7 5700U, 16 CPU lógicas, AMD-V, `/dev/kvm`,
13 GiB de RAM total mostrada y 9,4 GiB disponibles en ese instante. La raíz y el
proyecto comparten ext4: 135 GiB libres mostrados. No se ha identificado el tipo
físico del disco, una UPS ni un respaldo independiente. Los valores de pantalla
están redondeados. La presencia de KVM/herramientas no demuestra acceso utilizable.

| Rol / Role | vCPU | RAM MiB | Disco virtual GiB / Virtual disk GiB |
| --- | ---: | ---: | ---: |
| runner | 2 | 3072 | 24 |
| SSH | 1 | 768 | 8 |
| FTP | 1 | 768 | 8 |
| SMB | 2 | 1536 | 12 |
| Total | 6 | 6144 | 52 |

Un solo conjunto dev/pilot/exp activo, máximo un intento técnico concurrente.
Los tres servicios pueden estar disponibles a la selección, aunque solo se ejecute
un intento a la vez. La asignación conjunta de RAM no superará 6144 MiB; se reservan
al menos 5120 MiB de RAM total para anfitrión y administración. Antes de arrancar
el conjunto se exige MemAvailable >= 7680 MiB y capacidad total para ambas reservas.
Durante una campaña, MemAvailable < 2048 MiB, crecimiento sostenido del swap,
presión de CPU/E/S o throttling se registran y bloquean nuevos despachos. Se resuelve
el intento en curso con el supervisor; nunca se mata silenciosamente ni se repite.
Swap no cuenta como RAM disponible para dimensionar VM. No se obliga a desactivar
swap del anfitrión ni se alteran otros proyectos.

Presupuesto máximo inicial: 80 GiB **realmente asignados** a todo el laboratorio
(bases, overlays, ISOs, registros, evidencias y temporales), conservando 40 GiB libres
en el sistema anfitrión. Espacio libre de otros proyectos puede cambiar y debe
medirse antes de cada activación. 52 GiB virtuales no son una garantía de ocupación:
las capas y copias consumen espacio adicional. No se guardarán 54 clones completos
ni los tres entornos encendidos. No se borrará evidencia para respetar el presupuesto:
se detiene la recolección y se amplía/archiva mediante procedimiento verificado.

**EN.** Operator-reported inventory is rounded and not independently measured.
Use at most one environment set and one concurrent technical attempt. The three
services may remain visible to selection. Allocate 6 GiB total to guests, reserve
5 GiB total for the host, require 7.5 GiB MemAvailable before starting the set and
monitor a 2 GiB available-memory floor. Swap is not RAM capacity. Resource pressure
blocks new dispatches and requires supervised reconciliation, never silent retries.
Budget 80 GiB actual lab allocation and retain 40 GiB host free space. Virtual sizes
do not bound overlay/backup growth. Never delete evidence to meet a quota.

## Tecnologías y reproducibilidad / Technologies and reproducibility

**ES.** Mantener Kali como anfitrión y utilizar Debian 13 minimal en invitados.
KVM/QEMU + libvirt/virsh administran VM; virt-manager es opcional. QCOW2 utiliza
bases inmutables y overlays cortos por escenario. Elegir ext4 para los discos de
invitados; registrar modos de caché y flush reales antes de ensayos de durabilidad.
No usar caché unsafe. No se promete persistencia ante corte eléctrico solo por
elegir ext4, QCOW2 o fsync.

Ansible no está encontrado en el inventario. Se instalará de manera versionada en
el paso 4, en un entorno propio compatible, sin sustituir el Python del sistema.
Preparación inicial con imagen verificada y cloud-init de un solo uso o consola;
Ansible aplica configuraciones por una red de aprovisionamiento temporal. Las
credenciales de construcción se retiran antes de sellar las imágenes de escenario.

Fijar SHA-256 y procedencia de imagen, kernel, QEMU, libvirt, nftables, Ansible,
paquetes Debian, OpenSSH, vsftpd, Samba y clientes. Conservar paquetes/metadata de
repositorio para reconstrucción. No usar referencias `latest`. El prototipo conserva
Python 3.14.7 y Rust 1.98.1 de su base; la compatibilidad del runtime dentro de Debian
se verificará por empaquetado y pruebas. Registrar cambios de Kali Rolling y no
actualizar kernel/hipervisor durante una campaña. Un cambio material exige nueva
base y verificaciones afectadas; el congelamiento experimental ocurre después del piloto.

**EN.** Retain Kali as host; use minimal Debian 13 guests, KVM/QEMU, libvirt/virsh,
optional virt-manager and QCOW2 immutable bases with short overlay chains. Record
guest/host filesystem, cache and flush behavior; never infer power-loss durability.
Install a pinned Ansible environment at step 4. Bootstrap through a verified image
and one-use cloud-init or console, then provision over a temporary management network.
Remove build credentials before sealing. Record image, kernel, package and tool
versions/hashes, retain reconstruction inputs, avoid floating latest references and
freeze the execution platform per campaign. Python/Rust runtime compatibility remains
to be verified inside the guests.

## Red y coexistencia / Networking and coexistence

**ES.** `topology-v1.json` es la fuente de las nueve reservas /28: dev usa terceros
octetos 30/31/32, piloto 40/41/42 y experimento 50/51/52 bajo 10.203.0.0/16.
En cada segmento `.1` identifica al runner y `.2` al objetivo; `.1` no es una
pasarela. Las rutas comunicadas no se superponen, pero esta conclusión se limita al
inventario: antes del despliegue se examinan todas las tablas de rutas, reglas,
VPN y redes libvirt/Docker inactivas. Conflicto implica detener y versionar otra
reserva. No se prueban rutas enviando tráfico a sistemas externos.

Cada red se define sin `<forward>`, sin IP del anfitrión, DHCP, DNS o interfaz física.
Objetivos con una NIC; runner con tres, sin forwarding IPv4/IPv6. IPv6 se deshabilita
en los segmentos ARDREC y se filtra EtherType IPv6 en sus puentes; IPv6 del Wi-Fi
del anfitrión permanece intacto. No hay ruta por defecto en invitados durante prueba.
Sin NIC NAT, VPN, puertos publicados, carpetas compartidas, portapapeles compartido,
USB passthrough ni reenvío del agente SSH personal. Consola libvirt para emergencia.

Filtrar entrada/salida del invitado y tráfico bridge del anfitrión. Allowlist de
MAC/IP/puerto por interfaz, ARP necesario, respuestas establecidas y, si hacen falta,
errores ICMP acotados. Denegar tráfico nuevo de objetivos al runner, entre objetivos,
al anfitrión, a otros entornos y a redes externas. Autorizar del runner al objetivo
únicamente TCP 22 (SSH), TCP 21 y 50000–50009 (FTP pasivo), TCP 445 (SMB).
FTP activo y NetBIOS quedan fuera de la base; incorporar un caso que los requiera
exige revisión explícita. La política de red admite transporte; no sustituye la
autorización de cuenta, recurso, operación o perfil.

Preservar `docker0`, puentes Docker y `virbr0` predeterminado. No activar este último
para ARDREC ni borrar reglas generales. Crear nombres propios y tablas/cadenas
dedicadas, revisar interacción con Docker y probar antes/después. La red del runner
no debe ampliar el aislamiento mediante routing accidental. Verificar que el
reinicio no reintroduce conectividad de preparación.

**EN.** Nine reserved /28 subnets live in the topology JSON. `.1` is the runner,
not a gateway; `.2` is the target. Recheck all route tables, policy routing, VPNs
and inactive networks before deployment. Guests use private libvirt networks without
forwarding, host addresses, DNS/DHCP or physical uplinks. Disable and filter IPv6
only on ARDREC segments. Enforce guest and host bridge allowlists; no target-initiated
connections or target-to-target traffic. Only TCP 22, TCP 21 plus passive 50000–50009,
and TCP 445 are initially allowed. Keep existing Docker, default libvirt, host IPv6
and personal SSH configuration untouched. No global firewall flush, shared host folders,
personal agent forwarding, USB passthrough or measurement-time management/NAT NICs.

## Servicios y recursos / Services and resources

**ES.** OpenSSH soportará SSH-T01…T08; vsftpd FTP-T01…T08 y Samba SMB-T01…T09.
No se concede alcance a familias VUL por instalar estas tecnologías. Los casos VUL
requieren especificación previa, objetivo exacto y demostración mínima autorizada.
Preparar cuentas sintéticas distintas, archivos conocidos, directorios de listado,
lectura, escritura temporal y recursos restringidos. Conservar hashes, propietarios
y permisos de base. Solo marcadores nuevos en rutas preparadas pueden escribirse
y eliminarse durante pruebas; los permisos/cuentas se modifican al aprovisionar,
no como acción ordinaria del caso.

SSH: claves de host inventariadas, contraseña/clave sintéticas, operación inocua de
identidad efectiva y facultad privilegiada limitada (sin sudo general). FTP: FTPS
explícito, CA de laboratorio y verificación de certificado; distinguir protección
de control y datos. SMB: SMB2/3 ordinario, firma/cifrado por separado, invitado y
autenticado separados. SMB-T02 exige cliente compatible para atribuir rechazo de
SMBv1; habilitar SMBv1 solo en variante expresamente autorizada. No requiere AD.
Una versión de producto no acredita vulnerabilidad ni explotabilidad.

Clientes previstos: OpenSSH, curl, smbclient, OpenSSL y auxiliares acotados cuando
un cliente no produzca soporte suficiente. Captura tcpdump/dumpcap solo con filtro
de flujo autorizado, límite de bytes/duración y proceso de captura separado con
privilegio mínimo. No se autoriza una herramienta completa por estar instalada.
Ejecutable, argumentos, entorno, credenciales, redirecciones y límites se fijarán
por perfil en el paso 8. No se ejecuta shell libre para montar argumentos.

**EN.** Prepare OpenSSH, vsftpd and Samba for the 25 thesis families, with synthetic
accounts, known fixtures and explicit allowed/restricted resources. Runtime writes
are limited to new temporary markers with separately verified cleanup. Provisioning
is the only phase for changing accounts, permissions and keys. Separate SSH transport,
authentication and operations; FTP control/data TLS; SMB dialect/signing/encryption
and session identities. SMBv1 tests require a compatible client and explicit variant.
Tool availability does not authorize arbitrary invocation; pin each execution profile.
Product versions never establish exploitability. Captures are bounded and scoped.

## Autoridad y procesos / Authority and processes

**ES.** El administrador controla libvirt y las imágenes desde el anfitrión. Python
y Rust comparten la VM runner y socket Unix, con usuarios de servicio distintos,
sin root, sin pertenecer al grupo libvirt y sin acceso a discos base. El administrador
instala configuración confiable de UID/GID, rutas, propietario/permisos del socket
y perfiles; Python o herramientas no pueden modificarla. Comprobar credenciales
del par con identidad/lifetime efectiva, no un PID aislado. Descriptores mínimos,
sin herencia accidental. Los auxiliares privilegiados deben tener función fija y
permisos mínimos; nunca sudo general o acceso completo a systemd/libvirt.

Cada intento se ejecutará en cgroup propio con límites de tareas, CPU, memoria,
tiempo y salidas, directorio temporal privado y credenciales de alcance mínimo.
El supervisor debe conciliar descendientes y recursos aunque muera Python. Esto
es una obligación de implementación de los pasos 9–12, no una capacidad ya probada.

`authorization-template-v1.json` NO autoriza ejecución. Responsable legítimo,
operador, fechas, identidades, VM UUID, IP, puertos, perfiles, cuentas/referencias,
rutas, límites y contacto de parada deben constar en un registro privado aprobado.
El README público enlaza el diseño; no contiene secretos. Credenciales protegidas
fuera del repo, sin argumentos visibles, logs o capturas publicados sin revisión.

**EN.** Host administration controls libvirt/images. Python and Rust share the runner
and Unix socket under separate unprivileged service users. Trusted peer/profile policy
is administrator-owned; verify effective lifetime as well as credentials, not PID alone.
Per-attempt cgroups, private temporary paths, least-privilege credentials and narrowly
scoped helpers are implementation obligations, not existing verified features. A separate
completed private authorization is mandatory; the public template grants no execution.

## Restauración, custodia y tiempo / Restoration, custody and time

**ES.** Fases: construcción con actualizaciones verificadas; aprovisionamiento;
desconexión de NIC de preparación y comprobación de aislamiento; ejecución;
conciliación/extracción; restauración con objetivo apagado. Bases selladas sin
memoria guardada. Instancias con UUID, claves y machine-id controlados: no duplicar
identidad accidentalmente al clonar. Separar cuentas/credenciales y discos de dev,
pilot y exp aunque compartan sistema operativo base.

Ruta propuesta de datos: `/home/cicada/ardrec-lab/`, fuera de Git y de los parches,
con subdirectorios bases, overlays por entorno, evidence y custody. Esta propuesta
no crea directorios ni pools. El pool libvirt deberá tener ACL mínimas, sin hacer
world-readable el home. Runner conserva estado durable separado de objetivos;
restaurar un objetivo no retrocede contadores, recibos o estado confirmado.

Custodia de expected_head en anfitrión, fuera del snapshot del runner, con registros
versionados autenticados y archivo de evidencia exportado por procedimiento acotado.
No conceder al runner modificación de la custodia. El host es parte de la base de
confianza, no un adversario que este diseño pueda resistir. La custodia local separa
rollback de invitados pero comparte disco/fallo eléctrico: antes de recolección
definitiva se requiere respaldo independiente verificado. Nunca recuperar desde una
copia vieja porque su hash sea válido: comparar con ancla confiable y conciliar.

Extraer evidencias con el intento terminado/conciliado, a un área de recepción
limitada, validando tamaño, nombre, hash y procedencia. No montar el disco objetivo
no confiable con escritura en el anfitrión ni copiar rutas arbitrarias. Una VM
colectora desechable puede sustituir una VM objetivo apagada si la extracción
requiere interpretar su filesystem. La copia aceptada queda fuera de la restauración.
No borrar registros al limpiar. Limpieza fallida conserva su incidente aunque luego
se restaure. CERRADO/DETENIDO no se reabren mediante rollback.

Excluir suspensión/hibernación durante campañas, registrar el estado efectivo de
inhibidores/alimentación y detectar discontinuidades. No prometer que un inhibidor
evita todos los apagados. Sincronizar UTC antes de aislar, registrar desviación y
usar reloj monotónico para duración conforme al contrato temporal. Sin llamadas NTP
externas durante prueba. Suspensión, ajuste UTC, reinicio o presión material producen
incidente y conciliación. Límites definitivos de tolerancia se fijan en pilotaje.

**EN.** Build/provision, disconnect preparation interfaces, verify isolation, execute,
reconcile/export, then restore powered-off targets. Preserve distinct clone identities.
Proposed lab data lives outside Git; no pool or directories are created by this design.
Keep runner persistence separate from target rollback and expected_head custody outside
runner snapshots. The trusted host remains a shared disk/power failure domain; independent
verified backup is required before final collection. Bounded evidence extraction must
not grant arbitrary host paths or mount untrusted target disks writable on the host.
Restore never erases failed cleanup, resets counters or reopens terminal observations.
Prevent and detect suspend; synchronize UTC before isolation, measure duration with
the monotonic contract, preserve rejected reports and reconcile discontinuities.

## Diseño experimental y cierre / Experimental design and closure

**ES.** Las 54 unidades planificadas (18 por protocolo) son servicio–escenario,
no 54 VM simultáneas. Reconstruir por lotes conserva recursos, pero requiere identidad,
configuración y estado base por unidad. Diferencias técnicas reales, no solo nombres/IP.
Repeticiones no aumentan n. El agrupamiento y orden se fijan antes de recolección;
no atribuir al algoritmo efectos del orden, calentamiento de caché o carga externa.
Tres objetivos activos permiten seleccionar entre servicios; ensayos que requieran
más candidatos reales deben revisar capacidad y topología antes de congelar.
Las simulaciones se separan de intentos físicos y no entran en I7 experimental.

Se cierra el diseño tras validar coherencia, revisar alcance y registrar/integrar
este incremento. La instalación queda para el paso 4; aislamiento/restauración para
el 5; separación implementada para el 6; catálogo/perfiles para 7–8; supervisor para
9–12. `verification-plan-v1.json` define comprobaciones pendientes, nunca resultados.
Los presupuestos de intento se fijan durante piloto: una ejecución ordinaria y solo
la repetición preautorizada, sin reintentos ocultos o cambios materiales automáticos.
La aceptación funcional, algoritmos y validación experimental siguen pendientes.

**EN.** The 54 planned units are service-scenarios, not simultaneous VMs. Batch reuse
requires preserved unit identity, baseline and meaningful technical differences.
Fix grouping/order and control cache/load effects before collection; repeats do not
increase n. Three active targets allow cross-service selection; larger real candidate
sets require a capacity/topology review. Simulation is separate from physical evidence.
Document review/integration closes design only. Deployment, physical checks, catalog,
profiles and supervisor remain assigned to later steps. All verification entries are
plans; functional acceptance, algorithms and experimental validation remain pending.

## Referencias técnicas / Technical references

- libvirt networking: https://libvirt.org/formatnetwork.html
- QEMU disk images: https://www.qemu.org/docs/master/system/images.html
- Debian 13: https://www.debian.org/releases/trixie/
- systemd resource control: https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
- Ansible: https://docs.ansible.com/projects/ansible-core/
- OpenSSH: https://www.openssh.com/manual.html
- vsftpd: https://security.appspot.com/vsftpd.html
- Samba: https://www.samba.org/samba/docs/

Consultadas al preparar el diseño el 2026-11-02; antes del despliegue contrastar
contra la documentación de las versiones instaladas. / Consulted during design on
2026-11-02; check installed-version documentation before deployment.
