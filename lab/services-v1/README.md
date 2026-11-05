# Servicios de desarrollo v1 / Development services v1

## Estado y alcance / Status and scope

El 4 de noviembre de 2026 se completó una ejecución controlada de desarrollo con
17 comprobaciones satisfactorias sobre SSH, FTPS explícito y SMB. Cuatro VM
arrancaron, verificaron identidad/configuración y terminaron apagadas sin parada
forzada. Se retiraron las tres redes transitorias y el filtrado dedicado.
El registro acredita aquella ejecución; no consulta el estado actual del anfitrión.
El cierre de repositorio queda pendiente hasta integrar este incremento y verificar CI.

On 4 November 2026 one controlled development run passed 17 service checks. Four
VMs were verified and shut down gracefully; transient networks and dedicated rules
were removed. This records that run, not the current host state. Repository closure
requires integration and CI. This is neither the 25-case catalogue nor ARDREC acceptance.

## Versiones, red y recursos / Versions, network and resources

[versions.json](versions.json) distingue paquetes comprobados dentro de cada VM y
herramientas del inventario del anfitrión. Debian 13 sirve de invitado; Kali permanece
como anfitrión. KVM/QEMU, libvirt, QCOW2 y nftables implementan esta base.
No hay prototipo Python/Rust instalado en los invitados.

| Rol / Role | Dirección / Address | vCPU | RAM MiB | Disco GiB | Servicio / Service |
| --- | --- | ---: | ---: | ---: | --- |
| runner | 10.203.30.1, 10.203.31.1, 10.203.32.1 | 2 | 3072 | 24 | Clientes / Clients |
| ssh | 10.203.30.2 | 1 | 768 | 8 | OpenSSH 10.0p1 |
| ftp | 10.203.31.2 | 1 | 768 | 8 | vsftpd 3.0.5 |
| smb | 10.203.32.2 | 2 | 1536 | 12 | Samba 4.22.11 |

Cada segmento es /28. Solo se crearon las redes dev 30/31/32. Piloto y experimento
siguen reservados. El runner no es pasarela: no hay forwarding ni ruta por defecto.
Los objetivos reciben únicamente TCP 22, TCP 21 y 50000–50009, o TCP 445 según rol.
No se publican puertos en el anfitrión. Las verificaciones físicas negativas y de
reinicio/restauración corresponden al punto 5; los controles positivos no las sustituyen.

Each segment is /28. Only dev networks 30/31/32 were instantiated. No gateway,
default route or forwarding is configured. Pilot/experiment separation remains step 6.
Positive service checks do not establish all negative isolation or restoration checks.

## Cuentas y recursos / Accounts and resources

[resources.json](resources.json) registra cuentas sintéticas distintas, permisos,
recursos conocidos y huellas. `ardrec_ssh`, `ardrec_ftp` y `ardrec_smb` no son cuentas
personales. En el runner, `ardrec-operator` ejecuta clientes; controller/executor
son cuentas reservadas sin el prototipo instalado. Contraseñas, claves privadas,
archivos de autenticación y recibos completos permanecen fuera de Git.

Cada objetivo tiene `/srv/ardrec/<rol>/read-only/reference.txt`, `temporary/` y
`restricted/denied.txt`. La raíz es root:root 0755, referencia 0644; restricted es
root:root 0700 con archivo 0600; temporary pertenece a la cuenta sintética y es 0700.
La prueba solo creó un marcador nuevo, verificó su contenido y lo retiró. Las tres
carpetas temporary se comprobaron vacías al terminar. Los permisos aquí registrados
proceden del aprovisionamiento; las pruebas de acceso verifican los casos enumerados,
no toda combinación posible de ACL.

Synthetic identities and fixtures are separate from personal accounts. Secrets and
full private receipts stay outside Git. Provisioned permissions and selected access
checks are recorded; this is not an exhaustive ACL audit. Temporary marker directories
were empty after the run.

## Configuraciones efectivas / Effective configuration

- [SSH](config/ssh.conf): autenticación sintética por clave/contraseña configurada;
  esta ejecución verificó la clave. Sin root login, forwarding, túneles ni X11.
  El único sudo autorizado ejecuta `ardrec-identidad` sin argumentos (devuelve UID).
- [FTP](config/ftp.conf): FTPS explícito, control y datos cifrados obligatorios,
  certificado validado con CA de laboratorio, pasivo 50000–50009, sin anónimo ni
  FTP activo. `ssl_tlsv11=NO`, `ssl_tlsv12=YES`, `ssl_tlsv13=YES` son los nombres
  aceptados por el binario 3.0.5-0.2. Los guiones bajos del intento anterior eran erróneos.
- [SMB](config/smb.conf): servidor autónomo, SMB2/3, firma obligatoria, sin NetBIOS,
  sin invitado; cifrado obligatorio en temporary. No se afirma prueba de SMBv1,
  invitado, vulnerabilidades o todos los dialectos.

The checked-in files match audited guest configuration hashes. SSH key authentication,
explicit FTPS and signed/encrypted SMB operations were exercised. Other authentication
modes, dialects and thesis case variants require their own operational cases.

## Construcción y correcciones / Build and corrections

La imagen Debian y dependencias se adquirieron con versiones/huellas fijadas. Los
paquetes se instalaron en una imagen de construcción, no en Kali. Los roles se
configuraron **fuera de línea mediante libguestfs y Python explícito**, sin red de
aprovisionamiento. Ansible 2.21.6 está disponible en un entorno propio, pero no aplicó
estas configuraciones. Esta decisión sustituye el método previsto en el diseño v1;
no se atribuye a Ansible una ejecución inexistente.

La raíz real es /dev/sda3 ext4. Las bases v4 incorporan la reparación BIOS/GRUB.
La comparación de arranque justificó VGA de 16 MiB, sin pantalla gráfica ni listener
remoto. R8 reutilizó esas bases de solo lectura y creó nuevos overlays v6. Antes de
activar FTP corrigió únicamente los tres nombres TLS y volvió a verificar los hashes.
Las bases FTP originales conservan la configuración anterior. **Una reconstrucción
futura debe aplicar config/ftp.conf y verificar su huella antes del arranque del servicio.**

The actual provisioning method was offline libguestfs/Python, not Ansible. Root is
/dev/sda3; repaired v4 bases boot with VGA without a remote graphics listener. R8
used fresh v6 overlays and corrected only the three FTP TLS option names. Original
FTP bases retain the old configuration and must never be treated as corrected templates.

## Operación y conservación / Operation and retention

[procedures/activation-r8.py](procedures/activation-r8.py) conserva exactamente el
procedimiento ejecutado y su alcance. Está ligado a recibos locales y directorios
exclusivos: **no es un lanzador reutilizable**. Rechaza repetir sobre los mismos
artefactos. No volver a ejecutar para producir un resultado nuevo ni editar su huella.
El script de documentación no instala paquetes, no arranca VM y no cambia redes.

Conservar en privado: entradas verificadas; recibos de construcción, roles, arranque
y activación; registros; certificados y claves; bases v4 y overlays v6 apagados.
No borrar intentos fallidos. El recibo v6 referencia cada registro por SHA-256.
Los datos se ubican fuera del repo, en el laboratorio del operador y los pools libvirt.
El punto 5 definirá el sellado/restauración y un ciclo reutilizable sin retroceder evidencia.

The archived activation script is the exact one-shot procedure, not a reusable runner.
Preserve all failed attempts and successful evidence privately. Read-only v4 bases
plus stopped v6 overlays are not yet restoration-sealed templates. Step 5 owns that
lifecycle. CI checks documents; it never launches VMs or replays physical tests.

## Evidencia y límites / Evidence and limits

[evidence.json](evidence.json) es una proyección pública de campos permitidos del
recibo privado cuyo SHA-256 queda fijado. No contiene credenciales ni registros crudos.
La prueba de desarrollo no entra en la muestra experimental y no aumenta n.
AL-06, AL-07 y las siete obligaciones conservan sus estados y puntos de control.
La custodia externa, restauración, suspensión, cortes eléctricos y aceptación del
sistema integrado siguen pendientes en sus respectivos pasos.

Public evidence is a bounded projection of the hash-pinned private receipt. Development
data is excluded from the experimental sample. All seven obligations remain open;
no full isolation, restoration, power-loss or system-acceptance claim is made.
