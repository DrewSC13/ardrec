# ARDREC R116-F1 — restaurador autónomo DENY 5/1 (contrato de fuente)

## 1. Estado heredado

Base exacta: `46dccd948d2d61c4fd777c64dafad3efa71cf035`, PR #189 R115 fusionado. Rama `feat/p14-r116-piloto-ftp-fisico-a5-a10`. R115-F17 cerró **fuente NO-GO**; no declaró P7 calibrado, conexión autorizada, evidencia A6, Rf confirmado ni A9 publicado. Esta entrega preserva ese límite.

## 2. Capacidad concreta

`scripts/ardrec_p14_r116_f1_root_deny_guard.py` contiene una herramienta **independiente de raíz, exclusivamente DENY**. Una vez instalada de forma explícita como archivos propiedad de root y modo 0600 en `/var/lib/ardrec/r116-f1-five-one-deny-v1`, proporciona tres operaciones privilegiadas:

- `--check`: comprueba **sin mutaciones** tabla nftables R34, estados de cuatro VM y todos los bindings presentes para la etapa real. Debe rechazar candidatos permisivos.
- `--restore-deny`: escribe **primero** las cuatro reglas R34 DENY desde el paquete histórico íntegro R113-F6; después inspecciona los estados, restaura únicamente vinculaciones conocidas (originales o candidatos R113 autenticados) y verifica otra vez nftables y los bindings. No abre puertos ni tiene acceso a destinos arbitrarios.
- `--arm-deny <16 hex>`: estando SSH, runner y FTP encendidas bajo DENY (SMB apagada), reserva durablemente un único intento y arma con systemd un `--restore-deny` autónomo a los **60 segundos**. Comprueba el temporizador antes de emitir un recibo de armamento. No abre la ventana FTP.

`--capabilities` puede ejecutarse como usuario común sin operaciones privilegiadas. La primera escritura de `--restore-deny` es siempre una restauración **DENY**, incluso si luego falla libvirt o la topología no es admisible. Si falla nftables no se prosigue con los bindings.

### Topología real de seis interfaces

| VM encendidas | Vinculaciones DENY esperadas | Ausentes por VM apagada |
|---|---:|---:|
| Ninguna | 0 | 6 |
| SSH | 1 | 5 |
| SSH + runner | 4 | 2 |
| SSH + runner + FTP | 5 | 1 |

Con runner activa, `runner_smb` **sí existe**, porque el runner tiene tres interfaces. La vinculación `smb` del servidor apagado es la única ausente en la etapa FTP. Se rechaza cualquier otro conjunto de VM, como SMB encendida sin autorización de alcance.

### Integridad y límites

- El script debe estar exactamente en su ruta raíz fija, en un directorio root:0700, sin ancestros inseguros, y con `manifest.json` root:0600 cuyo SHA-256 fija el propio script.
- Reutiliza `/var/lib/ardrec/r113-six-deny-guard-v1` y comprueba la huella histórica exacta del recuperador R113-F6 (`3a9c2d0e70d7b6b808ee2eaf7382b11715c2e2d8e0f777ff627a1ed084a8bb05`). El recuperador anterior valida a su vez su manifiesto, las 6 XML originales y sus contrapartes candidatas.
- Las rutas y argumentos host son constantes; no acepta comandos externos, IP, puertos ni nombre de VM del operador.
- `--arm-deny` **consume** su reserva antes de solicitar systemd. Si falla systemd, no reintenta automáticamente. No existe opción para cancelar el timer o restaurar una regla ACCEPT.
- Duración desde **armamento**: 60 segundos. El controlador R116-F2 tendrá que dejar un margen explícito antes de abrir, comprobar la vigencia y ejecutar restauración DENY al terminar, además del backup autónomo.

## 3. Instalación y autorización de raíz

**El instalador del parche F1 nunca ejecuta `--stage-root`, `--arm-deny` o `--restore-deny`.** Solo instala las fuentes, ejecuta las pruebas y realiza un commit Git local firmado. Aun si el commit aprueba, esto NO autoriza ejecutar el piloto.

Existe un stager independiente `scripts/ardrec_p14_r116_f1_root_stage.py`, que deberá invocarse **en otra etapa con consentimiento explícito del operador**. Antes de copiar exige una rama R116 desde R115, HEAD firmado `G`, árbol limpio, contenido byte a byte idéntico a Git y manifiesto que fija el guard. Crea exclusivamente los dos archivos de raíz con permisos restrictivos; rechaza despliegues existentes y no realiza ninguna modificación de libvirt/nftables/systemd.

La instalación root, la atestación física, los ensayos de pérdida del proceso y del reloj, la política de permisos y el timeout de emergencia deberán aprobarse por separado antes de conectar un piloto F2 real. **35 pruebas simuladas no sustituyen una prueba física de restauración.**

## 4. Pruebas y límites de aceptación

Se cubren ciclos 0/6, 1/5, 4/2, 5/1; estados no admitidos; detección de DENY alterado; pérdida de binding activo; candidato reconocido, candidato desconocido, restauración de nftables antes de cualquier acción en VM; armamento único, timer fallido y prohibición de otro intento; huella inmutable del script. Las pruebas inyectan un adaptador de host simulado y no contactan libvirt.

**Queda para R116-F2:** autorización independiente de alcance, arranque físico SSH→runner→FTP, revisión A3/cliente/servicio, staging autorizado del recuperador, atestación y armamento root efectivo, aplicación temporal de la política estrictamente FTP-T01 y captura física desde un único socket autorizado. Solo un resultado con procedencia real podrá continuar por R115-F13/F14 hacia A6; R116-F3 completará A7–A10 y TUI.

### Estado explícito

`P7=DRAFT`, `P8=NO-GO`, `A5 físico=NOT_ATTESTED`, `A6=ND`, `A7=NO_CONFIRMED`, `A8=NOT_APPLIED`, `A9=NOT_PUBLISHED`. No se reinicia ningún equipo, no se altera nftables y no se ejecutan conexiones durante la instalación F1.
