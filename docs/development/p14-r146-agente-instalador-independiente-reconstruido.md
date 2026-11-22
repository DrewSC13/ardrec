# ARDREC · R146 — Reconstrucción del agente independiente B4/B9

## 1. Origen, base y alcance

R145 no encontró ningún `*R131*.zip` en los tres directorios examinados en Prometheus. La copia del repositorio tampoco contiene un instalador R131 recuperable por su ruta histórica. **R146 es un componente nuevo:** no reutiliza la identidad, firma, digest ni presunta autoridad del script R131 faltante.

Base requerida: HEAD R143 `8256c1ee7eaff0facbfc62f1f9220d139228dd89`, árbol `0d3753d4e0e65fbb9386fc576b434368299cc4b1`, rama única `feat/ardrec-cierre-operacional-experimental`, `main` inalterada. R146 añade un núcleo de validación y transacción, un agente root candidato, el generador de expediente y sus pruebas. **El aplicador nunca ejecuta `--install`, sudo, virsh, nft, systemctl, un socket FTP ni cambios bajo `/opt`, `/etc` o `/var/lib`.**

El agente solo podrá ejecutarse con privilegios si una persona/autoridad independiente lo revisa, lo instala en una ruta root-owned fija y aprovisiona auténticas claves públicas, permisos, revocaciones y recibos. Todas esas condiciones faltan en R144. La firma Git del desarrollador y 70 pruebas simuladas no son una autorización administrativa o física.

## 2. Componentes y ubicaciones fijadas

| Objeto | Ubicación de operación | Condición |
|---|---|---|
| Agente | `/opt/ardrec/r146-installer-v1/installer.py` | Solo un administrador independiente lo instala y verifica |
| Runtime revisado | `/opt/ardrec/r146-installer-v1/runtime/` | Solo módulos R135, R136, R139 y R146; manifiesto y SHA |
| Manifiesto de agente | `/opt/ardrec/r146-installer-v1/manifest.json` | Head, tree, huellas por archivo, JSON canónico, root:0600 |
| Depósito B4/B9 y permiso | `/var/lib/ardrec/r146-source-drop-v1/` | Root:0700, B4 y B9 root:0700, archivos root:0600 |
| Journal/receipt/lock | `/var/lib/ardrec/r146-install-state-v1/` | Root:0700, exclusivo, duradero, sin reinicio destructivo |
| Confianza de instalación | `/etc/ardrec/r146-install-trust-v1.json` | Root:0600, autoridad independiente |
| Revocación de instalación | `/etc/ardrec/r146-install-revocation-v1.json` | Root:0600, firmante diferente, frescura ≤30 s |
| Destino B4 | `/var/lib/ardrec/r126-ftp-session-guard-v1` | Sin sobrescritura |
| Destino B9 | `/var/lib/ardrec/r128-one-session-v2` | Sin sobrescritura |

Los diez documentos de alcance, piloto, ventana y tráfico y las dos políticas de liberación B9 siguen en sus rutas `/etc/ardrec/` fijadas por R141. La referencia F8 se conserva en la ubicación histórica root. R116-F1/F3 **no se reemplazan**: se cotejan con los SHA-256 ya acreditados. Los firmantes operacionales son **12 claves** de seis ámbitos; instalación agrega **2 claves distintas**. Identidades de clave distintas no prueban personas independientes, separación de funciones ni autorización institucional: eso lo atestigua el administrador por fuera de la aplicación.

B4 V2 `f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8`. B9 V2 `c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3`. R116-F1 `c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7`, R116-F3 `37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c`.

## 3. Contratos de firma para el administrador

El fichero de confianza, JSON canónico, contiene exactamente `schema=ARDREC-R146-INDEPENDENT-ROOT-INSTALL-v1-trust`, `permit_signer`, `revocation_signer`; cada firmante `{key_id,public_key_pem}`. No introducir claves privadas en Git, ZIP ni chat.

El permiso está envuelto en `{statement, signer_key_id, signature_b64}`, firmado Ed25519 sobre bytes `b'ARDREC-R146-INDEPENDENT-ROOT-INSTALL-v1-permit\x00' + canonical(statement)`. Su declaración tiene exclusivamente:

- `schema=ARDREC-R146-INDEPENDENT-ROOT-INSTALL-v1-permit`
- `session`: 16 dígitos hexadecimales minúsculos; `head` y `tree`: SHA-1 de 40 dígitos de la revisión autorizada;
- `inventory_sha256`: hash del inventario de exactamente 13 archivos B4/B9;
- `source_b4_sha256`, `source_b9_sha256`: los dos pins fijos;
- `agent_bundle_sha256`: SHA-256 del manifiesto **exacto de runtime instalado**;
- `action=INSTALL_B4_B9_ONLY`, `destinations`: dos rutas exactas en orden B4/B9;
- `boot_id`: identidad vigente de `/proc/sys/kernel/random/boot_id`;
- `valid_from` y `valid_until`: UTC `YYYY-MM-DDTHH:MM:SSZ`, duración máxima 600 s y al menos 5 s restantes;
- `network_traffic_authorized=false`, `one_shot=true`, `p8=NO-GO`.

La declaración de revocación usa `{statement, signer_key_id, signature_b64}` firmada Ed25519 sobre bytes `b'ARDREC-R146-INDEPENDENT-ROOT-INSTALL-v1-revocation\x00' + canonical(statement)`; sus campos exclusivos son `schema`, `session`, `permit_sha256`, `issued_at`, `valid_until`, `revoked=false`, `reason_code`. La emisión debe tener **30 s o menos** y no puede provenir del futuro. La instalación reabre y comprueba confianza, permiso, revocación y las firmas B4/B9 **antes del journal, antes de B4, antes de B9 y antes del recibo**. No se inventan ventanas de tiempo ni se prolongan documentos.

El archivo `manifest.json` del agente no es una firma: el permiso auténtico ata su SHA-256. El manifiesto y su árbol deben ser autenticados por la autoridad externa; el desarrollador no se puede autoaprobar. El expediente público generado por `--prepare-public-readonly` contiene una plantilla verificable de ese manifiesto, **no un permiso**.

## 4. Máquina de estados y recuperación

Se utiliza journal de solo adición `install.json`, lock exclusivo con `flock`, dos directorios privados `pending-b4` y `pending-b9`, publicación B4 y después B9 por `renameat2(RENAME_NOREPLACE)`, fsync y comprobación de cada archivo desde su destino. Finalmente se emite `receipt.json`; todos los nombres y destinos son fijos.

Las interrupciones antes de B4, después de B4, antes/después de B9 y antes del recibo se reconcilian con el **mismo** plan, mismo HEAD/árbol, mismo inventario y un permiso vigente; no se borra el journal ni se realiza reemplazo de destinos. Si falta B4 cuando B9 existe, el entorno presenta deriva o un archivo publicado es alterado, la operación bloquea y conserva evidencia. Una escritura parcial/disco lleno conserva el estado inseguro de completar y exige revisión manual: **no se afirma recuperación automática de archivos parcialmente escritos**. La transacción no es atómica en los dos destinos. No hay rollback ni eliminación automática del guardián B4.

El núcleo `transact` admite callbacks de test para inyección de fallos; **la única ruta de instalación real** se define en el ejecutable root fijo y aporta el autorizador que relee la autoridad externa antes de cada fase. No llamar al núcleo desde un checkout Python elevado, ni usar los callbacks sintéticos R140/R142 en root.

## 5. Fuente firmada, entrega al administrador y ejecución

1. Incorporar R146 mediante su aplicador de usuario normal. Deben aprobar exactamente **536 pruebas acumuladas** antes del commit; no se hace push, PR, merge ni instalación root.
2. Desde el HEAD R146 limpio y firmado, generar **expediente externo** mediante `python3 -B scripts/ardrec_p14_r146_bootstrap_request.py --prepare-public-readonly` sin sudo. El ZIP público incluye las cinco fuentes a provisionar y los manifiestos, pero **ningún** permiso, certificado vivo, revocación privada ni clave secreta.
3. La autoridad independiente autentica Git, revisa código, hace el bootstrap root del agente, registra cadena de custodia y fuente/hash aprobados. Debe comprobar propietario root, 0700 en directorios, 0600 en archivos, ausencia de enlaces duros/simbólicos y medios de revocación vigente.
4. La autoridad externa obtiene las políticas y doce firmantes operacionales requeridos, los dos firmantes adicionales de instalación, documentos de alcance/piloto/ventana/release, referencia F8 y pruebas físicas que correspondan. Se crean permisos solo bajo el procedimiento institucional autenticado. No se facilitan secretos por chat.
5. **Solo después** el administrador autorizado puede evaluar la invocación de `/usr/bin/python3 -I -B /opt/ardrec/r146-installer-v1/installer.py --install` como root, con Python aislado y sin archivos bytecode. El modo rechazará toda ejecución fuera de esa ruta exacta o sin materiales firmados. La salida de prueba de checkout `--capabilities` no concede permisos.
6. Después de la instalación, se releen B4/B9 desde sus destinos, se verifican journal, receipt, modos, firmas y revocaciones. Si falla un paso, conservar NO-GO y planear recuperación con respaldo independiente.

## 6. Limitaciones y aceptación pendiente

Las pruebas unitarias verifican 65 escenarios de validación, instalación en carpetas de prueba y elaboración del paquete. **No se ejecutó la ruta root real ni se verificó su empaquetado con uid 0 en Prometheus**; requiere revisión de seguridad antes de una instalación efectiva. No se ha obtenido la autoridad externa ni la atestación física de F8, las 5/1 DENY, el watchdog autónomo de 45 s o las observaciones FTP-T01. El hecho de que `--install` exista no implica que sea correcto ejecutarlo hoy. A6=`ND`, A9=`NOT_PUBLISHED`, P8=`NO-GO`.

Registro de continuidad: R143 firma `8256c1ee7eaff0facbfc62f1f9220d139228dd89`; R144 observa 20 elementos root ausentes; R145 no recupera R131 ZIP; R146 reconstruye **nueva versión, nueva identidad de fuente y aprobación independiente obligatoria**. `main` se mantiene en `95a6d57b8241101c7a8fa3aedc07fb779b088d9f` hasta cierre A–D.
