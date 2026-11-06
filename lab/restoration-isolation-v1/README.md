# Restauración y aislamiento de desarrollo / Development restoration and isolation

## Español

Registro del punto 5 sobre la base `37d4ce27c565fc8fce8a963d090e4325799797a2`.
Los resultados proceden de ejecuciones locales del operador, cuyos archivos se
revisaron por huella, recibos, registros y cadena de eventos. No son una ejecución
remota del revisor ni una validación experimental de ARDREC.

| Comprobación | Evidencia y resultado | Límite |
|---|---|---|
| Bases | Cuatro bases independientes fijadas por SHA256; corrección FTP incorporada | No son la muestra experimental |
| LAB-V04 | Tres objetivos, 18 modificaciones controladas, persistencia tras reinicio y restauración desde la base; nueve arranques | Runner y evidencia externa no se restauran; no prueba contadores analíticos todavía no integrados |
| LAB-V02 | 17 controles funcionales; seis bloqueos de salida del invitado; 63 tramas prohibidas con incremento del contador correspondiente | Testigos propios; no se sondearon LAN ni Internet reales |
| Testigos | Tres interfaces recibieron controles positivos antes y después; cero tramas prohibidas observadas | La ausencia de tráfico se interpreta junto con los contadores y controles positivos |
| LAB-V03: reinicio | Cuatro VM apagadas y arrancadas; topología, configuración y conexiones TCP verificadas | No equivale a corte físico de energía |
| LAB-V03: interfaz | Apertura, cierre, nueva conexión y cierre final de virt-manager 5.1.0; proceso nuevo en reapertura | Observación asistida por operador; no automatización de la interfaz |
| Limpieza | Apagados por agente sin fuerza, recursos temporales retirados y firewall ajeno equivalente antes/después | Se conservan discos de evidencia sellados y registros |

La comprobación usa KVM/QEMU y libvirt, tres redes sin NAT ni dirección del
anfitrión, reglas bridge de nftables y reglas de compatibilidad limitadas a las
interfaces del laboratorio. El runner conecta exclusivamente a sus objetivos
SSH, FTP/FTPS y SMB. Las tramas de prueba verifican por separado el filtro del
anfitrión, incluso cuando se omite deliberadamente el filtro de salida invitado.
Los testigos de LAN, Internet, piloto y experimento son destinos sintéticos propios.

### Restauración y custodia

1. Detener el objetivo y confirmar que ningún dominio usa su disco antes de operar.
2. Verificar la base de solo lectura y su huella contra el recibo privado.
3. Conservar el overlay anterior como evidencia; crear otro overlay con nombre nuevo.
4. Contrastar identidades, cuentas, permisos, configuraciones y recursos sintéticos.
5. Conservar registros y estado del controlador fuera de los discos restaurados.

Restaurar un servicio no reabre estados CERRADO o DETENIDO, no elimina intentos
confirmados ni autoriza repetir una ejecución incierta. Este ensayo acredita la
separación del almacenamiento de evidencia y los objetivos; la recuperación del
estado analítico completo y sus contadores sigue siendo una obligación posterior.

### Condiciones de parada

Detener ante huella o versión distinta, recursos insuficientes, VM o red ajena
en el alcance reservado, cambio de topología/firewall, fallo de servicios,
trama prohibida observada, falta de controles positivos, tiempo agotado o
confirmación no recibida. No repetir automáticamente el intento.
Apagar exclusivamente los dominios creados por el ensayo. Si no se puede confirmar
su parada, conservar la contención y registrar fallo; nunca vaciar el firewall
global ni detener recursos ajenos. Un apagado forzado no acredita PASS.
Preservar registros e imágenes de cada fallo y revisar antes de recuperar.

### Alcance del cierre

El punto 5 se completa para el laboratorio de desarrollo probado cuando este
registro se revise e integre. No cierra AL-06/AL-07 ni las siete obligaciones de
desarrollo. La separación completa dev/piloto/experimento corresponde al punto 6;
perfiles autorizados al 8; supervisión al 9; recuperación y pérdida física de
energía al 12. No cortar la energía del equipo personal.
El ejecutor real continúa bloqueado por las obligaciones residuales.

Las huellas públicas están en [record.json](record.json). Los ZIP y recibos
originales permanecen privados: no publicar credenciales, claves, registros del
anfitrión, inventario de recursos ajenos ni capturas de pantalla.
El plan histórico `lab/verification-plan-v1.json` conserva su condición original;
este registro incorpora los resultados posteriores sin reescribir el pasado.

Verificación documental: `python3 lab/verify_restoration_isolation.py`.
CI comprueba consistencia del registro; no vuelve a ejecutar las pruebas físicas.

## English

This is a scoped development-laboratory record based on locally collected,
hash-checked evidence. Three targets underwent controlled changes, reboot and
restoration; external evidence was preserved. Four immutable bases include the
FTP correction. Isolation passed 17 service checks, six guest-output denials and
63 exact frame-drop checks using three owned witnesses with positive controls.
Four domains were cold-started; GUI opening and reconnect were operator-observed
and corroborated by process lifecycle, network topology and firewall records.

The GUI connection itself was not automatically inspected. Third-party probing,
physical power loss, analytical rollback, system acceptance and experimental
validation are not claimed. AL-06/AL-07 and seven development obligations remain.
Historical records and failed attempts are preserved. Stop on drift, unavailable
controls, prohibited traffic, timeouts or uncertain cleanup. Restore only stopped
targets into new overlays; retain controller state and evidence outside them.
Restoration must not reopen terminal analytical states or retry uncertain attempts.
Public CI validates document consistency only. Original receipts and archives are
private; the public JSON contains checksums and bounded conclusions.
