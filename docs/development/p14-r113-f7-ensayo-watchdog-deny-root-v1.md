# R113-F7 — Ensayo físico del temporizador root DENY (sin tráfico)

**Alcance:** únicamente el laboratorio privado ARDREC de cuatro VM y seis interfaces. No modifica R55.8 ni el recuperador F6, no crea filtros `ALLOW`, no ejecuta QGA y no genera conexiones de protocolo. Se preserva `P8=NO-GO`.

## Predecesores obligatorios

- Rama `feat/p14-r111-r114-real-lab`, commit firmado `6cbfeaa0a465cbb6885726691b789fa54d30bb69`, árbol limpio.
- Evidencia F6R de 495 pruebas; instalación del paquete root `/var/lib/ardrec/r113-six-deny-guard-v1` acreditada, con 16 archivos autenticados.
- DENY real F6R: tabla `bridge ardrec_r34_guard` de cuatro reglas DROP y seis vinculaciones al filtro de contención. Su `root-recover.py --check-root-bundle` y `--attest-deny` deben aprobar **inmediatamente antes** de programar el temporizador.

## Modelo F7

Se programa **una sola vez** un timer transitorio de `systemd` del sistema, con nombre impredecible `ardrec-r113-f7-deny-<12 hex>`, `OnActiveSec=20s` y `AccuracySec=1s`. El servicio ejecuta exactamente `/usr/bin/python3 /var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py --restore-deny`, sin opciones de apertura. La programación y el marcador local `armed.once` se guardan antes de llamar a `systemd-run`; si la respuesta es ambigua, **no se reintenta**.

La evidencia verifica un temporizador activo vinculado al servicio correcto, después comprueba que el servicio realmente fue iniciado (`ExecMainStartTimestampMonotonic > 0`) y terminó con `Result=success`, y finalmente acredita de nuevo F6 DENY. La ejecución por systemd es independiente de la duración de la sesión del operador; no obstante, **el ensayo por sí solo no prueba recuperación tras un reinicio del host, ni sirve aún como autorización de una ventana de tráfico**. La siguiente fase deberá reacreditar el arranque protegido F11, el guardián en vivo y la revocación antes de crear filtros permisivos.

## Evidencia y reproducibilidad

El operador genera una carpeta `0700` bajo `/home/cicada/ardrec-lab/r113-f7-deny-timer-v1` con archivos `0600`: intención, marcador de intento, stdout/stderr de F6 root pre/post, timer, servicio, jornal acotado y manifiesto canónico con SHA-256. `--replay` no ejecuta `sudo`, no llama a systemd y rechaza capturas ausentes o alteradas. Una ejecución física incompleta conserva su carpeta y requiere conciliación manual; ni el operador ni el instalador realizan reintentos automáticos.

## Criterios de aceptación

1. Pasan 530 pruebas acumuladas (495 anteriores, 35 nuevas), commit firmado y árbol limpio.
2. F6 root check y deny attestation previas PASS.
3. Una autorización separada del operador para un solo timer root DENY.
4. El temporizador `systemd` está armado, su servicio se dispara y termina en éxito.
5. La atestación posterior recupera las seis vinculaciones y el R34 DENY, replay válido.
6. Ninguna regla ALLOW, ningún `guest-exec`, ninguna conexión de protocolo, no push/merge.

Este hito **no es** la admisión F8: no interpretar la prueba de timer como prueba de mitigación de fallo de alimentación o reinicio. Toda autorización posterior de red se debe emitir aparte y limitar a IP, puerto, MAC, tiempo y origen runner.
