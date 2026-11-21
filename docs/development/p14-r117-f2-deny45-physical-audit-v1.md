# R117-F2 — Comprobación temporal DENY 45 s, sin piloto de red

## Alcance

El incremento verifica la integridad de F12 efectivamente instalado, la preservación del expediente F8 y el estado físico 0/6. El modo `--inspect` es estrictamente de lectura. El modo `--run` requiere una invocación separada y consciente con permisos root; crea una marca persistente de uso único, programa `systemd-run --on-active=45s` y ejecuta exclusivamente el guardián F12 firmado mediante `--restore-deny`. Esta acción **escribe reglas nftables DENY**; no instala ninguna regla ACCEPT, no arranca invitados y no abre sockets. No se ejecuta en CI.

## Evidencia temporal

En la finalización, la medición usa `ExecMainStartTimestampMonotonic` y `ExecMainExitTimestampMonotonic`, expresados en microsegundos del reloj monotónico del anfitrión. Se compara con el instante en que se persistió la marca de uso único *anterior* al comando systemd-run. Exige arranque no anterior a 40 s y finalización en 60 s o menos. Los valores ausentes, invertidos o que exceden el umbral implican NO-GO, con recibo durable aun cuando la medición monotónica no esté disponible. Una evidencia válida acredita solamente esta ejecución concreta en DENY 0/6, no una garantía temporal absoluta ante fallos del host.

## Garantías de alcance

- F1/F3 autenticados mediante SHA-256, fuente Git firmada, manifiestos root y 33 fuentes fijadas.
- Archivado F8/R116-F11 y R114 sin alterar ni volver a consumir intentos.
- Contrato persistente `attempt.json` antes de armar timer; cualquier fallo posterior consume esa oportunidad y requiere revisión.
- `--finalize` solo puede releer, medir y cerrar el intento ya existente; no rearma.
- P7 sigue DRAFT, A6=ND, P8=NO-GO. No se acredita 5/1, recuperación desde ALLOW, ventana FTP, explotación, ni autorización.

## Cierre físico posterior

Los resultados de F2 permitirán decidir si el margen de 45/60 s es suficiente en la observación real 0/6. Para una eventual validación física 5/1 y del piloto P7 se requerirán autorizaciones independientes específicas, paradas autónomas y ausencia de sesgos temporales de CI.
