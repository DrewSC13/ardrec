# ARDREC R114-F1 — Admisión de resultados físicos SSH/FTP/SMB

Este incremento enlaza el recibo root inmutable de la única ventana F10R
`window-13af3370` (SHA-256 `8aecaaccafca822da5204aedd781bc64af44c79afa38e8ca1e091eadd6ea5363`)
con las respuestas originales de QGA y el cierre acreditado por F6.

**Alcance:** importar y reproducir evidencia física real *sin abrir tráfico*, sin ejecutar
QGA, sin cambiar VM, libvirt, nftables o systemd. El único acceso privilegiado es
`sudo -n /usr/bin/cat` contra siete nombres exactos de archivos root; el código
Python se ejecuta como usuario normal y escribe un recibo privado 0700/0600.

La prueba física demuestra:

* SSH: conexión TCP desde `10.203.30.1` a `10.203.30.2:22` y banner SSH-2.0.
* FTP: conexión TCP desde `10.203.31.1` a `10.203.31.2:21` y saludo `220`.
* SMB: conexión TCP desde `10.203.32.1` a `10.203.32.2:445`; ningún byte
  recibido y **no se confirma negociación SMB2**. Requiere investigación posterior.
* F6: restauración física de R34 DENY y seis bindings; `--attest-deny` al cierre.

Los archivos unitarios de test contienen datos artificiales **solo para ejercer
rechazos del analizador**. Nunca se reutilizan como resultados de laboratorio.

El resultado R114-F1 **NO** acredita vinculación de identidad A5 a las 54 unidades,
condición A6 de las 25 familias, vulnerabilidad confirmada, Rf, A9, generación
publicada ni despacho P8. La evidencia sirve como procedencia técnica para un
posterior mapeo de condiciones declaradas autorizado, no como puntuación automática.

No repetir F10R: su marcador `window-attempted.once` permanece consumido.
No hacer push ni merge hasta cerrar R111–R114. Conservar F10R y F7E sin modificaciones.
