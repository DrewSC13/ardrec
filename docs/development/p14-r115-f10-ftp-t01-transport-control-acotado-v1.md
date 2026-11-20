# ARDREC P14 / R115-F10 — Lector operativo de respuesta FTP-T01 con presupuesto finito

**Alcance:** primer componente de transporte A5 que trabaja con un **socket TCP ya conectado**; no constituye por sí mismo un intento A5 acreditado ni una ejecución permitida. El transporte se ha separado de la apertura de red, de A3/P7/P8 y de la admisión A6 para evitar que un lector de bytes pueda otorgarse autoridad.

## Punto de partida

R115-F9 consolidado con commit firmado `e0bb0bb3dabfb14ff64292bb3b2aa9a76fa3ad2b`. F9 ha constatado raíces de confianza `scope` y `boot` ausentes, autorización de alcance ND y P8 NO-GO. No debe iniciarse ninguna VM ni tráfico para instalar F10.

El catálogo P7 describe `FTP-T01`, condición **«Conexión de control FTP/FTPS a destino autorizado»**, con cinco guardas A3 y soporte `CONTROL_CHANNEL_RESPONSE`. Una respuesta del canal de control no prueba autenticación ni acceso a archivos.

## Nuevo contrato de software

Archivo `src/ardrec/coordination/r115_f10_ftp_a5_transport.py`:

- `receive_control_reply(connected_socket, current_p8_guard=..., limits=Limits(...))` consume exclusivamente un socket `AF_INET/SOCK_STREAM` que ya está conectado al único par permitido `10.203.31.2:21`.
- El módulo **no crea ni conecta sockets** y **no invoca `send`, `sendall`, `subprocess`, `virsh`, `sudo` ni cambios de nftables**. No inicia sesión, no solicita credenciales, no transfiere archivos y no intenta más de una observación.
- Presupuesto máximo interno: 10 segundos, 4.096 bytes, 16 líneas y 512 bytes por `recv` (límites seleccionables pueden ser inferiores). La apertura TCP y su presupuesto finito siguen siendo responsabilidad del futuro despachador P8.
- Verifica antes y después de cada `recv` un callback del *despachador* y aborta si se revoca. **El callback no constituye una firma, una autorización ni un mecanismo de confianza autónomo; F10 no puede revisar P8 por sí solo.**
- Interpreta una respuesta FTP de tres dígitos terminada en CRLF, incluidos los anuncios multilínea `220-...` hasta `220 ...`. Distingue `220`, `421`, datos incompletos, error de lectura, timeouts, respuestas malformadas y excedentes.
- Conserva los bytes capturados en Base64 y su SHA-256; declara siempre `a5_physical_origin_independently_attested=false`, `a6_classification=ND`, sin riesgo confirmado, transiciones ni generación. No persiste recibos como prueba operativa, no acredita A5 físico ni ofrece una API que publique A9.

`--capabilities` es el **único** comando de la CLI y no realiza tráfico. El módulo recibe un socket desde un despachador que aún no está implementado, por lo que no existe un modo autónomo ejecutable para conectar al FTP.

## Condiciones necesarias para completar el flujo

Antes de conectar un socket, el despachador P8 deberá: (1) verificar autorización independiente de alcance FTP-T01 y revocación actual; (2) acreditar la activación SSH→runner→FTP por recibos F7/F8, F11/R34 y las seis vinculaciones activas; (3) comprobar cliente, servicio y las cinco guardas A3; (4) obtener una ventana **independiente** de tráfico y presupuestos finitos exigidos por el ejecutor; (5) registrar de manera durable la reserva de intento único y su límite; (6) conectar únicamente el destino fijo. Durante la lectura deberá reevaluar vigencia/revocación. Posteriormente un atestador independiente ligará el A5 real y sus soportes y recién entonces A6 evaluará admisibilidad, dejando A7–A10 condicionales.

## Pruebas y límites

Las 28 pruebas F10 son de simulación local en memoria: socket preconectado simulado y callback simulado; **no son evidencia de laboratorio físico**. Se prueba lectura de 220, 421, multilínea, cierre prematuro, límite de bytes/líneas, timeout, malformación, IP/puerto erróneos, protocolo incorrecto, ausencia/revocación del callback y ausencia de promociones A6/A9.

El instalador R115-F10 debe comprobar el SHA del HEAD `e0bb0bb3dabfb14ff64292bb3b2aa9a76fa3ad2b`, su firma G, el árbol limpio, las huellas de los 30 archivos de F1–F9 y el catálogo. Solo añade cuatro archivos, ejecuta regresión y **no realiza un commit ni solicita sudo**. El cierre firmado de F10 debe ocurrir en un paso posterior después de verificar los resultados en Prometheus.
