# ARDREC — P8-R14: fuentes completas y anclas de entradas CLI (propuesta)

**Base exacta:** `67c55f1bb2165a1edac25ecaf86e8638ef705548` (merge protegido de P8-R13 vía PR #46; CI pre y posmerge verificados).

Captura completa del contenido roff de 7 manuales, 485.755 bytes de documentación, SHA de cada fuente comprobado y SHA de la QCOW2 inalterado antes/después. La captura la efectuaron herramientas del anfitrión en solo lectura; ningún binario de la imagen invitada fue ejecutado.

Esta propuesta registra **91 entradas localizadas** por encabezado exacto dentro de las páginas íntegras, **25 límites de seguridad** y las **29 asociaciones de perfiles** previamente documentadas. A diferencia de los 91 fragmentos de R12, el catálogo R14 señala una línea estructuralmente correspondiente a cada entrada, evitando la confusión entre opciones cortas como `-o` y `-O`.

La localización del encabezado no certifica una revisión exhaustiva del comportamiento de ese flag: **0 revisiones semánticas completas, 0 opciones o gramáticas CLI ejecutables aprobadas, 0 renderizadores argv, 0 casos y perfiles autorizados, 0 despachos**. La evidencia privada de 640 KB no se publica en Git, pero se compara completamente en la estación del operador mediante `--private-full` y su hash conocido.

Persisten los límites contra intérpretes SSH, llamadas externas de configuración, lotes SFTP mutadores, degradación TLS, cadenas arbitrarias FTP/SMB/RPC, ambigüedad entre firma y cifrado y operaciones mutadoras sin limpieza independiente. La revisión posterior deberá cerrar gramáticas por herramienta, pruebas de semántica de argumentos, configuración efectiva e identidad de binario en ejecución antes de cualquier autorización.

**AL-06 / AL-07, P8 y siete obligaciones de desarrollo** siguen abiertos; P9, A1–A10, laboratorio físico y experimentos no iniciados.

**EN:** Full documentary capture and structural anchor audit only. The 29 symbolic profiles remain deny-only. This is not a runtime, network, or capability attestation.
