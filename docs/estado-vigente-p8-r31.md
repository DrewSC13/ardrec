# ARDREC — P8-R31: contextos de manuales reales ya capturados

**Estado inicial:** propuesta sobre el merge firmado de R30 `e7caa5c49cebb3c7258c07bbfe72d802da2ae64b`; el trabajo requiere validación en Prometheus, commit firmado, PR y CI antes de integrarse.

**Nueva evidencia prevista:** a partir del recibo privado original R14, ya capturado y fijado por SHA-256, se extraerán **39 ventanas acotadas de fuente roff real** para las **21 variantes FTP/SMB**. Se reutilizan las siete fuentes íntegras de R14 y se producen extractos privados exclusivamente de `curl.1`, `smbclient.1` y `rpcclient.1`. Cada ventana registra identidad de fuente, línea de ancla autenticada, SHA-256 del contexto, 24 líneas como máximo y los perfiles relacionados. El extractor se limita a ventanas arbitrariamente acotadas: **no afirma que recojan las cláusulas semánticas completas**.

La lectura privada es separada de CI y se activa mediante comando explícito de operador `inspect`/`extract`. **No abre la QCOW2**; valida los bytes auténticos almacenados en el recibo R14. Los extractos/recibos no se integran en Git, no se imprimen y se guardan una sola vez en archivos privados 0600, directorio 0700. El objetivo es disponer de material documental reproducible para una **revisión semántica humana posterior**, que todavía no se ha realizado.

No se certifican características operacionales de ejecutables, compatibilidad de CLI, precedencia de configuración, cierre del cargador, aislamiento, credenciales, presupuestos, casos, valores de flags o `argv`. R30 permanece como oráculo sintético de aceptación, no prueba de capacidad. Se mantienen 29 perfiles bloqueados, 348 vinculaciones, 261 barreras, 5 limpiezas pendientes, cero autorizaciones y cero despachos. P8/AL-06/AL-07 abiertos; P9 y A1–A10 no iniciados.

**EN:** Source-authenticated, private, bounded manual excerpts for semantic review. No automatic semantic completion, executable grammar, runtime proof, case authority, or dispatch.
