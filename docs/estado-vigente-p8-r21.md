# ARDREC — P8-R21: conciliación de relaciones ELF pendientes

**Base:** merge `363f5ca7b34419e5a1da270907f9b89c768e6a08`, PR #53 (R20), CI posterior `42718164089` aprobada. Los recibos privados R19 y R20 continúan fuera de Git y fijados por SHA-256.

R20 obtuvo 64 nuevas bibliotecas ELF candidatas en el directorio privado de Samba, recuperó 67 relaciones de R19 y encontró 563 nuevas relaciones, de las que 8 quedaron sin candidato (5 SONAME diferentes). R21 añade búsqueda **conjunta por siete directorios** sin imponer prioridad de `ld.so`, registra alias canónicos y ambigüedad como resultados distintos, verifica material nuevo mediante lectura ELF offline de la imagen QCOW2 fijada, y conserva dependencias posteriores no resueltas. El contrato público rechaza estados de autoridad, configuración real y despacho.

La adquisición material R21 del operador es requisito para determinar resultados; **esta propuesta todavía no declara esa adquisición efectuada**. En un próximo registro, solo se incorporarán los conteos comprobados y el SHA del recibo privado, no los bytes de la evidencia.

**Límites:** no hay identidad dinámica de runtime, equivalencia de carga `ld.so`, compatibilidad real de CLI SSH/FTP/SMB, destinos o credenciales de casos, presupuestos autorizados ni limpieza independiente completada. Los 29 perfiles y las 348 vinculaciones del corte histórico permanecen pendientes de resolución material específica; las cinco variantes de escritura conservan requisitos propios. No se confunde compatibilidad estática con autorización ni se reescriben cortes históricos. P8, AL-06 y AL-07 siguen abiertos; P9 y A1–A10 sin iniciar. Cero perfiles/casos autorizados y cero despachos.

**EN:** Offline seven-directory candidate reconciliation only, not effective loader closure or operational case authorization.

## Resultado material offline R21 autenticado

Adquisición R21 comunicada por el operador y vinculada mediante SHA-256 del recibo privado verificado: **8/8 relaciones R20 recuperadas como candidatos**, **6 bibliotecas nuevas**, **51 relaciones DT_NEEDED nuevas**, **0 relaciones nuevas sin candidato**, **0 ambiguas** y **4 indicadores nuevos de rutas personalizadas**. Se inspeccionaron 6 SONAME; el recibo privado permanece fuera de Git.

SHA-256 del recibo R21: `79a9d6512cb3fccaafb90240b44d29d9747df798c34d2b956008161d667cbeff`. La observación NO acredita equivalencia con el cargador dinámico, identidad binaria en runtime, configuración real, autorización ni despacho. 29 perfiles bloqueados; cero casos autorizados. P8 sigue abierto.
