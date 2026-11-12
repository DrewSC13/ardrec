# ARDREC — P8-R30: aceptación sintética por operación FTP/SMB

Estado: incremento source-only propuesto sobre merge protegido `a3ecc122bcd5819c6a211174ac33214bb19bc021`; no es integración hasta firma, PR y CI aprobadas.

R30 incorpora un oráculo puro para los **21 perfiles FTP y SMB**. Para cada operación exige la secuencia exacta de soportes definida en R1 y conciliada mediante R29; rechaza campos adicionales, pruebas atribuidas a ejecución real, promoción de autoridad, resultados indeterminados presentados como éxito, confusión control/datos TLS, firma/cifrado SMB y omisión de limpieza en mutaciones.

La función `evaluate_synthetic` clasifica resultados únicamente dentro de fixtures sintéticos. Incluso el vector completo y positivo es `SYNTHETIC_POSITIVE_ORACLE_NOT_RUNTIME_PROOF` con decisión final `DENY`. No hay `argv`, shell ni conexión. Esta implementación crea mecanismos de validación de resultados esperados y casos negativos para el futuro diseño experimental, sin declarar experimentos realizados.

Continúan: 29 perfiles bloqueados (incluidos los ocho SSH), 348 campos materiales pendientes, 261 barreras de suficiencia pendientes, 271 enlaces documentales y 238 enlaces de riesgos. Las cinco variantes mutadoras globales mantienen limpieza independiente pendiente; los recibos R27/R28 permanecen privados sin lectura en CI.

Próxima dependencia material: capacidades efectivas de cliente, carga real, configuración de cliente/servidor, aislamiento y autoridad por caso. Esas pruebas no pueden inferirse de los oráculos y necesitarán alcance y permisos específicos. P8, AL-06 y AL-07 abiertos; P9 y A1–A10 no iniciados.
