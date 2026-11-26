# R335 — Integridad documental I2, I4 e I8 / Documentary integrity

## Español

La preparación I2 rechaza reutilización de identificadores con prefijo `PILOT-`
en caso, escenario e instancia de servicio tanto en la selección como al
construir directamente un candidato. I8 aplica la misma restricción a las
unidades registradas o excluidas. El prefijo no constituye autenticación de
identidad ni prueba que dos nombres distintos correspondan a instancias distintas.

I2 abre soportes con `O_NONBLOCK` para rechazar FIFO sin espera. I2 e I4
comprueban que el archivo leído sigue siendo el objeto identificado por su ruta,
con identidad, tamaño, permisos, propietario, enlaces y marcas de modificación
nanosegundo coincidentes. I2 también contrasta ctime antes y después de leer.
No se usa atime como indicador de cambio. No se garantiza atomicidad frente a
cambios posteriores ni se acredita semántica, frescura o custodia externa.

Las siete regresiones nuevas usan archivos privados y datos sintéticos. No
modifican los instrumentos originales ni la matriz de investigación. AL-06 y
AL-07 permanecen abiertos; P7 no congelado y P8 NO-GO.

## English

I2 rejects pilot-prefixed case, scenario and service instance identifiers on
both selection and direct candidate construction; I8 also rejects such service
identifiers for recorded and excluded units. Prefix checking is not identity
authentication. I2 opens supports nonblocking; I2/I4 recheck the named object
against the opened descriptor using identity and nanosecond metadata, excluding
atime. I2 also checks ctime across the read. No post-check atomicity, operational
authority, independent reference or experimental admission is established.
