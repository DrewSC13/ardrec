# ARDREC — P8-R9, inventario material observado (propuesta)

**Corte de código confirmado:** `main` `9bb8e06c5d007cac82a102a97a87ab909bb35d7b`, PR #40 integrado, firma del merge y CI previo/posterior verificados. El PR #41 A1 fue cerrado sin integrar; A1–A10 corresponden al punto 14 en adelante.

**Punto actual:** 8, perfiles de ejecución autorizados. El objetivo de R9 es pasar de las propuestas materialmente no verificadas a un inventario observable y reproducible. El paso 9 (supervisión real), los puntos 10–13 y los algoritmos no se inician en este cambio.

Se recopilaron por lectura de la imagen base del runner Debian 13: huella SHA-256 de la QCOW2 registrada y contrastada, imagen sin `backing file`, cuatro versiones de paquetes coincidentes con `lab/services-v1/versions.json`, y 15 SHA-256 de archivos ejecutables observados bajo `/usr/bin`; `sshpass` no está presente. Esta información procede de una ejecución de lectura comunicada por el operador; no se confunde con un certificado criptográfico emitido por un tercero ni con una atestación del binario en uso futuro.

La relación de 29 perfiles con tres ejecutables candidatos se registra **sin demostrar compatibilidad funcional ni otorgar permisos**. Los 29 perfiles siguen bloqueados. Las etapas P6 registran cero casos, el presupuesto numérico piloto es `null`, las autorizaciones privadas no se han verificado y no hay despachos, herramientas ejecutadas o validación experimental.

**Gates aún abiertos:** (1) procedencia confiable de imagen y materiales, (2) resolución de binario/dependencias y transferencia protegida al supervisor, (3) parámetros `argv` seguros y fijados por familia, (4) variables de entorno y auxiliares, (5) casos P6 y destino autorizados, (6) presupuesto de piloto calibrado, (7) limpieza/captura, (8) autoridad privada y revocación, (9) límites efectivos y aislamiento de ejecución que deberá demostrar P9. AL-06, AL-07 y las siete obligaciones previas siguen abiertos.

**Estado documental:** P8-R9 es una **propuesta source-only** hasta que CI y merge protegido sean verificados. Las fechas/etiquetas de propuestas históricas R4–R8 no se reescriben retrospectivamente.

**EN:** P8-R9 proposes versioned, operator-observed read-only runner-binary hashes and strictly blocked per-protocol tool candidates. No trusted authorization, full profile pin, executable dispatch, A1–A10, or experimental acceptance is inferred from matching bytes.
