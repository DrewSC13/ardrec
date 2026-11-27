# Revisión semántica de contenido / Semantic content review

## Español

R363 integra la revisión de contenido de SSH-T06, FTP-T06
y SMB-T07 sobre recibos nativos y soportes materiales R362.

La referencia de contenido esperado se suministra mediante
un documento fijado externamente por huella, vinculado a la
identidad exacta del recibo incorporado.

Se compara la huella y longitud del recurso recuperado con
la referencia conocida. El soporte KNOWN_CONTENT_DIGEST debe
contener el registro canónico derivado de la identidad y del
contenido observado.

Se distinguen MATCH, MISMATCH, INCOMPLETE y
CONTRADICTORY_DIGEST_RECORD.

La igualdad criptográfica de contenido no acredita origen
físico, cronología, custodia de la referencia, identidad
efectiva del servicio ni cumplimiento de otros requisitos.

El formato R363 de registro de digest constituye un contrato
nuevo de implementación que deberá adoptar el productor
autorizado de soportes.

A6 permanece ND. No se confirma Rf ni se publica A9.

## English

R363 reviews known synthetic content for SSH-T06, FTP-T06
and SMB-T07 using native receipts and R362 material supports.

A separately pinned reference document binds expected content
to the exact identity of the incorporated receipt.

Observed content hash and size are compared against the
known reference. KNOWN_CONTENT_DIGEST must contain the
canonical record derived from receipt identity and observed
content.

MATCH, MISMATCH, INCOMPLETE and CONTRADICTORY_DIGEST_RECORD
are kept distinct.

Cryptographic content equality does not establish physical
origin, chronology, reference custody, effective service
identity or satisfaction of remaining family requirements.

The R363 digest-record format is a new implementation contract
that must be adopted by the authorized support producer.

A6 remains ND. No confirmed Rf or A9 publication is produced.
