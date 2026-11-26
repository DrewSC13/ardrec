# R315 — Prevalidación integral de lotes DEV / DEV batch preflight

## Español

La entrada `caso prevalidar-lote-dev` acepta el mismo manifiesto, huella y
archivo privado que R307. Calcula las proyecciones documentales y sus huellas
esperadas, verifica las valoraciones existentes y los archivos nativos ya
instalados aunque falte el índice. Devuelve el esquema de previsualización
R315, distinto del resultado persistido R307. Los estados distinguen una
proyección nueva, una recuperable y una reabierta. No crea archivos ni índices;
las lecturas nativas pueden adquirir el bloqueo existente y sincronizar bytes.

La preparación R307 reutiliza esta fase antes de persistir ninguna valoración
nueva. Una discrepancia en una instantánea existente sin índice, un archivo
nativo inválido o un índice incompatible impiden iniciar la escritura del lote.
La huella de valoración prevalidada se exige antes de crear su registro.
Las huellas esperadas se derivan del formato nativo de archivo y se contrastan
con su resultado. No se cambia el formato histórico ni el archivo nativo.

No existe transacción atómica global. Cambios concurrentes, fallos del medio
o interrupciones después de prevalidar pueden dejar registros anteriores
persistidos. Los restos pendientes del archivo nativo no se promueven. La
previsualización no acredita A3, A6, Rf, A9 operacional ni una observación.
AL-06/AL-07 permanecen abiertos y P8 NO-GO.

## English

The existing DEV batch coordinator gains a preflight-only command. It computes
expected native snapshot addresses, validates existing assessments and installed
snapshots including those missing an index, and returns an explicitly distinct
preview schema. Batch preparation reuses this preflight before writes and checks
assessment identity before persistence. Native archive format and R307 result
format are unchanged. There is no global atomicity or operational authority;
concurrent changes and interruptions may leave earlier valid records. No
technical execution, evidence admission or experimental observations are created.
