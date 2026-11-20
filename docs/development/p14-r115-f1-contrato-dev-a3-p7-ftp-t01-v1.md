# R115-F1 — Contrato DEV estático y límites para FTP-T01

## Propósito y alcance

Inicio verificable y **no operacional** de R115 en la rama `feat/p14-r115-a3-p7-a6-real` basada en `a652195a544a549dbad6a44120e3d447cf4d4994`.

Se incorpora un validador Python puro, con salida JSON determinista, para un contrato individual FTP-T01 y límites DEV finitos. **No autoriza tráfico, no levanta VM, no cambia P7, no transforma A3 ND en VERDADERO, no admite A6, no calcula A7 ni publica A9.** Mantiene intactos los recibos y verificadores R114 y el catálogo histórico. Un documento de entrada y sus SHA-256 son únicamente referencias, no autoridad autenticada ni pruebas de vigencia.

## Esquema de entrada

`ARDREC-R115-F1-DEV-FTP-T01-PREFLIGHT-v1`. Campos requeridos exactamente: `schema`, `case_id`, `family_id=FTP-T01`, `stage=DEV`, `created_at`, `valid_from`, `valid_until`, `source_commit`, `catalog_sha256`, `target`, `client`, `profile`, `authority`, `isolation`, `service`, `limits`. Las fechas son ISO-8601 con zona; el intervalo no supera 24 horas. `target`: VM, red y dirección del segmento FTP DEV, puerto 21, MAC con forma válida; **la MAC no se compara todavía con virsh**, pendiente de adaptador real.

Las cinco referencias `client`, `profile`, `authority`, `isolation`, `service` usan `{id, sha256}`; el validador NO consulta esas fuentes ni acredita autenticidad. Sus cinco guardas A3 se mantienen `ND` incluso con un contrato formalmente válido. Este diseño impide que el autor de un JSON pueda autootorgarse permiso.

Presupuesto de una tentativa ordinaria y **cero tentativas adicionales**; cotas estáticas máximas de R115-F1: duración 120 s, operaciones 20, solicitudes 20, transferencia 65536 bytes, salida 65536 bytes, memoria 512 MiB. Son límites *DEV de validación estática*, **no límites operacionales calibrados ni aplicados por un ejecutor**. Cada perfil debe declarar enteros positivos menores o iguales a esas cotas. Los límites reales del ejecutor deben ser verificados antes de habilitar una acción.

## Comprobación sin operaciones físicas

`PYTHONPATH=src python3 -m unittest discover -s lab/tests -p 'test_p14_r115_f1_*.py' -v`

`PYTHONPATH=src python3 -m ardrec.coordination.r115_dev_admission_contract --contract <contrato-privado.json> --catalog lab/operational-catalog-v1/catalog.json`

El comando no crea archivos de resultados, no accede a servicios y no registra secretos. El contrato que contiene la referencia de autoridad se mantiene privado. No se adjunta un contrato habilitado, ni de ejemplo, que pueda interpretarse como autorización.

## Siguiente capacidad requerida

R115-F2 debe vincular las referencias a fuentes confiables y actuales, hacer comprobaciones de aislamiento/identidad/cliente/servicio, y verificar autorización firmada/emitida por autoridad independiente, revocación y vencimiento. Debe mantener FALSO/ND cuando corresponda. R115-F3 integra con A5/A6 solo tras autorización específica y presupuestos efectivamente aplicados. R115-F1 **no es cierre de R115**.
