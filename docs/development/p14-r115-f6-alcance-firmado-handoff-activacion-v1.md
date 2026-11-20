# P14 — R115-F6: decisión A3 de alcance firmado y entrega al arranque autorizado

Fecha: 2026-11-20. Rama: `feat/p14-r115-a3-p7-a6-real`. Base: `a652195a544a549dbad6a44120e3d447cf4d4994`.

## 1. Entrega funcional (todavía NO-GO)

`r115_f6_signed_scope_and_activation.py` conecta **un recibo físico F5 vigente y verificable** con la revisión criptográfica F3. Recalcula el estado F5 desde la captura sin confiar en un `report.json` declarado, y exige manifest y SHA exactos. La captura F5 tiene vigencia máxima de 120 s; una antigua no representa el host actual. Se conservan F1–F5 y sus formatos inmutables.

La salida ofrece las cinco guardas, causas, estado offline/active, bloqueos y cuál de los mecanismos **ya existentes** R112 debe emplearse después de autorización. No genera tickets F11, permisos root, ni `virsh start`; tampoco publica A9, recalcula Rf o admite evidencia A6. El ejecutor Rust y P8 continúan cerrados. Este incremento no es una aceptación de FTP-T01 ni de las 25 familias.

## 2. Contrato de autoridad independiente

`SCOPE_APPROVED` no se acredita por el mero documento del operador. Para realizar una revisión firmada deben existir:

- Contrato F1 válido y autorizado para `FTP-T01`, `DEV`, destino exacto, fuente/commit, límites finitos y referencias de cliente/perfil/autoridad.
- Documento de autorización F3 con firma Ed25519 verificable, referido por el SHA del contrato. El archivo lo presenta el operador, pero su firma debe corresponder a la política externa.
- Política de confianza en **ruta fija** `/etc/ardrec/r115-ftp-t01-trust-v1.json`, con dos claves públicas diferentes (autoridad de alcance y autoridad de revocación), esquema `ARDREC-R115-F3-EXTERNAL-TRUST-PINS-v1`. Debe estar instalada mediante procedimiento institucional independiente, ser de propiedad root y sus padres no ser modificables por grupo ni otros.
- Declaración firmada de revocación o no revocación con el esquema F3 en **ruta fija** `/etc/ardrec/r115-ftp-t01-revocation-v1.json`, instalada por la autoridad responsable, root-owned, actualizada hace un máximo de 90 s y dentro de su ventana. Se comprueba que corresponde a la autorización presentada.

Una declaración firmada de revocación causa FALSO. Documento ausente, fuentes root no verificadas, firma incorrecta o revocación vencida **nunca** produce autorización. La presencia de los dos archivos root por sí sola **no** prueba delegación institucional: los firmantes y el procedimiento de provisión deben auditarse por separado y conservarse de manera privada. No se crean claves, firmas ni credenciales automáticamente.

`SCOPE_APPROVED=VERDADERO` es solamente una verificación documental puntual bajo los supuestos anteriores. Antes de cualquier ejecución se requiere una **nueva decisión fresca**, prueba de revocación vigente, autorización distinta de arranque y del perfil P8, y las demás cuatro guardas verdaderas.

## 3. Interpretación exacta F5 y transición

| F5 | Estado | Ruta posterior, bajo otra autorización |
|---|---|---|
| `OFFLINE_DENY_BASELINE_MATCH` | Cuatro invitados OFF, nftables DENY y definiciones MATCH, 6 bindings ausentes normalmente | R112-F12 SSH y runner, seguido por R112-F10 FTP; cada arranque tiene contrato, intención durable y un solo inicio |
| `RUNNING_SIX_DENY_BINDINGS_MATCH` | Cuatro invitados RUNNING, seis bindings DENY: no hay ventana de tráfico | P8 perfil/cliente/servicio específicos, timer y mecanismo de revocación |
| `DRIFT_NO_GO` | Diferencia física acreditada | Reconciliar sin despacho ni restauración automática |
| `INCOMPLETE_OR_TRANSITION_NO_GO` | Estado parcial, no atribuible o aún en transición | Reconciliar comienzo/resultado antes de repetir |

Durante `OFFLINE_DENY_BASELINE_MATCH`, `SERVICE_READY=FALSO`, los otros controles sin fuente suficiente quedan `ND`, y A5/A6/P8 permanecen NO-GO/ND/NO-GO. En estado RUNNING con DENY seis/seis, tampoco se convierte aislamiento en una ventana P8 permitida. La existencia de una VM y un MAC no acredita autorización del destino.

## 4. Uso

- Solo revisión, sin firma todavía: `python3 -m ardrec.coordination.r115_f6_signed_scope_and_activation --receipt RUTA_PRIVADA_F5_ACTUAL`.
- Revisión firmada (sin ejecutar): añadir `--contract RUTA_PRIVADA_CONTRATO` y `--authorization RUTA_PRIVADA_AUTORIZACION`. La política y revocación no tienen argumentos de ruta: **nunca** se aceptan desde el mismo directorio del operador como raíz de confianza.
- El script de aplicación F6 crea una nueva captura F5 (sudo autenticado en la terminal y 18 consultas permitidas), ejecuta esta revisión inmediatamente, valida los previos, y guarda los logs en el directorio patches. No arranca VM ni repite la operación FTP-T01.

Proteger `/home/cicada/ardrec-lab` y los recibos originales; no publicar datos privados por error. La salida F6 incluye únicamente estados y hashes. La fecha del recibo es parte de su validez, no una autorización persistente.

## 5. Criterios de F6 y siguiente trabajo

- Test F6 + regresión F1–F5/R112–R114 aprobadas y aplicación exclusiva en Prometheus.
- Pruebas negativas de manifest, informe inventado, vencimiento, definiciones alteradas, trust ausente, escenario RUNNING sin P8 y salida NO-GO.
- Para habilitar arranque real, seleccionar **una** ruta existente R112 con consentimiento explícito independiente, reconciliar el estado antes de cada paso y no confundir el permiso de arranque con permiso de tráfico.
- Completar fuente P8 y perfiles ejecutables, atestación del cliente, servicio y destino, A3 real → A5 → A6 → A7 → A8 → A9 → A10 → TUI; aceptar resultados ND/negativos cuando correspondan. No editar retrospectivamente P7, R113 o recibos NO-GO anteriores.
