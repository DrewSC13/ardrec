# R140 — Integración verificable de firmas y recuperación transaccional (solo sandbox)

## Propósito y resultado

R140 conecta **R139** (revisión de firmas y contratos B4/B9, liberación firmada y revocación) con **R135** (journal durable, dos publicaciones, readback, recibo y recuperación). Las mismas fuentes B4/B9 V2 y los diez firmantes operacionales y dos firmantes de liberación siguen sujetos a los validadores históricos. No crea identidades ni claves operacionales.

La integración se implementa mediante `r140_release_transaction_sandbox.exercise_sandbox()`. No es un instalador root: aborta cuando `geteuid()==0`, admite solo un directorio privado `0700` perteneciente al usuario bajo el directorio temporal del sistema y con prefijo `ardrec-r140-sandbox-`, y nunca escribe en las rutas root B4/B9.

## Contratos y estados

1. Verifica la revisión R139 antes de llamar R135.
2. Congela la identidad SHA-256 de los bytes y del inventario. Rechaza las modificaciones del material original entre fases.
3. El callback interno del sandbox vuelve a ejecutar la revisión firmada y la comprobación de vigencia **antes de journal, B4, B9 y recibo**. El callback es exclusivamente sintético: **no** es autorización root.
4. R135 escribe en el sandbox un journal durable, una carpeta publicada B4, otra B9 y un recibo, usando bloqueo, ficheros exclusivos, `fsync` y renombrado sin sobrescritura.
5. Un corte tras staging/B4/B9 o antes del recibo permite recuperar solo si el material y las revisiones actuales siguen siendo válidos. Alteraciones, expiraciones o revocaciones bloquean la reanudación.
6. Se rechaza el éxito ficticio: la salida codifica `installation_permission=false`, `root_install_executed=false`, `root_trust_provenance_verified=false`, `traffic_enabled=false`, `A6=ND`, `A9=null`, `P8=NO-GO`.

## Evidencia de prueba

30 pruebas R140 incluyen: publicación/idempotencia, cuatro controles de fase, fallos inyectados y recuperación, integridad de bytes, falsificación o pérdida de firmas, tiempo vencido entre fases, identidad de boot/HEAD, links, permisos, rutas fuera de sandbox, denegación a root y lectura de recibos adulterados. Se ejecutaron adicionalmente 18 pruebas R136 y 30 pruebas R139 en un entorno aislado sin privilegios: 78/78 PASS. La regresión conjunta objetivo en Prometheus es **360/360** y se ejecuta **antes** del commit R140.

## Frontera de seguridad no resuelta

- La confianza suministrada por R139 sigue siendo bytes del llamador, **no un ancla root autenticada**.
- Una afirmación firmada de «Git verificado» no sustituye comprobar realmente el commit, el tree, su firma y el agente instalador.
- Las ventanas temporales de los tests contienen claves efímeras y tiempos sintéticos: no deben trasladarse a `/etc/ardrec` ni a `/var/lib/ardrec`.
- El agente R134 no está instalado; R140 **no** invoca `--audit-root`, ni intenta manipular su ruta.
- No se ha ejecutado la transacción contra los dos destinos root reales, ni se ha probado fallas de alimentación bajo root; solo simula cortes transaccionales.
- No hay autorización operacional ni físicamente acreditada de VM, DENY 5/1, piloto FTP-T01, calibración P7 o A6.

## Siguiente entregable obligatorio

Crear un agente independiente, instalado fuera del checkout por autoridad autorizada, que autentique root `0700/0600`, procedencia de claves externas, firma del commit/tree y del agente, identidad de boot, contratos R136/R139 y revocación antes de **cada escritura**; debe tener recuperación no destructiva, no reutilizar esta API de sandbox y conservar el modo DENY. Solo con aceptación explícita y pruebas físicas independientes podrá gestionar los dos destinos root. Cualquier ambigüedad mantiene NO-GO.
