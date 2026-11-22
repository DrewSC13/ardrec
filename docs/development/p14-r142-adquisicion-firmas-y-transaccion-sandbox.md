# ARDREC — R142: lectura protegida, revisión firmada y recuperación en sandbox

## Objetivo

Conectar de forma determinista la adquisición de materiales R141 con la revisión
Ed25519 de R139 y la transacción durable R135/R140, sin crear un instalador root
operativo ni una ruta de activación de tráfico.

## Cadena implementada

1. `LockedTree` R141 abre una raíz **privada y no privilegiada** mediante descriptores
   de directorio y lee los trece archivos B4/B9, doce documentos externos y la
   referencia F8. Además lee `approval.json` como documento sin autoridad.
2. R142 separa exactamente los diez documentos de política operacional, los dos
   de liberación y la referencia F8, conserva los originales en memoria y
   verifica el encabezado declarado, `boot_id`, fuentes V2 y manifiestos.
3. R139 comprueba las firmas Ed25519, revocaciones, contratos, presupuesto,
   handoff, manifiestos y los doce firmantes distintos en las fuentes de prueba.
4. R140 invoca R135 para publicar exclusivamente en el sandbox privado. Antes
   de cada fase (`before_journal`, `before_b4`, `before_b9`, `before_receipt`),
   R142 **reabre y relee todos los materiales** y compara bytes/identidades con la
   captura inicial; R139 vuelve a verificar firma y vigencia.
5. R135 conserva journal, publicación exclusiva y recibo, sin sobrescritura ni
   reparación silenciosa. La recuperación de publicaciones parciales es probada
   con fallos inyectados y no autoriza ningún destino root.

## Riesgos que no quedan resueltos

- La lectura de una carpeta del usuario **no prueba la procedencia independiente**
  de los documentos root ni la identidad efectiva de las autoridades externas.
- `approval.json` es un documento capturado, NO una autorización de instalación.
- `source_commit_signature_verified` dentro de una declaración firmada es una
  afirmación del firmante: R142 no verifica independientemente la firma Git.
- R142 no valida físicamente los recibos históricos de arranque F7/F8 ni
  controla el arranque de máquinas o la restauración real de DENY.
- La relectura protegida y firma vigente durante el ensayo no confieren un permiso
  de escritura a los destinos root; `R135` recibe un callback sintético **solo**
  dentro de `/tmp/ardrec-r140-sandbox-*`.
- Ningún módulo R142 puede ejecutarse con `euid=0` para publicar.
- Los resultados se refieren a pruebas de laboratorio sintéticas en un árbol
  privado, sin comprobar que los documentos root reales estén provisionados.

## Aceptación

Treinta pruebas R142: casos positivos, resúmenes de fases, idempotencia, cuatro
recuperaciones de caída, modificaciones B4/B9, firmas, revocaciones, referencias
F8, head, boot, vencimiento, rutas y permisos, ataques de enlaces y cambios de
material en fases, prohibición root, alcance de sandbox y banderas NO-GO.

En Prometheus debe aprobar la regresión acumulada de 430 pruebas y producirse
un único commit local firmado, con `main` sin modificar.

## Siguiente frontera

La futura instalación privilegiada exige un agente root **instalado y
atestado independientemente**, origen externo de confianza, validación
independiente de la firma Git, autorización de instalación con revocación
actual, protección de rutas y transacción de destinos root con aceptación por
el responsable del laboratorio. Se debe implementar y probar de forma separada:
la aprobación sintética de R140 nunca se reutiliza para root.

Estados invariantes: A6=ND, A9 sin publicación, P8=NO-GO; ningún `virsh start`,
ningún `nft` mutante, ningún socket TCP/FTP, ningún `push`, PR o merge.
