# ARDREC — P8-R24: frontera de suficiencia de pruebas por perfil

**Base protegida:** `7df89ca81d04a796fed86896c1e09e255f8f4bc0`, merge PR #56 (R23), CI posterior #42734632876. No se modifican las fuentes P7, P8, R9 ni los contratos R18–R23.

R24 produce una **matriz determinista y denegatoria** de 29 perfiles × 9 barreras = **261 obligaciones de acreditación aún sin verificar**, sobre el registro de R23, que conserva 348 campos materiales pendientes. Dos de las nueve barreras tienen **referencias estáticas candidatas** por perfil: identidad del ejecutable en la imagen R9 y metadatos de búsqueda del cargador R22 (58 referencias en total). La existencia, el hash SHA-256 o la procedencia de esas referencias **no prueban** identidad del binario que se usaría en tiempo de ejecución, resolución efectiva del cargador, capacidad de cliente ni configuración efectiva de servicio.

Los otros controles exigen, en fases futuras sujetas a autorización, pruebas específicas de la operación del cliente, configuración y alcance del servidor, autorización de caso/destino, plan de argumentos tipados y auxiliares anclados, presupuesto de recursos fijo, captura y procedencia de evidencias, y restauración/limpieza independiente cuando haya mutación. Las **cinco variantes de escritura** siguen sin acreditar limpieza. En las otras variantes la limpieza es condicional, no una afirmación de restauración comprobada.

La interfaz `inspect_claim` únicamente puede reconocer referencias estáticas rigurosamente tipadas con hash/origen fijo; aun si reconoce una referencia, devuelve `DENY`, nunca cierre de barrera, capacidad, autorización o despacho. La interfaz `deny_profile` deniega incluso aserciones hostiles. El verificador público ejecutado por CI utiliza solo fuentes públicas y **nunca lee recibos privados**. El colector privado de operador, si se ejecuta, autentica por hash el recibo R23 y crea un nuevo recibo R24 `0600` en carpeta `0700`, sin acceder a la QCOW2.

**No se acredita ni se habilita:** comandos/argv, acciones SSH/FTP/SMB, identidad runtime, `ld.so` efectivo, configuración servidor, casos, presupuestos, operaciones de escritura, pruebas de clientes ni autorizaciones. Cero perfiles aprobados, cero casos aprobados, cero despachos. P8, AL-06 y AL-07 siguen abiertos; P9 y A1–A10 no se inician.

**EN:** Source-pinned 29 × 9 proof-sufficiency boundary. Recognized offline references remain candidate-only and never grant operational authority.

## Resultado material R24 autenticado

Auditoría privada R24: autenticidad del recibo R23 comprobada por SHA-256; **29 perfiles** de **25 familias**, **261 barreras de suficiencia sin verificar** (9 por perfil), **348 campos materiales sin vincular**, **58 referencias candidatas estáticas**, **5 variantes de escritura con limpieza independiente pendiente**. La matriz rechaza toda elevación de evidencia candidata a capacidad efectiva o autorización. No se incluyen los bytes ni rutas del recibo privado en Git.

SHA-256 recibo privado R24: `68747c677b41dea3f5c5329075ddc1a97b1bf8f47d34bc7c07a54be67a5194aa`. SHA-256 matriz determinista: `e53900abea3d83ef27de6fc77e25d1698788a9616c90f696c5ea5781dbd6c5d2`. SHA-256 recibo privado antecedente R23: `42b7ff79f73d589be96a8d76e1bcb812a5374112679c277a23f598eeb851f1c3`.

**Cero perfiles aprobados, cero casos autorizados y cero despachos.** Sin acceso a QCOW2, ejecución invitada, identidad runtime, resolución efectiva `ld.so`, configuración de servicios, capacidad de opciones CLI, autorización de casos ni limpieza independiente. P8/AL-06/AL-07 permanecen abiertos; P9/A1–A10 no iniciados.
