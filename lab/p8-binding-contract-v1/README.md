# ARDREC — P8-R4: contrato de vinculación y autorización por caso

## Español — alcance

Incremento **de código fuente y diseño**, basado en la tesis ARDREC con SHA-256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`,
secciones **3.7.5** (restricciones, presupuesto, limpieza) y **3.9.2** (ejecutor).
Base de integración P8-R3: `5855ac8956b1672c698919e3c8c87b2cfa1c1823`.

El contrato **NO promueve** los 29 perfiles del registro P8, **NO modifica** los
manifiestos P6/P7/P8 ni los componentes Rust, y **NO valida** herramientas reales,
cuentas, red, aislamiento, credenciales, archivos ni firmas privadas. Su éxito solo
acredita una gramática estricta y un estado documentado de **denegación total**.

### Límites de confianza

- P6 determina la etapa, el servicio y el escenario registrado. P7 debe derivar el
  caso desde ese escenario. P8 determina familia, variante, precondiciones,
  parámetros materiales, soportes, precedencia y limpieza. Una propuesta no puede
  redefinir ninguna de estas fuentes. **Hoy P6 tiene cero escenarios registrados**;
  ningún contrato material vivo puede pasar por esta línea base.
- `assess_synthetic_candidate` es una función pura **para pruebas sintéticas**.
  Los objetos `trusted_case`, `profile` y `manifest` se consideran **supuestos**
  suministrados por el llamador. Esto NO es una puerta operativa; una integración
  futura deberá cargar fuentes confiables verificadas y derivar el caso usando P7,
  no suministrarlos arbitrariamente. El éxito sintético no concede autorización.
- Los once campos de vinculación **previos** al despacho incluyen ruta, digest,
  versión, argv tipado, directorio, entorno, auxiliares, autorización, destino,
  presupuesto y política de captura. Su aspecto sintáctico NO prueba los bytes
  reales ni la procedencia del ejecutable, ni resuelve TOCTOU, permisos AL-07,
  scripts embebidos u opciones propias de cada herramienta.
- `cleanup_receipt_ref` es el campo **posterior**; no puede aparecer en una
  propuesta. Para escritura de marcadores, el plan y verificación independiente
  son prerrequisitos previstos; el recibo solo existe si hubo una ejecución
  acreditada y limpieza efectivamente constatada.
- El sobre de autorización propuesto identifica emisor, operador, etapa,
  escenario, servicio, caso, perfil, destino, acción, vigencia y referencia a
  revocación. El único estado permitido aquí es `PROPOSED_NOT_VERIFIED` con
  revocación `UNKNOWN`. No autentica emisor, firma, reloj, vigencia efectiva,
  revocación, alcance físico ni permisos. No almacena valores secretos.
- Los presupuestos finitos de **propuesta** (`timeout_ms <= 60000`,
  `max_stdout_bytes` y `max_stderr_bytes <= 1048576`, etc.) son topes de
  revisión sintética, **NO límites operativos aprobados por piloto**. Un límite
  `null` jamás autoriza infinito; un segundo intento requiere preautorización
  posterior explícita, jamás reintento oculto.
- Guardas trivalentes `VERDADERO`/`FALSO`/`ND`: una declaración de `VERDADERO`
  con referencia de soporte tampoco acredita su veracidad; `FALSO` y `ND`
  permanecen en `unmet_preconditions` y **nunca** habilitan un despacho.

### Contratos comprobables

`python3 lab/verify_p8_binding_contract.py` verifica **solo lectura** la línea
base P6/P7/P8 usando el validador P8-R3 y contrasta el contrato versionado.

`python3 -m unittest discover -s lab/tests -p test_p8_binding_contract.py -v`
comprueba derivación relativa, enlaces entre protocolos/etapas/casos, parámetros,
variantes, presupuestos, propuestas de autorización, limpieza pre/post, digest
meramente declarado, rechazo de shell y ausencia total de despacho.

Ninguna propuesta privada se admite por CLI ni se serializa en documentos públicos.
La siguiente subetapa necesita **escenarios de desarrollo realmente registrados y
sus soportes privados**, antes de elegir binarios/argv y comprobar autoridad
material. P9 supervisará procesos solo después de esta cadena; AL-06, AL-07 y
las siete obligaciones de desarrollo siguen abiertas.

## English — bounded claim

P8-R4 introduces a **read-only, deny-only contract** and a synthetic semantic
oracle for future P6→P7→P8 per-case proposals. Candidate file digests, authority
windows, cleanup plans and bounded budgets are only declarations. No registered
real cases, pinned binaries, trusted private issuers, executed attempts or experimental
units are added. The 29 existing profiles remain unbound. No dispatch or approval is
implemented; P9 and all outstanding safeguards stay pending.
