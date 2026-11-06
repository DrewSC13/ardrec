# Punto 7 — Catálogo operacional / Step 7 — Operational family catalogue

## Español — alcance verificable

**Fuente normativa:** tesis ARDREC vigente, SHA-256
`6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, sección
**3.7** y tablas 3.7–3.12 (páginas impresas 134–143). Punto de partida Git:
`f803ba28af310f3c08dc33dddbd0c22522d2377f` (P6 integrado).

`catalog.json` contiene exactamente **25 especificaciones familiares**: SSH-T01…T08,
FTP-T01…T08 y SMB-T01…T09. Cada familia define la afirmación y operación mínima
acotada, precedencia, precondiciones, parámetros materiales representados **solo
como referencias**, soportes obligatorios, condiciones de aceptación, limitación
interpretativa y política de limpieza. Las variantes mantienen explícitamente la
separación de canales FTP control/datos, comparación lectura/escritura y protección
SMB firma/cifrado. Las acciones son **descripciones**, no comandos ejecutables.

### Identidad y derivación

La tesis define `SERVICIO-CASO-id_i-nn`. Aquí la familia es `SSH-T03`, por ejemplo;
`id_i` se aporta con un código de escenario ya documentado (`Snn` en la interfaz
inicial del catálogo) y `nn` es un ordinal explícito. El formato generado sigue
`SSH-T03-S01-01`, **exclusivamente como identidad sintáctica**, nunca como evidencia de
un caso real. No se asignan `S01` ni ordinales a ninguna de las 54 unidades previstas.

La función pura `derive_case(root, request)` del verificador construye en memoria un
descriptor `DRAFT_NOT_AUTHORIZED` **solo cuando el servicio–escenario figura en su
manifiesto de etapa P6** y el protocolo coincide. Los parámetros son referencias
simbólicas (`ref:...`), nunca contraseñas, secretos, rutas de ejecución arbitrarias ni
herramientas invocables. `derive_batch` rechaza identificadores duplicados. La
función no escribe ficheros, no consulta la red, no solicita ejecución, no verifica
físicamente guardas y no actualiza la muestra experimental. Los fixtures con
escenarios sintéticos existen únicamente dentro de tests temporales.

**Hoy hay 25 familias y cero casos derivados reales**, porque P6 documentó cero
escenarios efectivos en los tres manifiestos. No sería válido afirmar la existencia
de 25 casos experimentales ni congelar 54 unidades antes de los pasos de piloto.

### Contratos operacionales documentales

- **Elegibilidad:** todas las guardas comunes (autorización, laboratorio aislado,
  destino fijado y cliente compatible) deben acreditarse en su momento; `ND` y
  `FALSO` no habilitan. Precedencia 1–4 solo desempata candidatos aplicables; no
  establece autorización ni satisface dependencias por sí misma.
- **Clasificación:** se preservan las seis clases de tesis: `POSITIVO_VALIDO`,
  `NEGATIVO_VALIDO`, `INCONCLUSO`, `INCIDENCIA`, `INVALIDO`, `NO_ADMITIDO`. Los
  soportes planificados NO son evidencia admitida: A6 decidirá después sobre su
  integridad, procedencia, pertinencia y suficiencia. Una negativa no observada es
  `INCONCLUSO`, no `NEGATIVO_VALIDO`.
- **Límites:** una ejecución ordinaria por caso y repetición adicional solo con
  preautorización. Los límites numéricos de segundos, operaciones, transferencias,
  salida, RAM y solicitudes se fijarán mediante piloto y congelamiento. Aquí todos
  figuran expresamente como `null`, **no como infinito ni como cero autorizado**.
  El ejecutor no debe aceptar estos perfiles incompletos.
- **Seguridad:** solo identidades y recursos sintéticos y autorizados. Prohibidos
  fuerza bruta, `password spraying`, enumeración sin límite, persistencia,
  explotación destructiva, objetivos externos, cambios en cuentas, permisos,
  claves o archivos existentes, ampliación dinámica de alcance y reintentos ocultos.
- **Escritura:** SSH-T07, FTP-T07 y SMB-T08 exigen crear solo marcadores preparados,
  verificar y retirar. La limpieza es un soporte independiente. FTP-T08 y SMB-T09
  exigen limpieza de marcadores si la variante examinada es `WRITE`.
- **Precedencia especial:** FTP-T02: canal `CONTROL` → nivel 1 y `DATA` → nivel 3;
  SMB-T03: `SIGNING` y `ENCRYPTION` son casos distintos de nivel 3; FTP-T08/SMB-T09:
  `READ` → nivel 3 y `WRITE` → nivel 4. Nunca derivar una condición a partir de otra.
- **Obligaciones condicionadas:** TLS de datos exige sesión y canal de datos preparados;
  TLS de control no presupone observar datos. La variante SMB firma no necesita
  prueba de cifrado, ni viceversa. Comparaciones `WRITE` añaden explícitamente
  preparación de marcador y acreditación separada de limpieza.
- **Resultados:** el identificador de familia o el producto/versionado no demuestra
  vulnerabilidad ni explotabilidad. Las extensiones `*-VUL-nn` de la tesis no forman
  parte de estas 25 familias y siguen sin autorización ni definición operativa.

### Límites del incremento y continuidad

Este incremento no define un `argv`, ejecutable, perfil de subprocess, entorno,
credencial efectiva o destino operativo: eso corresponde al **punto 8**. No arranca
SSH, FTP o SMB; no crea credenciales, artefactos, VM o redes; no modifica los
registros históricos ni habilita el ejecutor. La custodia de frescura, tolerancia a
fallo de energía y AL-06/AL-07 siguen pendientes; se mantienen las siete obligaciones.
Las pruebas son oráculos **sintéticos y documentales**, no aceptación funcional ni
validación experimental. El estado de trazabilidad registra las pretensiones
existentes al momento de construir este incremento, no los resultados futuros de CI.

Comprobar: `python3 lab/verify_operational_catalog.py`.
Pruebas: `python3 -m unittest discover -s lab/tests -p test_operational_catalog.py -v`.

## English — explicit limitations

Exactly 25 thesis-grounded, non-executable family specifications for SSH, FTP and
SMB/Samba, with provenance, preconditions, symbolic material-parameter references,
required supports, acceptance boundaries, precedence and cleanup. Zero real derived
cases because the existing P6 stage manifests still contain zero service–scenarios.
No executable/argument profiles (step 8), live execution, calibrated budgets, pilot,
experimental freeze, risk conclusions, functional acceptance or hypothesis validation
is claimed. All historical safety gates and residual obligations remain open.
