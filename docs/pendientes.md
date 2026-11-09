# Pendientes de la línea base

## Español

- Comprobar la firma local del primer commit.
- Elegir propietario y crear el repositorio remoto privado.
- Verificar la firma del commit en GitHub.
- Seleccionar y fijar una versión estable de Rust para ARDREC.
- Verificar compatibilidad de dependencias con la versión Python elegida.
- Configurar empaquetado, versiones y archivos de bloqueo.
- Implementar CI y comprobar las reglas del repositorio.
- Resolver el nombre canónico del mensaje de consulta de intento:
  attempt_status_response frente a attempt_status_result.
- Implementar y probar A1–A10.
- Preparar y verificar el laboratorio y el protocolo experimental.

## English

### Baseline pending tasks

- Verify the local signature of the initial commit.
- Select the owner and create the private remote repository.
- Verify the commit signature on GitHub.
- Select and pin a stable Rust version for ARDREC.
- Verify dependency compatibility with the selected Python version.
- Configure packaging, versions and lockfiles.
- Implement CI and verify repository rules.
- Resolve the canonical attempt-status response message name:
  attempt_status_response versus attempt_status_result.
- Implement and test A1–A10.
- Prepare and verify the laboratory and experimental protocol.

## Estado posterior comprobado / Later verified status

**ES:** La lista precedente registra pendientes de la línea base original, no el inventario actual. Consultar `docs/estado-vigente-p8-r3.md` y `lab/p8-readiness-v1/README.md`. P8 continúa bloqueado; AL-06, AL-07 y siete obligaciones de desarrollo siguen abiertos. El incremento R3 no acredita herramientas ni permisos.

**EN:** The preceding bootstrap list is historical. See the current-status and deny-only readiness documents. No operational authorization or dispatch is granted by P8 R3.

## Contrato adicional propuesto P8-R4 / Proposed additional P8-R4 contract

**ES:** `lab/p8-binding-contract-v1` verifica el contrato documentado para futuras propuestas por caso sin modificar registros P6/P7/P8. Ninguna propuesta real está aceptada y el alcance no acredita herramienta, presupuesto piloto ni autorización. P8, AL-06, AL-07 y siete obligaciones permanecen abiertos.

**EN:** Synthetic P8-R4 per-case semantic contract only; no approval, execution, private artifact verification or experiment.

## Propuesta adicional P8-R5 / Additional proposed P8-R5 source

**ES:** Oráculo de observación de archivos de prueba temporales: SHA-256 sobre bytes leídos por FD, propiedad, permisos y estabilidad limitada; no certifica origen confiable, versiones reales, autorización, integridad futura ni aislamiento. P8, AL-06, AL-07 y siete obligaciones abiertas.

**EN:** Synthetic test-owned FD byte observation only; no trusted real binary pins, no operational authority, no process dispatch and no experiment.

## Propuesta adicional P8-R6 / Additional proposed P8-R6 source

**ES:** Contrato puramente sintético de huella vinculada a caso y época, caducidad declarada, invalidación irreversible por eventos y rechazo de revocación no comprobada. Ninguna declaración pública prueba autoridad o reloj confiable. P8, AL-06, AL-07 y siete obligaciones de desarrollo siguen abiertos.

**EN:** Deny-only synthetic temporal/revocation oracle; no trusted clock, issuer, revocation register, executable dispatch, physical tests or experiment.

## Propuesta P8-R7 — diagnóstico interoperable denegado / Deny-only diagnostic interoperability

**ES:** Se compara un contrato sintético de diagnóstico con campos estrictos entre Python y Rust sobre los mismos vectores JSON. Sin vinculación real de emisores, registros privados, reloj o materiales; ningún resultado autoriza despacho. P8, AL-06, AL-07 y siete obligaciones permanecen abiertos.

**EN:** Cross-language diagnostic denial fixtures only. No trusted case authority, actual tool execution, laboratory result or permission is granted.

## Propuesta P8-R8 — frontera de estado sintética / Synthetic state boundary

**ES:** T1–T10 y guardas trivalentes se inspeccionan junto con el diagnóstico R7 sin producir transición, despacho o generación publicada. R4–R7 constan como integrados en el nuevo corte `docs/estado-vigente-p8-r8.md`; los cortes históricos no se alteran. P8, AL-06, AL-07 y siete obligaciones siguen abiertos.

**EN:** A pure source-only T1–T10/state diagnostic review, with no execution, publication, acceptance or laboratory testing.

## P8-R9 — materiales del runner / Runner material inventory

**ES:** Registro de 15 bytes-hash de ejecutables en imagen base QCOW2 comprobada por lectura y una herramienta ausente (`sshpass`); 29 correspondencias preliminares por protocolo. No acredita compatibilidad por familia, `argv`, presupuesto, autoridad, caso real, origen confiable ni operación futura. Ningún perfil habilitado; P8 y AL-06/AL-07 permanecen abiertos. A1-R9 PR #41 cerrado sin merge; A1–A10 se implementan desde punto 14.

**EN:** Observed 15 point-in-time guest-image binary hashes and 29 non-authorized protocol-level candidates; no runtime pins, dispatch authorization, experiment or algorithm advancement.

## P8-R10 — intenciones técnicas tipadas / Typed symbolic intents

**ES:** Se proponen 29 contratos semánticos por variante, unidos a P8 y P8-R9 con operaciones, campos materiales simbólicos, controles declarativos y cinco políticas de limpieza para escritura. No equivalen a opciones reales de CLI, comandos SSH/SMB, `argv`, contratos privados ni autorizaciones. P8 y AL-06/AL-07 y siete obligaciones siguen abiertos; P9 y A1–A10 no iniciados.

**EN:** 29 deny-only typed symbolic intents with separate SSH/FTP/SMB language boundaries and write cleanup gates, not runnable CLI recipes.

## P8-R11 — fuentes documentales del runner / CLI documentary evidence

**ES:** Registro reportado y verificable por lectura de 7 manuales de la QCOW2 y cuatro campos `Depends`, vinculados a 29 intenciones tipadas. No valida opciones CLI ni cierre de dependencias o autorización por caso. Cero argumentos materializados, casos reales o despachos; P8, AL-06/AL-07 y siete obligaciones continúan abiertos.

**EN:** Version-pinned documentary source observations only; no semantic CLI grammar, trusted execution, private authority or algorithm implementation.

## P8-R12 — fragmentos semánticos acotados / Bounded semantic excerpts

**ES:** Revisión de 91 fragmentos obtenidos en 7 manuales de la QCOW2: 74 definiciones de fragmento, 15 referencias insuficientes y 2 ambigüedades de opciones cortas. Conexión documentada con 29 perfiles sin aprobación de flags, `argv`, destino, credenciales, caso o despacho. AL-06/AL-07 y siete obligaciones continúan abiertos.

**EN:** Excerpt-level source analysis only, not full manpage semantics, runtime capability, trusted authorization, executable grammar or algorithm implementation.

## P8-R13 — gramática simbólica no ejecutable / Non-executable typed grammar

**ES:** Validador puro de seis campos tipados con correspondencia exacta a 29 perfiles SSH/FTP/SMB. Distingue cinco escrituras, TLS control/datos, firma/cifrado SMB y SMBv1 aislado; no acredita opciones reales, `argv`, credenciales, destinos, permisos ni despachos. AL-06/AL-07 y siete obligaciones siguen abiertos.

**EN:** Canonical synthetic intent tags, not runnable CLI grammar, binary attestation, runtime protection or authorized case execution.

## P8-R14 — fuentes completas y anclas / Full manual source anchors

**ES:** 7 manuales roff íntegros autenticados desde una QCOW2 de solo lectura; 91 entradas localizadas exactamente con hashes de línea y 25 límites de seguridad. El informe privado se verifica por SHA y sin publicar las fuentes. No se completa una revisión semántica operacional ni se aprueban opciones, `argv`, perfil, caso o despacho. AL-06/AL-07 y siete obligaciones siguen abiertos.

**EN:** Full pinned manuals, exact source headers and documented risk boundaries only. All 29 profiles deny-only; P9 and A1–A10 not started.
