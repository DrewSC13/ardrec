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
