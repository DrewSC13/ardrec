# P8-R6 — Ciclo de validez, invalidación y denegación por defecto

**Naturaleza:** propuesta fuente con un oráculo puramente sintético, sin conexión a fuentes de autoridad o materiales reales. Base `61f978a8cda7315dd09f66f4e3d63d99a6d7ee4c`. P8 permanece abierto.

## Flujo conceptual

1. Recibir una **afirmación sintética de contexto** de etapa, servicio, escenario, caso, perfil, referencia de destino, presupuesto, plan de limpieza, época material y revisión de autorización. La observación de materiales tiene la gramática denegada de P8-R5; **no se comprueba su origen en esta función**.
2. Calcular una huella SHA-256 canónica, separada por dominio, que liga todos esos campos. Una sustitución de bytes declarados, material, escenario, presupuesto, objetivo o época cambia la huella y hace incompatible cualquier solicitud anterior.
3. Evaluar una **ventana UTC declarada** con límite sintético de 24 h. Se distingue fuera-de-vigencia, caducado, calendario inválido, orden temporal incorrecto y límite excesivo. El reloj **no está autenticado** y jamás sirve para aprobar operaciones.
4. Aplicar un **diario sintético ordenado** de hasta 64 eventos. Las entradas solo representan invalidaciones; carecen de firmas. Las transiciones no revierten una invalidación. Ausencia de eventos **no prueba** ausencia de revocación en una autoridad real.
5. Devolver un diagnóstico reproducible, las razones de denegación y una huella del diagnóstico. Aun cuando la consistencia sintética sea positiva, `operational_authorization=false`, `dispatch_allowed=false` y `real_cases_authorized=0`.

## Frontera técnica

La huella de contexto no es una firma, token de despacho ni prueba de origen. Las fechas provienen del llamador y no de un reloj confiable. Los estados del diario son *reclamaciones públicas*; el registro confiable de emisores, revocación real, control monotónico, autorización por caso, custodia de materiales, entrega segura de FD a Rust, límites de piloto, aislamiento y AL-07 siguen **pendientes**. AL-06 y siete obligaciones siguen abiertas. Ninguna parte implementa la máquina global de estados de observación de ARDREC ni valida el experimento de 54 unidades.

## Evidencia

`lab/verify_p8_lifecycle.py`: validador sin efectos; revisa la línea de base denegada P8-R5 y el contrato documental R6.

`lab/tests/test_p8_lifecycle.py`: adversarios de contexto/época, revocación, caducidad, duplicación, reloj no confiable y modificaciones de identidad. No hay subprocess, red, VM ni binarios del host bajo observación.

**EN:** Deny-only synthetic temporal and revocation lifecycle oracle. Claimed timing, events and materials are untrusted; even a coherent synthetic result never grants executable authority.
