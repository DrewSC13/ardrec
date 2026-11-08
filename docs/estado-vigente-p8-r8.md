# ARDREC — Estado consolidado P8 y propuesta P8-R8, 8 de noviembre de 2026

## Integraciones previas verificadas / Verified earlier integrations

| Incremento | PR | SHA de merge en `main` | Alcance y límites |
| --- | --- | --- | --- |
| P8-R4 | #36 | `2030ef4fe24e3595cfb365853912548ff3294056` | Contrato de vínculo por caso, sin ejecución |
| P8-R5 | #37 | `61f978a8cda7315dd09f66f4e3d63d99a6d7ee4c` | Materiales de prueba temporales, no binarios reales |
| P8-R6 | #38 | `bd3500bfc7310abdbaf9bb1e57042e1c526f25d7` | Ciclo sintético de caducidad e invalidación, reloj no confiable |
| P8-R7 | #39 | `517aa57183ca6a406c890fc92ccd00211eb79c3c` | Diagnósticos estrictos Python–Rust, 106 vectores, siempre DENY_ALL |

Esta tabla informa del **estado histórico integrado ya contrastado**. No reescribe
ni convierte retroactivamente los documentos R4–R7, que describen su estado al
momento de elaborarse. Sus rótulos históricos «propuesta» o «sin integrar» no
indican el estado actual de `main`.

## Propuesta P8-R8 (source-only; pendiente de pruebas e integración)

Se propone una frontera **de revisión estructural sintética**, independiente
de permisos reales, que lee `GlobalState` y el diagnóstico no confiable R7 y
produce un resultado inmutable de denegación. La tabla T1–T10 se coteja con
las ocho fases y las guardas trivalentes, sin llamar a funciones de transición,
reservas, diario o almacenamiento.

- **Referencia de diseño:** tesis 3.5.2–3.5.4; relaciones de estado y guardas.
- **Referencias P8:** tesis 3.7.5 y 3.9.2; contratos R5–R7 existentes.
- **Sin promoción:** ninguna ruta se habilita a partir de un diagnóstico, un
  destino hipotético o un valor VERDADERO declarado artificialmente.
- **Sin atribución indebida:** no se ejecutaron A1–A10, no existe validación
  experimental ni aceptación funcional del sistema integral.
- **Abierto:** P8 global, AL-06, AL-07, siete obligaciones; 29 perfiles sin
  vinculación, cero casos reales y cero despachos.

**EN:** R4–R7 are integrated on the verified historical main commits; their
point-in-time proposals remain unedited. R8 adds a source-only immutable
structural state/diagnostic boundary. Every possible output denies authority,
execution, state change and generation publication. Its own CI, PR and merge
remain pending until independently checked.
