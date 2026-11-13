# ARDREC — P14-R17: prevalidación A1 y frontera preparatoria de A2

**Base requerida:** merge PR #82 `9295db4bf83a54a3da7b7b5b478982135ac8d36c`.

**Ámbito:** únicamente un preflight estructural y una instantánea pura de tablas de decisión. No constituye A1 ni A2 completos, no publica generaciones, no configura el ejecutor y no otorga autorización operacional P8.

## Relación con la especificación

La sección 3.3.2 de la tesis (noviembre de 2026) distingue `VERDADERO`, `FALSO`, `ND` en expresiones tipadas; las figuras 3.4 y 3.5 separan `DECIDIR` y `EVALUAR`. En el repositorio, R16 implementa su núcleo tipado inicial. R17 **reutiliza R16** para validar todas las condiciones de una configuración de ensayo antes de consultarla y conserva una copia inmutable de los datos de origen.

La exigencia estructural de `initial_state=PREPARADO` es una precondición declarativa del fixture, **no una ejecución del algoritmo A2**. No valida la configuración integral, las caracterizaciones R0, los 54 servicios del protocolo, pesos/dependencias completos, el catálogo de casos o los estados publicados. El límite de 32 servicios es intencional para este preflight de ensayo; no representa un límite del sistema ARDREC o de la tesis.

## Contrato verificable R17

1. Entrada exacta: `format`, `fields`, `services`. Cada servicio declara `id`, `initial_state=PREPARADO` y `rules` (filas `id`, `condicion`). Campos autorizados, tipos y condiciones se verifican **antes** de congelar.
2. Se rechazan identidades y reglas duplicadas, campos inexistentes, condiciones no lógicas, expresiones inválidas, órdenes mal formados, estructuras extrañas y entradas no acotadas. El resultado se ordena canónicamente por identificador de servicio y fila y se conserva por bytes con SHA-256.
3. La mutación posterior de una configuración de entrada no modifica la instantánea. Las decisiones puras repiten `decide` de R16 sobre la instantánea, distinguen `ND` de `FALSO` y no utilizan aritmética de coma flotante.
4. Una `logical_guard_satisfied=true` significa únicamente la evaluación lógica `VERDADERO`. `operationally_authorized` es siempre `false` y `operational_dispatch=false`. Las incertidumbres y ambigüedades conservan la denegación conservadora de R16.
5. El digest SHA-256 detecta alteración accidental del contenido congelado; sin raíz externa de confianza **no autentica procedencia, autoridad ni frescura**. No sustituye a la persistencia A9.

## Evidencia y límites

Regresiones R17: `lab/tests/test_p14_r17_a1_a2_preflight.py`. Demo R17: `scripts/demo_p14_r17_a1_a2_preflight.py`. La CI solo ejecuta pruebas sintéticas en Python, además de los controles existentes Python/Rust. No lanza systemd, SSH, FTP o SMB.

**Estados exigidos:** `R17_COMPONENT=PREVIEW_TESTED` solo cuando Prometheus confirme su suite y las regresiones; `A1_FULL=NOT_CLOSED`; `A2_FULL=NOT_CLOSED`; `AC-06/AC-07=PENDING`; `P8_OPERATIONAL=NO-GO`; `SYSTEM_ACCEPTANCE=PENDING`; `EXPERIMENTAL_VALIDATION=NOT_RUN`.

**Pendiente para R18 y posteriores:** reconciliar `DECIDIR` contra todas las ramas del pseudocódigo final, completar A1; implementar A2 con configuración y caracterización completa, fijación de R0, inicialización de E0/Rf y estados y referencias durables. Nada de lo anterior se declara logrado por el preflight R17.

## English summary

R17 builds a strict, canonical, digest-checked, read-only preflight for R16's three-valued rule tables. It is a synthetic integration boundary toward A2, not A2 initialization, operational authorization, evidence admission, state publication or P8 dispatch.
