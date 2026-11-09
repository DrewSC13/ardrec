# ARDREC — P8-R16: semántica parcial SSH y modelo sintético versionado

**Base R15:** `4453c98720ba9ee86bcdf9909b71829f15b05dfa` (PR #48 integrado).

## Evidencias privadas locales previas, no incorporadas a Git

- R1: 24 cláusulas candidatas de 4 manuales SSH, 8 perfiles y 9 riesgos. SHA del informe `15ca2e03d37d1b10c6f8e9da238a6ef1690684f9b5c3a7d5cd272f6ed591059c`.
- R2: 24 anotaciones parciales y 10 interacciones documentales. SHA `d52e903fa3ede2a0c45f824086cac6bfef0a6811c388c28881204083fa40db81`.
- R3-R3: 25/25 referencias, corrección de etiqueta documental `HostName` a `Hostname` sin alterar la evidencia histórica. SHA `62166ea1ecc75d5460e1b436486181fc53cf48ec535b4f54b71def66a31e1f3c`.
- R4: 25 interpretaciones parciales y 17 dependencias; SHA `c2dbfcb7ab667008cb35c7432be883e3cb68b123fb5b1329216a7d012b2697ee`.
- R5: 10 casos sintéticos de precedencia; 55 pruebas aprobadas en Prometheus; SHA del informe `54e73fb46fd834d947de5deb8663910f049d0140251c10d70c633061e4741844`.

## Alcance R6, propuesta para integración

R6 instala el modelo puro derivado de R5 como código y pruebas en la CI; el archivo
original privado y los textos completos de manuales siguen fuera del repositorio.
El componente verifica reglas `CLI > USER > SYSTEM`, primera coincidencia salvo entradas
acumulativas `IdentityFile`/`CertificateFile`, coincidencia `Host` limitada y resultados
bloqueados. Los diez vectores públicos son sintéticos y están congelados.

**Distinción de certeza:** R1–R4 constituyen evidencia documental, R5–R6 prueban solamente
un modelo acotado. No hay equivalencia formal con OpenSSH, parser real de configuración,
prueba de configuración efectiva, identidad operacional de binario/objetivo/credencial,
ni presupuestos reales. Ninguna opción, gramática CLI, renderizador, perfil, caso o
operación recibe autorización. La integración en rama/PR es independiente de su aprobación.

**Próxima obligación P8:** prueba independiente y segura de la configuración efectiva
que integre precedencia, `Include`/`Match`, expansión, entorno, autoridad, materiales,
plazos y recertificación por cambio. Su adquisición requiere diseño de aislamiento y
permiso independiente; no ejecutar un cliente invitado ni introducir P9 sin ello.

P8, AL-06/AL-07 y siete obligaciones del plan continúan abiertos. P9–P13 y A1–A10
permanecen no iniciados.

**EN:** Proposed CI integration of a deny-only synthetic SSH configuration model;
prior private evidence remains private and is not reattested in CI. P8 remains open.
