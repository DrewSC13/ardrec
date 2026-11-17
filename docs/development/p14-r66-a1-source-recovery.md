# P14-R66 — A1: recuperar estado serializado y evaluar sin atribuir autoridad

**Base de rama:** `feat/p14-r65-a1-confirmed-model-binding`, commit GPG `1714e96edb2d63216c004fdbb34361f7d7907c2e`.
**Main protegido:** `c07c355f3282e10f10043dc3d11479b38329d21f`.
**Tesis:** 17/11/2026, §3.6.1, figura 3.4, página impresa 105, PDF 120; SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`.

## Objetivo

R65 utilizaba un objeto `ConfirmedState` proporcionado por el invocador. R66 agrega una frontera verificable entre un **modelo serializado** y la decisión A1:

1. Se recibe una secuencia de bytes canónica y un pin SHA-256 de origen externo.
2. Se exige que el pin corresponda exactamente a los bytes suministrados.
3. Se decodifica con el códec nativo `ardrec.persistence.codec` (`parse`, `unpack`, `pack`, `canonical`), rechazando JSON no canónico, duplicados, tipos incorrectos e identidades inválidas.
4. Se recupera una instancia real de `ConfirmedState` y se reevalúa A1 usando R65, R64 y el núcleo R16/R61–R63.
5. Se emite un recibo inmutable, canónico y reproducible con las huellas independientes del modelo, la fuente serializada y la configuración R17.

La variante `evaluate_recovered_a1_file` lee una ruta absoluta en **solo lectura** mediante `os.open` y `O_NOFOLLOW` donde esté disponible; exige archivo regular de propiedad del usuario, un único enlace físico, permisos privados y bytes inmutables durante la lectura. No escribe ni modifica el archivo fuente. Los límites son de 1 MiB por estado y 128 KiB por recibo.

## Límites importantes

- El pin SHA-256 **no está acreditado por el propio archivo**. Debe provenir de una fuente confiable independiente.
- Una instancia reconstruida de `ConfirmedState` **no equivale automáticamente a una generación A9 duraderamente publicada**.
- La huella `ConfirmedState.configuration_sha256` **no acredita por sí misma** que el snapshot de reglas R17 sea una proyección de la misma configuración global.
- La verificación de recibos exige `verify()` para bytes y `verify_file()` para ficheros: un consumidor de bytes no puede reclamar el modo de origen `READONLY_FILE` sin efectuar la lectura.
- No se infiere procedencia física del sistema SSH/FTP/SMB ni se concede autoridad operacional. Todos los recibos mantienen `p8_operational: NO-GO`, `operational_dispatch: false`, `published_generation: null`.
- Las rutas normales del coordinador y sus fuentes de confianza siguen pendientes de integración; no se declara A1 al 100%.

## Evidencia

Oráculo: `lab/tests/test_p14_r66_a1_persisted_context.py` — 30 pruebas sobre recuperación, diferencias de estado, contexto, `ND`, manipulación, límites, enlaces, permisos y autorización. Se suman regresiones R16–R65 en la rama de trabajo.

## Regla nueva de trabajo

El desarrollo permanece **LOCAL** en `ardrec` y con recibos solo en `ardrec-patches`: no se realiza `git push`, `gh pr create` ni merge hasta que A1 alcance los criterios de aceptación final. Los commits locales deben tener firma GPG verificada. R60-E5 continúa en rama WIP independiente.

**EN.** A1 recovered-state source validation through the existing canonical persistence codec and an independently pinned SHA-256, with optional read-only private-file input. This tests integrity, **not external publication authority**. No operational dispatch; P8 NO-GO. No remote publication until A1 final acceptance.
