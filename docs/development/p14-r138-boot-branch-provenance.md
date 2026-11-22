# R138 — Continuidad firmada de arranque F7/F8 bajo rama ARDREC

## Alcance

La fuente R115-F7 conservará su rama y commit base históricos:

- `feat/p14-r115-a3-p7-a6-real` / `6ce42a1143d50f7adf69ea3159b56c0e993c45cb`.

Para la continuidad unificada A–D, su función `git_guard` admite adicionalmente:

- `feat/ardrec-cierre-operacional-experimental`.
- Ancestro adicional obligatorio y fijado: `b43b9488ad7f89d728ea24430b789342f758c4a0`, cierre firmado R136.
- Se comprueba **también** la ascendencia histórica R115.
- Se conserva la firma Git válida `G`, el árbol limpio, el directorio del repositorio y los dos archivos F7 rastreados e inalterados.
- El código R115-F8 reutiliza `f7.git_guard(for_boot=True)` y comprueba además sus propias fuentes.

## Restricciones sin cambios

`--inspect` no inicia máquinas ni modifica políticas. `--plan` exige alcance FTP-T01 vigente y firmado. `--boot` exige permiso independiente para el rol, revocación fresca, evidencia física previa, marcadores irrevocables de intento único y confirmación explícita del operador. SMB no dispone de ruta de arranque.

**Compatibilidad de rama no significa autorización física**. Nunca se emiten permisos, claves ni revocaciones desde R138. No se habilita P8, no se modifica nftables ni se instala root.

## Evidencia y pruebas

- 19 pruebas nuevas de rama: procedencia, firmas, árbol limpio, fuentes F7/F8, exclusiones, ancestros y no ampliación de roles.
- 60 pruebas históricas F7/F8 conservadas.
- La regresión R130–R136 (221) se ejecuta adicionalmente en Prometheus. Criterio de aceptación combinado: 300 pruebas.
- Todo commit se firma y se verifica localmente; no se hace `push`, PR ni merge.

## Situación física verificada en R137

- F5: `OFFLINE_DENY_BASELINE_MATCH`, R34 y F11 `MATCH`.
- Root R116-F1/F3: SHA-256 acreditados.
- F7 SSH: `DENY_STAGE_READY_NO_BOOT_AUTHORITY`.
- Materiales root de alcance y piloto F3 ausentes: 8 según inspección de metadatos.
- A6=`ND`, P8=`NO-GO`; topología activa 5/1 y recuperación autónoma real continúan sin acreditar.

## Siguiente dependencia

Las autoridades externas deben entregar certificados/archivos de confianza instalados independientemente y permisos/revocaciones vigentes. El agente autónomo de instalación A aún necesita integrar R134–R136 con seguridad root real y un mecanismo de publicación con journal/readback. R138 no sustituye ese trabajo.
