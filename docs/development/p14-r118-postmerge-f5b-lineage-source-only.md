# ARDREC P14-R118: continuidad de fuente posterior al PR #201

**Estado:** incremento implementado con pruebas automáticas; **SOURCE_ONLY**. Esta revisión del código no acredita inspección física nueva, permisos de arranque, tráfico, A6 admitida ni generación A9 real. No modifica el candidato instalado ni las autoridades históricas de F5B.

## Base de procedencia y contradicción resuelta conceptualmente

- Base exacta: `cdeb6ab831c473349f03a1d75a56c034bb951e5b` en `main`, PR #201 integrado.
- Cierre F5B V3 versionado: `lab/operational-controller/r117-f5b-physical-closure-v3.json`, SHA-256 `63629945aa1164973b0687318997be464c1c35be0f39c903a7dcf4a7c6381b74`.
- Candidato histórico, inmutable: HEAD `197785a38bf166ec0b4c8d3ae17346d1fa217265`, SHA-256 `5ef729690589497c787f34e99dba8fefea798459fc6c10a2d144a64a71cb2bf7`.
- `r117_f4_controlled_boot.git_guard` exige la antigua rama R117; `r117_f4_root_release.require_attested_release` exige el HEAD instalado. NO se cambia arbitrariamente esa guarda ni se ejecuta `checkout` para hacer coincidir identidades.
- La continuidad que admite R118 establece una **relación criptográficamente atestada** entre candidato histórico y código integrado, pero *no autoriza ejecutar el runtime*. Reemplazar el controlador histórico requiere una nueva release explícita con contratos y pruebas propios.

## Cambios nuevos

1. `src/ardrec/coordination/r118_postmerge_gate.py`: contrato puro y fail-closed de linaje, sin IO de host. Verifica cierre original íntegro, commit de integración, hashes exactos de cinco fuentes, declaración fresca Ed25519 de continuidad y declaración de revocación fresca de identidad independiente. Diferencia autenticación de firma de procedencia física; no eleva P8.
2. `scripts/ardrec_p14_r118_postmerge_readiness.py`: inspección de solo lectura del checkout actual y opción `--verify-root-lineage` cuando existan **nuevas** declaraciones firmadas en custodia root. En ambos casos `boot_authorized=false`, `network_authorized=false` y `p8=NO-GO`.
3. `lab/tests/test_p14_r118_postmerge_gate.py`: positivos/negativos, frescura, integridad, duplicados, formatos, cambios de fuente, no revocación, identidades distintas y Ed25519 real con claves temporales en prueba.
4. `.github/workflows/ci.yml`: incluye la nueva suite en el job Python; no interrumpe los gates históricos.

## Contrato futuro para emitir una atestación real (no emitida aquí)

Los documentos `lineage.json` y `revocation.json` deben ser emitidos por sus custodios bajo alcance **SOURCE_CONTINUITY_ONLY**, con campos y codificación exactos definidos por `r118_postmerge_gate.py`. Se depositarán **por proceso autorizado** bajo `/var/lib/ardrec/r118-postmerge-source-only/`; R118 **nunca los crea**. Ambos son JSON canónico con `statement` y `signature_b64`. El mensaje firmado es `PREFIX + canonical(statement)`; las claves públicas existentes deben tener las huellas PIN de V3 y lectura protegida en `/etc/ardrec/r117-authorities-v3/`. La aprobación de fuente dura como máximo 600 s y su no revocación, 90 s; solo se verifican cuando se dispone de documentos frescos. Las claves privadas no deben copiarse ni registrarse.

El comando `PYTHONPATH=src python3 -B scripts/ardrec_p14_r118_postmerge_readiness.py --json` únicamente examina el código fuente e informa bloqueos. `--verify-root-lineage` requiere autoridad root de lectura de las rutas root 0600; no debe elevarse ni invocarse por defecto para una demostración. Éxito criptográfico solo permite afirmar **continuidad de fuente**; NO permite cambiar `P7`, `A6=ND`, `P8=NO-GO`, ejecutar, abrir red ni modificar un estado confirmado.

## Brechas abiertas para la primera operación funcional real (sin porcentajes ficticios)

| Bloqueo | Artefacto responsable | Cierre exigible |
|---|---|---|
| Identidad candidata–main | R118 y nuevo controlador operacional versionado | Firma nueva, bytes exactos, release aprobada, integración explícita; jamás bypass de R117 |
| Autoridad y revocación actuales | A3/F11/R34 y nueva ventana autorizada | Alcance rol/flujo y revocación actuales, sin reutilizar firmas F5B |
| Estados reales, F11/R34 y recuperador | Host Prometheus, VM y filtros | Captura actual independiente y efecto comprobado de DENY/restauración |
| Ejecución FTP-T01 | A4/A5 más ejecutor Rust, reserva y ledger | Un intento real permitido, con límites y prueba de no duplicación |
| Evidencia y persistencia | A6/A7/A8/A9/A10 | Soportes reales, admisión por condición, cálculo exacto, generación durable y replay sin reejecución |
| Cobertura completa | Catálogo 8/8/9 y TUI | Contratos reales SSH/FTP/SMB, aceptación por familia, TUI sobre estado confirmado |

## Reglas de conservación

No reinstalar F5B, no borrar recibos, no modificar branch/HEAD para engañar guardas, no arrancar VM ni abrir puertos desde este incremento. Los registros de PR y CI son históricos y no permisos actuales. Las 54 observaciones definitivas siguen posteriores a piloto y congelamiento. La revisión de pruebas unitarias no prueba el estado físico.

**Siguiente entrega:** controlador operacional sucesor con fuente admitida, autoridad vigente, configuración y bloqueo F11/R34, más una primera sesión real acotada FTP; después conectar A5→A10 al estado durable y extender SSH/SMB sin reiniciar las fases cerradas.
