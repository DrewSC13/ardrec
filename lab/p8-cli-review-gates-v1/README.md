# ARDREC P8-R15 — Matriz de obligaciones previas a la liberación CLI

**Ámbito:** P8, estático, `deny-only`. El verificador cruza los **25 riesgos** documentados con **29 perfiles simbólicos** (238 enlaces conservadores) y devuelve, para cualquier intención sintética válida, `BLOCKED_REVIEW_GATES_NOT_CLEARED`. No crea comandos, `argv`, rutas ni tickets de autorización. El resultado se obtiene exclusivamente de los contratos versionados R13 y R14.

## Diseño

- Los riesgos proceden de `lab/p8-cli-full-source-v1/anchors.json` (R14), que referencia siete fuentes íntegras privadas por hash y 91 anclas. Los riesgos son **límites documentales**, no hechos de ejecución ni comportamiento comprobado.
- La proyección de riesgos es **conservadora por familia**, no una atribución operacional de causa ni una evaluación exhaustiva de opciones individuales: SSH incluye riesgos `SSH_` y `SFTP_`, FTP/FTPS incluye riesgos `CURL_`, SMB incluye `SMB_` y `RPC_`.
- Todos los perfiles conservan nueve obligaciones de evidencia pendientes: identidad binaria, dependencias en ejecución, configuración efectiva, aislamiento/destino, autorización de caso, procedencia de recursos/credenciales, presupuesto de operación, revisión semántica de opciones y protocolo de evidencias.
- Las cinco variantes que contemplan escrituras suman dos obligaciones independientes: recibo de limpieza y prueba de restauración. **Un documento de limpieza no equivale a una limpieza efectuada.**
- La matriz y el validador rechazan cualquier modificación de perfiles, efectos, riesgos, controles, fuentes, SHA, estado de aprobación, rutas de ejecución o campos inesperados. El verificador no admite excepciones ni elevaciones.

## Verificación sin ejecución

```sh
python3 lab/verify_p8_cli_review_gates.py
python3 -m unittest discover -s lab/tests -p test_p8_cli_review_gates.py -v
```

La función `assess_request` solo acepta los seis campos sintéticos estrictos establecidos por R13; incluso con un perfil exacto, únicamente genera una explicación de bloqueo. Nunca incorpora materiales de laboratorio, destinos, secretos o comandos libres. El informe privado `ARDREC_P8_R14_FULL_MANPAGES_20261109.json` se conserva **fuera de Git**, y su comprobación frente a R14 se ejecuta localmente al instalar el parche.

**Estado:** 0 revisiones semánticas completas, 0 opciones aprobadas, 0 gramáticas CLI ejecutables, 0 renderizadores `argv`, 0 perfiles/casos autorizados, 0 despachos. AL-06/AL-07 y siete obligaciones de desarrollo abiertas; P9/A1–A10 no iniciados.

**EN:** A conservative per-protocol risk-to-profile review matrix, not a runtime CLI policy or an authorization. Exact source hashes, closed enum fields, 29 blocked symbolic profiles, 25 source-only risks, 238 conservative links, 5 separately cleanup-gated writers. No execution, private materials, or claims of operational attestation.
