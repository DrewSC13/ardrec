# R117-F3 — Puerta Git de arranque actual y raíz histórica autenticada

## Motivación y límite formal
R116-F13 controla por SHA-256 el motor R116-F12 y las 33 fuentes F3. No se deben modificar después del merge. Se conserva **íntegro** el histórico R116 y su instalación raíz, incluidas las evidencias R114/F11/F2. La rama R117 necesita una puerta Git nueva, no una sustitución in-place ni monkeypatch de `r116_f12_controlled_boot.git_guard`.

## Implementación
Se añade `r117_f3_current_git_admission.py`: rama exacta R117, merge base verificado de R116, commit `G`, árbol limpio y tres fuentes ejecutivas registradas; vuelve a utilizar las guardas puras R116 F5 y el validador Ed25519 `r116_f2_current_pilot_gate`, siempre con `contract.source_commit == HEAD`. Ninguno de estos contratos confiere permiso operativo. La ejecución de VM desde el motor histórico R116 sigue **NO-GO** para R117 hasta disponer de un despachador R117 versionado, root staging autenticado y autorizaciones independientes.

`scripts/ardrec_p14_r117_f3_boot_chain_gate.py --source` comprueba la puerta Git y los 33 hashes F12; `--root` verifica el bundle raíz **histórico** de 33 archivos sin reemplazarlo. El estado esperado es `F12_SIGNED_UNCHANGED_R117_DISPATCH_NOT_RELEASED`. Es una auditoría y no un plan de arranque.

## Próximo incremento (sin preparativos artificiales)
R117-F4 debe aportar un despachador operacional versionado para SSH→runner→FTP **sin modificar los módulos R116**, con firma externa independiente por rol, revocaciones, expiración, controles 0/6→1/5→4/2→5/1, primer intento irreversible, recibos de R112 recomputados y plan de rollback sin ocultación de errores. Solo después actualizar root y autorizar la ventana FTP-T01. El control de tráfico y la clasificación A6 permanecerán NO-GO/ND mientras falte evidencia admisible.

## Prohibiciones
Sin `sudo` durante instalación; sin inicio de VM, red, nft, temporizador, `--arm-deny`, `--execute-pilot` o permisos ficticios. P7=DRAFT; A6=ND; P8=NO-GO.
