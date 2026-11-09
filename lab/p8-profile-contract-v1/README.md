# P8-R10 — Contratos semánticos por variante / Per-variant semantic contracts

## Español

**Roadmap: punto 8 únicamente.** Este incremento define un contrato **declarativo, tipado y no renderizable** para cada uno de los 29 espacios P8. La base de partida es el merge firmado P8-R9 `4290e759842fa090a0fb13979501dd8a8cc7d760`, con los 15 SHA-256 observados en el runner, 29 candidatos por protocolo y cero autorizaciones.

`contracts.json` codifica una operación semántica exclusiva por variante, la ruta y hash **observados en la imagen base** del candidato, las referencias materiales requeridas por P8, controles declarativos de seguridad, la frontera de lenguaje de comandos (SSH, curl o smbclient) y la política de limpieza. El verificador enlaza **por orden e identidad** P8-R10 con P8 y P8-R9, vuelve a comprobar SHA-256 congelados y rechaza variaciones de control, alcance, variante, operación y promoción indebida de autorización.

**Diferenciaciones preservadas:** FTP-T02 CONTROL versus DATA; FTP-T08 READ versus WRITE; SMB-T03 SIGNING versus ENCRYPTION; SMB-T09 READ versus WRITE. SSH-T03 sigue sin mecanismo de contraseña aprobado (`sshpass` está ausente en el runner inspeccionado). Cinco variantes con escritura requieren limpieza independiente (SSH-T07, FTP-T07, FTP-T08-WRITE, SMB-T08, SMB-T09-WRITE).

**Advertencia fundamental:** los `required_control_atoms` son requisitos semánticos que todavía NO son opciones CLI comprobadas. `material_reference_names` son **nombres de campos del contrato**, nunca parámetros resueltos, credenciales ni bytes del argumento. `rendered_argv`, `remote_command_ast` y `smb_command_ast` permanecen `null`; ninguna cadena libre para shell remoto, `smbclient -c` o configuración `curl` está autorizada. No se debe utilizar este JSON como receta para ejecutar herramientas. La única API de demostración `assess_symbolic_intent` valida consistencia estructural y **siempre devuelve denegación**.

**Contratos pendientes:** selección y custodia del binario durante futura ejecución, cierre del riesgo TOCTOU, gramática concreta de flags por versión, serializadores controlados para operaciones SSH/SMB, ruta de credenciales privadas, selección física de caso y destino P6, carpeta de trabajo, entorno, auxiliares versionados, presupuesto finito calibrado en piloto, política de captura, limpieza comprobable, identidad/autoridad/revocación y aislamiento operativo. AL-06, AL-07 y siete obligaciones anteriores siguen abiertos. P8 general **no** está cerrado.

Verificación de solo lectura: `python3 lab/verify_p8_profile_contracts.py`; pruebas adversariales: `python3 -m unittest discover -s lab/tests -p test_p8_profile_contracts.py -v`. CI ejecuta ambos sin disponer de VM, red de laboratorio ni archivos privados.

## English

Strict 29-row per-family and per-variant **symbolic, typed, non-executable** operation contracts. The material hashes are historical offline image observations, not live executable pins. No actual argv, remote command string, smbclient command language, credentials, authorized case, real permissions, budget, cleanup receipts, algorithm implementation or process dispatch are established. Five write variants require separately evidenced cleanup. All outcomes deny authorization and execution.
