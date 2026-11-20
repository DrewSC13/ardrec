# R113-F6 — Guardián de restauración DENY para las seis interfaces

**Ámbito:** exclusivamente `/var/lib/ardrec/r113-six-deny-guard-v1`, tabla `bridge ardrec_r34_guard`, y seis `nwfilter-binding` de las redes SSH, FTP y SMB.

**Evidencia primaria:** `r113-f5-host-AI6gBysL/manifest.json` (SHA-256 `a29b0c0e91ca139f1e2969d81dec10677c64460f6c6aead397cc1a68d8bc43ba`), cuatro VM físicas acreditadas, seis MAC/TAP y F11 anclado. **Padre Git:** `daf7e37a1e5b7f1eece13fe2d899a14b0ede10ab`.

La recuperación histórica R55.8 se limita a runner-SSH y SSH. **F6 no la altera**. Genera una segunda caja independiente, autenticada mediante el manifiesto F5, con los seis `filterbinding` originales y seis candidatos futuros de nombre fijo, y el mismo `r34-deny-restore.nft` que usa el contrato R55.3. Ningún candidato es instalado ni habilitado por F6.

El motor root rechaza valores inesperados de UID, permisos, archivos extra, XML, MAC, propietario, UUID, red, TAP, `nwfilter` o reglas. El procedimiento `--restore-deny` restaura la tabla R34 primero, verifica sus cuatro reglas DROP y luego reconcilia las seis vinculaciones. Si una vinculación es original, no la modifica; si es candidata autenticada, la reemplaza con su original; si falta, la crea tras verificar la identidad del dominio activo; si es desconocida, se detiene con R34 en DENY.

La instalación root se autoriza explícitamente, permanece dentro de una carpeta exclusiva root:root modo 0700 con 16 archivos modo 0600 y permite `--check-root-bundle` sin operaciones de host. Una segunda autorización, independiente, permite `--restore-deny` (reaplicación física de reglas DENY, sin permisos ALLOW). El recibo del operador conserva logs privados SHA-256; el comando no realiza reintentos ni borrados automáticos.

**Limitaciones:** esta fase verifica restauración manual de seis vinculaciones pero no instala un watchdog autónomo, no crea reglas TCP permisivas, no autoriza conexiones ni acredita protocolos. La futura admisión R113-F7 exige primero un disparador autónomo de expiración/revocación, pruebas reales de fallo controlado y una ventana acotada, sin permitir la ausencia de una protección independiente.

**Prohibido:** `flush ruleset`, mutaciones fuera de la tabla R34, otros guests, habilitar IP forwarding, cambios permanentes de DHCP, arranque/reinicio/parada de VM, escaneos no acotados, push, merge o declarar P8 aprobado.
